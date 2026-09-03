import asyncio
import aiosqlite
import json
import logging

from datetime import datetime, timezone

from blucifer.bluetooth.classifier import classify_device
from blucifer.bluetooth.models import ScannedBluetoothDevice
from blucifer.config.config import DB_PATH
from blucifer.db.models import BluciferSettings, Device

# The schema for the Blucifer database
SCHEMA: str = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    mac             TEXT PRIMARY KEY,
    vendor          TEXT,
    friendly_name   TEXT,
    device_type     TEXT,
    ignored         INTEGER NOT NULL DEFAULT 0,
    watched         INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT,
    last_seen       TEXT,
    total_sightings INTEGER NOT NULL DEFAULT 0,
    service_uuids   TEXT NOT NULL DEFAULT '[]',
    bt_type         TEXT NOT NULL DEFAULT 'ble',
    device_class    INTEGER,
    rssi            INTEGER,
    group_name      TEXT,
    notes           TEXT
);
"""

# Indexes are created after column migrations so they can reference columns
# added to an older devices table.
_DEVICE_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_name)",
]

# Columns added to the devices table after its first release, applied on startup
# for databases created before they existed.
_DEVICE_ADD_COLUMNS: list[tuple[str, str]] = [
    ("vendor", "TEXT"),
    ("friendly_name", "TEXT"),
    ("device_type", "TEXT"),
    ("ignored", "INTEGER NOT NULL DEFAULT 0"),
    ("watched", "INTEGER NOT NULL DEFAULT 0"),
    ("first_seen", "TEXT"),
    ("last_seen", "TEXT"),
    ("total_sightings", "INTEGER NOT NULL DEFAULT 0"),
    ("service_uuids", "TEXT NOT NULL DEFAULT '[]'"),
    ("bt_type", "TEXT NOT NULL DEFAULT 'ble'"),
    ("device_class", "INTEGER"),
    ("rssi", "INTEGER"),
    ("group_name", "TEXT"),
    ("notes", "TEXT"),
]

# The timeout value to use for database operations
_DB_TIMEOUT_SECONDS: float = 30.0

# The logger instance
logger = logging.getLogger(__name__)

# In-memory cache of the application settings. Settings are read on nearly every
# request (auth middleware), so we cache them and invalidate on write rather than
# opening a fresh connection each time.
_settings_cache: BluciferSettings | None = None
_settings_lock: asyncio.Lock = asyncio.Lock()


def _invalidate_settings_cache() -> None:
    """Drops the cached settings so the next read reloads from the database."""
    global _settings_cache
    _settings_cache = None

def _connect() -> aiosqlite.Connection:
    """Opens a new database connection."""
    return aiosqlite.connect(DB_PATH, timeout=_DB_TIMEOUT_SECONDS)

async def _enable_wal(db: aiosqlite.Connection) -> None:
    """
    Enables WAL and warns if SQLite falls back.
    """
    async with db.execute("PRAGMA journal_mode=WAL") as cur:
        row = await cur.fetchone()

    mode = (row[0] if row else "") or ""
    if mode.lower() != 'wal':
        logger.warning(f"SQLite journal_mode is {mode}, not 'wal'. The database "
                       "is more vulnerable to corruption on unclean shutdowns; "
                       f"Check the filesystem backing {DB_PATH}!")

async def _ensure_device_columns(conn: aiosqlite.Connection) -> None:
    """Adds any devices-table columns missing from an older database."""
    async with conn.execute("PRAGMA table_info(devices)") as cur:
        existing = {row[1] for row in await cur.fetchall()}

    for name, ddl in _DEVICE_ADD_COLUMNS:
        if name not in existing:
            logger.info(f"Migrating devices table: adding column {name}")
            await conn.execute(f"ALTER TABLE devices ADD COLUMN {name} {ddl}")

    for stmt in _DEVICE_INDEXES:
        await conn.execute(stmt)

async def init_db() -> None:
    """Initializes the database schema."""
    async with _connect() as db:
        await _enable_wal(db)
        # TODO: Possibly add an integrity check
        await db.executescript(SCHEMA)
        await _ensure_device_columns(db)
        await db.commit()

    _invalidate_settings_cache()

########
# Application Settings
########

async def _load_settings() -> BluciferSettings:
    """Reads the application settings straight from the database."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute ("SELECT key, value FROM settings") as cur:
            rows = await cur.fetchall()
            settings = { row["key"]: row["value"] for row in rows }

    # Build the settings object
    return BluciferSettings(
        # Authentication
        auth_enabled=settings.get("auth_enabled", "0") == "1",
        auth_username=settings.get("auth_username"),
        auth_password_hash=settings.get("auth_password_hash"),
    )

async def get_settings() -> BluciferSettings:
    """
    Returns the application settings, using an in-memory cache.

    The cache is populated on first access and dropped whenever a setting is
    written, so callers always observe their own writes.
    """
    global _settings_cache

    if _settings_cache is not None:
        return _settings_cache

    async with _settings_lock:
        # Another coroutine may have populated the cache while we waited.
        if _settings_cache is None:
            _settings_cache = await _load_settings()
        return _settings_cache

async def set_setting(key: str, value: str) -> None:
    """Sets an individual setting in the db."""
    async with _connect() as db:
        await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                         (key, value))
        await db.commit()

    _invalidate_settings_cache()

async def update_settings(settings: BluciferSettings) -> None:
    """Updates all settings stored in the database."""
    async with _connect() as db:
        setting_pairs: list[tuple[str, str]] = [
            # Authentication
            ("auth_enabled", "1" if settings.auth_enabled else "0"),
            ("auth_username", "" if settings.auth_username is None else settings.auth_username),
            ("auth_password_hash", "" if settings.auth_password_hash is None else settings.auth_password_hash),
        ]

        for key, value in setting_pairs:
            await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                             (key, value))

        await db.commit()

    _invalidate_settings_cache()

########
# Devices
########

def _row_to_device(row: aiosqlite.Row) -> Device:
    """Builds a Device from a devices-table row."""
    return Device(
        mac=row["mac"],
        vendor=row["vendor"],
        friendly_name=row["friendly_name"],
        device_type=row["device_type"],
        ignored=bool(row["ignored"]),
        watched=bool(row["watched"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        total_sightings=row["total_sightings"],
        service_uuids=json.loads(row["service_uuids"] or "[]"),
        bt_type=row["bt_type"],
        device_class=row["device_class"],
        rssi=row["rssi"],
        group_name=row["group_name"],
        notes=row["notes"],
    )

async def record_devices(
    devices: list[ScannedBluetoothDevice],
) -> list[tuple[Device, bool]]:
    """
    Upserts a batch of freshly-scanned devices in a single transaction.

    Returns (device, is_new) for each input, in order, where is_new is True the
    first time a MAC has ever been seen. Existing rows keep their first_seen and
    bump total_sightings; volatile fields (rssi, name, vendor, ...) are refreshed.
    """
    if not devices:
        return []

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    results: list[tuple[Device, bool]] = []

    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row

        for scanned in devices:
            async with conn.execute(
                "SELECT * FROM devices WHERE mac = ?", (scanned.mac,)
            ) as cur:
                existing = await cur.fetchone()

            uuids = list(scanned.service_uuids or [])

            if existing is None:
                device_type = classify_device(
                    name=scanned.name,
                    vendor=scanned.vendor,
                    service_uuids=uuids,
                    device_class=scanned.device_class,
                    manufacturer_data=scanned.manufacturer_data,
                    service_data=scanned.service_data,
                )
                await conn.execute(
                    """
                    INSERT INTO devices
                        (mac, vendor, friendly_name, device_type, first_seen, last_seen,
                         total_sightings, service_uuids, bt_type, device_class, rssi)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """,
                    (scanned.mac, scanned.vendor, scanned.name, device_type, now, now,
                     json.dumps(uuids), scanned.bt_type, scanned.device_class,
                     scanned.rssi),
                )
                results.append((
                    Device(
                        mac=scanned.mac,
                        vendor=scanned.vendor,
                        friendly_name=scanned.name,
                        device_type=device_type,
                        first_seen=now,
                        last_seen=now,
                        total_sightings=1,
                        service_uuids=uuids,
                        bt_type=scanned.bt_type,
                        device_class=scanned.device_class,
                        rssi=scanned.rssi,
                    ),
                    True,
                ))
                continue

            # Merge onto the existing row.
            vendor = scanned.vendor or existing["vendor"]
            friendly_name = scanned.name or existing["friendly_name"]
            device_class = (
                scanned.device_class
                if scanned.device_class is not None
                else existing["device_class"]
            )
            merged_uuids = uuids or json.loads(existing["service_uuids"] or "[]")
            total = existing["total_sightings"] + 1

            # Re-classify each sighting - name / vendor / UUIDs may have improved.
            device_type = classify_device(
                name=friendly_name,
                vendor=vendor,
                service_uuids=merged_uuids,
                device_class=device_class,
                manufacturer_data=scanned.manufacturer_data,
                service_data=scanned.service_data,
            )
            if device_type == "unknown" and existing["device_type"]:
                device_type = existing["device_type"]

            await conn.execute(
                """
                UPDATE devices
                   SET vendor = ?, friendly_name = ?, device_type = ?, last_seen = ?,
                       total_sightings = ?, service_uuids = ?, bt_type = ?,
                       device_class = ?, rssi = ?
                 WHERE mac = ?
                """,
                (vendor, friendly_name, device_type, now, total, json.dumps(merged_uuids),
                 scanned.bt_type, device_class, scanned.rssi, scanned.mac),
            )

            merged = _row_to_device(existing)
            merged.vendor = vendor
            merged.friendly_name = friendly_name
            merged.device_type = device_type
            merged.last_seen = now
            merged.total_sightings = total
            merged.service_uuids = merged_uuids
            merged.bt_type = scanned.bt_type
            merged.device_class = device_class
            merged.rssi = scanned.rssi
            results.append((merged, False))

        await conn.commit()

    return results

async def list_devices(
    limit: int = 1000,
    include_ignored: bool = False,
    since: str | None = None,
    until: str | None = None,
) -> list[Device]:
    """
    Returns stored devices, most recently seen first.

    ``since`` / ``until`` are ISO-8601 UTC strings that bound ``last_seen``.
    """
    clauses: list[str] = []
    params: list = []
    if not include_ignored:
        clauses.append("ignored = 0")
    if since:
        clauses.append("last_seen >= ?")
        params.append(since)
    if until:
        clauses.append("last_seen <= ?")
        params.append(until)

    query = "SELECT * FROM devices"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY last_seen DESC LIMIT ?"
    params.append(limit)

    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(query, params) as cur:
            rows = await cur.fetchall()

    return [_row_to_device(row) for row in rows]

async def set_device_group(macs: list[str], group: str | None) -> int:
    """Assigns (or clears, when group is None/empty) a group for the given MACs."""
    macs = [m for m in macs if m]
    if not macs:
        return 0
    group = (group or "").strip() or None

    placeholders = ",".join("?" for _ in macs)
    async with _connect() as conn:
        cur = await conn.execute(
            f"UPDATE devices SET group_name = ? WHERE mac IN ({placeholders})",
            [group, *macs],
        )
        await conn.commit()
        return cur.rowcount

async def set_device_watched(macs: list[str], watched: bool) -> int:
    """Sets the watched flag for the given MACs."""
    macs = [m for m in macs if m]
    if not macs:
        return 0

    placeholders = ",".join("?" for _ in macs)
    async with _connect() as conn:
        cur = await conn.execute(
            f"UPDATE devices SET watched = ? WHERE mac IN ({placeholders})",
            [1 if watched else 0, *macs],
        )
        await conn.commit()
        return cur.rowcount
