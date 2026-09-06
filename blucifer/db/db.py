import asyncio
import aiosqlite
import json
import logging

from datetime import datetime, timezone

from blucifer.analytics.visits import segment_visits, visits_summary
from blucifer.bluetooth.classifier import classify_device
from blucifer.bluetooth.models import ScannedBluetoothDevice
from blucifer.config.config import DB_PATH, SIGHTINGS_RETENTION_DAYS, VISIT_GAP_SECONDS
from blucifer.db.models import BluciferSettings, Device

# Bounds for the user-configurable sighting-history retention.
RETENTION_MIN_DAYS = 1
RETENTION_MAX_DAYS = 3650

# Bounds for the user-configurable visit idle-gap (seconds): one minute to a day.
VISIT_GAP_MIN_SECONDS = 60
VISIT_GAP_MAX_SECONDS = 86400

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

-- One row per device per scan cycle: the raw timeline behind patterns of life.
CREATE TABLE IF NOT EXISTS sightings (
    id        INTEGER PRIMARY KEY,
    mac       TEXT NOT NULL,
    ts        TEXT NOT NULL,   -- ISO 8601 UTC
    rssi      INTEGER,
    sensor_id TEXT
);
"""

# Indexes are created after column migrations so they can reference columns
# added to an older devices table.
_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(group_name)",
    "CREATE INDEX IF NOT EXISTS idx_sightings_mac_ts ON sightings(mac, ts)",
    "CREATE INDEX IF NOT EXISTS idx_sightings_ts ON sightings(ts)",
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

async def init_db() -> None:
    """Initializes the database schema."""
    async with _connect() as db:
        await _enable_wal(db)
        # TODO: Possibly add an integrity check
        await db.executescript(SCHEMA)
        await _ensure_device_columns(db)
        for stmt in _INDEXES:
            await db.execute(stmt)
        await db.commit()

    _invalidate_settings_cache()

########
# Application Settings
########

def _clamp_retention(days: int) -> int:
    return max(RETENTION_MIN_DAYS, min(RETENTION_MAX_DAYS, days))

def _clamp_visit_gap(seconds: int) -> int:
    return max(VISIT_GAP_MIN_SECONDS, min(VISIT_GAP_MAX_SECONDS, seconds))

async def _load_settings() -> BluciferSettings:
    """Reads the application settings straight from the database."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute ("SELECT key, value FROM settings") as cur:
            rows = await cur.fetchall()
            settings = { row["key"]: row["value"] for row in rows }

    try:
        retention = _clamp_retention(int(settings["sightings_retention_days"]))
    except (KeyError, ValueError, TypeError):
        retention = SIGHTINGS_RETENTION_DAYS  # env default until set in the UI

    try:
        visit_gap = _clamp_visit_gap(int(settings["visit_gap_seconds"]))
    except (KeyError, ValueError, TypeError):
        visit_gap = VISIT_GAP_SECONDS  # env default until set in the UI

    # Build the settings object
    return BluciferSettings(
        # Authentication
        auth_enabled=settings.get("auth_enabled", "0") == "1",
        auth_username=settings.get("auth_username"),
        auth_password_hash=settings.get("auth_password_hash"),
        # Data retention
        sightings_retention_days=retention,
        # Presence / visits
        visit_gap_seconds=visit_gap,
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
            # Data retention
            ("sightings_retention_days", str(_clamp_retention(settings.sightings_retention_days))),
            # Presence / visits
            ("visit_gap_seconds", str(_clamp_visit_gap(settings.visit_gap_seconds))),
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

# Keep "WHERE mac IN (...)" comfortably under SQLITE_MAX_VARIABLE_NUMBER on any
# SQLite version.
_SELECT_CHUNK = 500

async def get_device(mac: str) -> Device | None:
    """Returns one stored device, or None."""
    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)) as cur:
            row = await cur.fetchone()
    return _row_to_device(row) if row else None

async def record_devices(
    devices: list[ScannedBluetoothDevice],
    sensor_id: str | None = None,
) -> list[tuple[Device, bool]]:
    """
    Upserts a batch of freshly-scanned devices and appends one sighting each.

    Reads all existing rows in one query, decides inserts vs. merges in Python,
    then applies them with a few ``executemany`` writes in a single transaction -
    so the write lock is held only for the flush, not per device.

    Returns (device, is_new) per distinct MAC (the last sighting of a MAC in the
    batch wins); is_new is True the first time a MAC has ever been seen. Existing
    rows keep their first_seen and bump total_sightings; volatile fields (rssi,
    name, vendor, ...) are refreshed. Every distinct MAC also gets a row in
    ``sightings`` stamped with ``now`` and ``sensor_id``.
    """
    if not devices:
        return []

    # Collapse duplicate MACs within the batch - last sighting wins.
    by_mac: dict[str, ScannedBluetoothDevice] = {d.mac: d for d in devices}
    macs = list(by_mac)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row

        # --- one bulk read of everything we might touch ---
        existing: dict[str, aiosqlite.Row] = {}
        for i in range(0, len(macs), _SELECT_CHUNK):
            chunk = macs[i:i + _SELECT_CHUNK]
            placeholders = ",".join("?" * len(chunk))
            async with conn.execute(
                f"SELECT * FROM devices WHERE mac IN ({placeholders})", chunk
            ) as cur:
                async for row in cur:
                    existing[row["mac"]] = row

        # --- decide everything in Python, no DB calls in this loop ---
        inserts: list[tuple] = []
        updates: list[tuple] = []
        results: list[tuple[Device, bool]] = []

        for mac, scanned in by_mac.items():
            uuids = list(scanned.service_uuids or [])
            row = existing.get(mac)

            if row is None:
                device_type = classify_device(
                    name=scanned.name,
                    vendor=scanned.vendor,
                    service_uuids=uuids,
                    device_class=scanned.device_class,
                    manufacturer_data=scanned.manufacturer_data,
                    service_data=scanned.service_data,
                )
                inserts.append((
                    mac, scanned.vendor, scanned.name, device_type, now, now,
                    json.dumps(uuids), scanned.bt_type, scanned.device_class,
                    scanned.rssi,
                ))
                results.append((
                    Device(
                        mac=mac,
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
            vendor = scanned.vendor or row["vendor"]
            friendly_name = scanned.name or row["friendly_name"]
            device_class = (
                scanned.device_class
                if scanned.device_class is not None
                else row["device_class"]
            )
            merged_uuids = uuids or json.loads(row["service_uuids"] or "[]")
            total = row["total_sightings"] + 1

            # Re-classify each sighting - name / vendor / UUIDs may have improved.
            device_type = classify_device(
                name=friendly_name,
                vendor=vendor,
                service_uuids=merged_uuids,
                device_class=device_class,
                manufacturer_data=scanned.manufacturer_data,
                service_data=scanned.service_data,
            )
            if device_type == "unknown" and row["device_type"]:
                device_type = row["device_type"]

            updates.append((
                vendor, friendly_name, device_type, now, total,
                json.dumps(merged_uuids), scanned.bt_type, device_class,
                scanned.rssi, mac,
            ))

            merged = _row_to_device(row)
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

        # --- two bulk writes, one commit ---
        if inserts:
            await conn.executemany(
                """
                INSERT INTO devices
                    (mac, vendor, friendly_name, device_type, first_seen, last_seen,
                     total_sightings, service_uuids, bt_type, device_class, rssi)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(mac) DO NOTHING
                """,
                inserts,
            )
        if updates:
            await conn.executemany(
                """
                UPDATE devices
                   SET vendor = ?, friendly_name = ?, device_type = ?, last_seen = ?,
                       total_sightings = ?, service_uuids = ?, bt_type = ?,
                       device_class = ?, rssi = ?
                 WHERE mac = ?
                """,
                updates,
            )
        await conn.executemany(
            "INSERT INTO sightings (mac, ts, rssi, sensor_id) VALUES (?, ?, ?, ?)",
            [(mac, now, d.rssi, sensor_id) for mac, d in by_mac.items()],
        )
        await conn.commit()

    return results

async def list_sightings(
    mac: str,
    since: str | None = None,
    until: str | None = None,
    limit: int = 5000,
) -> list[dict]:
    """Raw sighting timeline for one device, most recent first."""
    clauses = ["mac = ?"]
    params: list = [mac]
    if since:
        clauses.append("ts >= ?")
        params.append(since)
    if until:
        clauses.append("ts <= ?")
        params.append(until)
    params.append(limit)

    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            f"SELECT ts, rssi, sensor_id FROM sightings "
            f"WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?",
            params,
        ) as cur:
            rows = await cur.fetchall()

    return [{"ts": r["ts"], "rssi": r["rssi"], "sensor_id": r["sensor_id"]} for r in rows]

async def sighting_summary(mac: str, since: str | None = None) -> dict:
    """
    Aggregates a device's sightings for a patterns-of-life view.

    Returns totals plus counts bucketed by hour-of-day (24) and weekday
    (0=Monday..6=Sunday), computed in Python so it works on any SQLite version.
    """
    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT COUNT(*) n, MIN(ts) first, MAX(ts) last FROM sightings WHERE mac = ?",
            (mac,),
        ) as cur:
            agg = await cur.fetchone()

        q = "SELECT ts FROM sightings WHERE mac = ?"
        params: list = [mac]
        if since:
            q += " AND ts >= ?"
            params.append(since)
        async with conn.execute(q, params) as cur:
            timestamps = [r["ts"] for r in await cur.fetchall()]

    by_hour = [0] * 24
    by_dow = [0] * 7
    by_dow_hour = [[0] * 24 for _ in range(7)]  # [weekday][hour], 0=Monday
    by_day: dict[str, int] = {}
    for ts in timestamps:
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            continue
        by_hour[dt.hour] += 1
        by_dow[dt.weekday()] += 1
        by_dow_hour[dt.weekday()][dt.hour] += 1
        day = dt.date().isoformat()
        by_day[day] = by_day.get(day, 0) + 1

    return {
        "total": agg["n"] if agg else 0,
        "first_seen": agg["first"] if agg else None,
        "last_seen": agg["last"] if agg else None,
        "window_total": len(timestamps),
        "by_hour": by_hour,
        "by_dow": by_dow,
        "by_dow_hour": by_dow_hour,
        "by_day": by_day,
    }

async def device_visits(
    mac: str,
    gap_seconds: int,
    since: str | None = None,
) -> dict:
    """
    Presence 'visits' for one device plus window aggregates.

    A visit is a maximal run of sightings whose successive gaps are
    <= ``gap_seconds``. Segmentation and the summary are delegated to
    ``blucifer.analytics.visits`` so that logic stays unit-testable without a
    database. Returns ``{"gap_seconds", "visits": [...], "summary": {...}}``.
    """
    clauses = ["mac = ?"]
    params: list = [mac]
    if since:
        clauses.append("ts >= ?")
        params.append(since)

    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            f"SELECT ts, rssi, sensor_id FROM sightings "
            f"WHERE {' AND '.join(clauses)} ORDER BY ts ASC",
            params,
        ) as cur:
            rows = [
                {"ts": r["ts"], "rssi": r["rssi"], "sensor_id": r["sensor_id"]}
                for r in await cur.fetchall()
            ]

    visits = segment_visits(rows, gap_seconds)
    return {
        "gap_seconds": gap_seconds,
        "visits": visits,
        "summary": visits_summary(visits, gap_seconds),
    }

async def prune_sightings(older_than: str) -> int:
    """Deletes sightings with ts strictly before the given ISO-8601 timestamp."""
    async with _connect() as conn:
        cur = await conn.execute("DELETE FROM sightings WHERE ts < ?", (older_than,))
        await conn.commit()
        return cur.rowcount

async def list_sensors() -> list[dict]:
    """Rollup of every sensor that has ever reported a sighting."""
    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT sensor_id, COUNT(*) sightings, COUNT(DISTINCT mac) devices, "
            "       MAX(ts) last_seen "
            "FROM sightings GROUP BY sensor_id"
        ) as cur:
            rows = await cur.fetchall()
    return [
        {"sensor_id": r["sensor_id"] or "unknown", "sightings": r["sightings"],
         "devices": r["devices"], "last_seen": r["last_seen"]}
        for r in rows
    ]

async def latest_sensor_by_mac() -> dict[str, str | None]:
    """The sensor that most recently reported each device."""
    async with _connect() as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT s.mac, s.sensor_id FROM sightings s "
            "JOIN (SELECT mac, MAX(id) mid FROM sightings GROUP BY mac) m ON s.id = m.mid"
        ) as cur:
            rows = await cur.fetchall()
    return {r["mac"]: r["sensor_id"] for r in rows}

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

async def set_device_notes(mac: str, notes: str | None) -> bool:
    """Stores (or clears, when notes is None/empty) the operator notes for one device.

    Returns True if a device row was updated.
    """
    mac = (mac or "").strip()
    if not mac:
        return False
    notes = (notes or "").strip() or None

    async with _connect() as conn:
        cur = await conn.execute(
            "UPDATE devices SET notes = ? WHERE mac = ?", (notes, mac)
        )
        await conn.commit()
        return cur.rowcount > 0

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
