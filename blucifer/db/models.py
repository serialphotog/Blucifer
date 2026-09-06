from dataclasses import asdict, dataclass, field

@dataclass
class BluciferSettings:
    """Stores Blucifer application settings."""
    # Authentication
    auth_enabled: bool = False
    auth_username: str | None = None
    auth_password_hash: str | None = None # Stored as a bcrypt hash
    # Data retention
    sightings_retention_days: int = 30    # per-sighting history is pruned past this
    # Presence / visits
    visit_gap_seconds: int = 900          # a new "visit" starts after a gap this long

@dataclass
class Device:
    """Represents a Bluetooth device as persisted in the database."""
    mac: str
    vendor: str | None = None
    friendly_name: str | None = None
    device_type: str | None = None
    ignored: bool = False
    watched: bool = False
    first_seen: str | None = None  # ISO 8601 (UTC)
    last_seen: str | None = None   # ISO 8601 (UTC)
    total_sightings: int = 0
    service_uuids: list[str] = field(default_factory=list)
    bt_type: str = "ble"
    device_class: int | None = None
    rssi: int | None = None        # RSSI at the most recent sighting
    group_name: str | None = None  # user-assigned group label
    notes: str | None = None

    def __post_init__(self):
        if self.service_uuids is None:
            self.service_uuids = []

    def to_dict(self) -> dict:
        return asdict(self)
