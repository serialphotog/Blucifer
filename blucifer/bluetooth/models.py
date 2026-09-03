from dataclasses import dataclass, field

@dataclass
class BluetoothAdapter:
    """Represents a bluetooth adapter."""
    name: str    # The adapter name (e.g. hci0)
    address: str # The MAC address of the adapter
    alias: str   # A friendly name to identify the adapter

@dataclass
class ScannedBluetoothDevice:
    """Represents a device found during a scan."""
    mac: str                                               # The MAC address of the device
    name: str | None                                       # The name of the device
    rssi: int                                              # The RSSI value
    vendor: str | None = None                              # The vendor string
    service_uuids: list[str] = field(default_factory=list) # The BLE UUIDs for fingerprinting
    bt_type: str = "ble"                                   # "ble" or "classic"
    device_class: int | None = None                        # The class for a classic BT device
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)  # company id -> payload
    service_data: dict[str, bytes] = field(default_factory=dict)       # service uuid -> payload

    def __post_init__(self):
        if self.service_uuids is None:
            self.service_uuids = []