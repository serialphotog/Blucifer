import re

from collections.abc import Iterable, Mapping

from blucifer.bluetooth.utils import parse_device_class

# MacOS CoreBluetooth provides UUIDs instead of a real MAC address for privacy.
_MACOS_UUID_RE = re.compile(
    r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
)

def is_macos_uuid(address: str) -> bool:
    """
    Checks if a device address is a MacOS CoreBluetooth UUID.

    Note: MacOS does not expose the real MAC address for BLE devices. It instead
          assigns a per-device UUID that Bleak passes through.
    """
    return bool(_MACOS_UUID_RE.match(address))

def address_type(address: str) -> str:
    """
    Classifies a Bluetooth address for display / vendor-lookup purposes.

    Returns one of:
      - "uuid":   a MacOS CoreBluetooth per-device UUID (no OUI, no vendor)
      - "random": a locally-administered / randomized MAC (no real vendor)
      - "public": a globally-administered MAC whose OUI identifies a vendor
    """
    if is_macos_uuid(address):
        return "uuid"

    try:
        first_octet = int(address.split(":")[0], 16)
    except (ValueError, IndexError):
        return "random"

    # Bit 1 of the first octet set => locally administered (randomized).
    return "random" if first_octet & 0x02 else "public"


########
# Device classification
########

# Every class classify_device() can return.
DEVICE_CLASSES = (
    "phone", "computer", "audio", "wearable", "tv", "tag",
    "beacon", "iot", "peripheral", "health", "vehicle", "unknown",
)

# When signals disagree, the earliest class in this tuple wins.
_PRIORITY = (
    "health", "audio", "wearable", "peripheral", "tv",
    "tag", "vehicle", "phone", "computer", "iot", "beacon",
)

_BT_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"

# 16-bit Bluetooth SIG assigned service UUIDs -> class.
_SERVICE_UUID_CLASS = {
    "1812": "peripheral",   # Human Interface Device
    "180d": "wearable",     # Heart Rate
    "1814": "wearable",     # Running Speed and Cadence
    "1816": "wearable",     # Cycling Speed and Cadence
    "1818": "wearable",     # Cycling Power
    "1826": "wearable",     # Fitness Machine
    "183e": "wearable",     # Physical Activity Monitor
    "fee0": "wearable",     # Huami / Amazfit / Mi Band
    "fee1": "wearable",
    "1808": "health",       # Glucose
    "1809": "health",       # Health Thermometer
    "1810": "health",       # Blood Pressure
    "181d": "health",       # Weight Scale
    "1822": "health",       # Pulse Oximeter
    "183a": "health",       # Insulin Delivery
    "184e": "audio",        # Audio Stream Control
    "184f": "audio",        # Broadcast Audio Scan
    "1850": "audio",        # Published Audio Capabilities
    "1843": "audio",        # Audio Input Control
    "1844": "audio",        # Volume Control
    "1849": "audio",        # Telephony and Media Audio
    "1854": "audio",        # Hearing Access
    "110b": "audio",        # A2DP Audio Sink
    "111e": "audio",        # Hands-Free
    "fe07": "audio",        # Sonos
    "feaa": "beacon",       # Eddystone
    "fd6f": "beacon",       # Exposure Notification
    "feed": "tag",          # Tile
    "feec": "tag",          # Tile
    "fd5a": "tag",          # Samsung SmartTag
    "fd44": "tag",          # Apple Find My accessory
    "1802": "tag",          # Immediate Alert (Find Me)
    "1803": "tag",          # Link Loss
    "fe0f": "iot",          # Signify / Philips Hue
    "fe95": "iot",          # Xiaomi MIoT
    "181a": "iot",          # Environmental Sensing
    "fcf1": "iot",          # Google
}

# Full 128-bit vendor service UUIDs -> class.
_VENDOR_UUID_CLASS = {
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "iot",  # Nordic UART (DIY / dev boards)
}

# Case-insensitive substrings matched against the advertised device name.
# Audio is listed before phone so "headphone" / "earphone" never read as a phone.
_NAME_KEYWORDS = (
    ("airpod", "audio"), ("headphone", "audio"), ("earphone", "audio"), ("earbud", "audio"),
    ("headset", "audio"), ("speaker", "audio"), ("soundbar", "audio"), ("soundcore", "audio"),
    ("buds", "audio"), ("beats", "audio"), ("bose", "audio"), ("jabra", "audio"),
    ("sony wh", "audio"), ("sony wf", "audio"), ("sennheiser", "audio"), ("jbl", "audio"),
    ("sonos", "audio"), ("homepod", "audio"), ("wonderboom", "audio"), ("boombox", "audio"),

    ("[tv]", "tv"), (" tv", "tv"), ("bravia", "tv"), ("roku", "tv"), ("firetv", "tv"),
    ("fire tv", "tv"), ("chromecast", "tv"), ("shield", "tv"), ("apple tv", "tv"),
    ("vizio", "tv"), ("webos", "tv"), ("aquos", "tv"),

    ("watch", "wearable"), ("band", "wearable"), ("fitbit", "wearable"), ("garmin", "wearable"),
    ("amazfit", "wearable"), ("whoop", "wearable"), ("oura", "wearable"), ("polar h", "wearable"),
    ("mi band", "wearable"), ("gear s", "wearable"), ("forerunner", "wearable"),

    ("airtag", "tag"), ("smarttag", "tag"), ("tile", "tag"), ("chipolo", "tag"),
    ("trackr", "tag"), ("tracker", "tag"),

    ("keyboard", "peripheral"), ("mouse", "peripheral"), ("trackpad", "peripheral"),
    ("dualsense", "peripheral"), ("dualshock", "peripheral"), ("xbox wireless", "peripheral"),
    ("joy-con", "peripheral"), ("joycon", "peripheral"), ("printer", "peripheral"),
    ("mx keys", "peripheral"), ("mx master", "peripheral"), ("mx anywhere", "peripheral"),
    ("8bitdo", "peripheral"), ("stadia", "peripheral"),

    ("scale", "health"), ("thermometer", "health"), ("glucose", "health"), ("oximeter", "health"),
    ("blood pressure", "health"), ("accu-chek", "health"), ("contour", "health"),
    ("omron", "health"), ("withings", "health"), ("beurer", "health"),

    ("obd", "vehicle"), ("tpms", "vehicle"), ("carplay", "vehicle"), ("vgate", "vehicle"),
    ("veepeak", "vehicle"), ("car kit", "vehicle"), ("uconnect", "vehicle"),

    ("govee", "iot"), ("hue", "iot"), ("lifx", "iot"), ("nanoleaf", "iot"), ("kasa", "iot"),
    ("wyze", "iot"), ("sonoff", "iot"), ("shelly", "iot"), ("switchbot", "iot"), ("aqara", "iot"),
    ("meross", "iot"), ("levoit", "iot"), ("smartthings", "iot"), ("smart plug", "iot"),
    ("thermostat", "iot"), ("nest", "iot"), ("ecobee", "iot"), ("doorbell", "iot"),
    ("smart lock", "iot"), ("nuki", "iot"), ("august", "iot"), ("myq", "iot"),
    ("bulb", "iot"), ("light strip", "iot"), ("led", "iot"), ("sensor", "iot"),

    ("beacon", "beacon"), ("eddystone", "beacon"), ("ibeacon", "beacon"),
    ("estimote", "beacon"), ("kontakt", "beacon"),

    ("macbook", "computer"), ("imac", "computer"), ("mac mini", "computer"),
    ("mac studio", "computer"), ("surface", "computer"), ("thinkpad", "computer"),
    ("laptop", "computer"), ("chromebook", "computer"), ("desktop", "computer"),
    ("ipad", "computer"), ("galaxy tab", "computer"),

    ("iphone", "phone"), ("pixel", "phone"), ("galaxy s", "phone"), ("galaxy note", "phone"),
    ("galaxy z", "phone"), ("galaxy a", "phone"), ("oneplus", "phone"), ("redmi", "phone"),
    ("poco ", "phone"), ("nothing phone", "phone"), ("moto g", "phone"), ("xperia", "phone"),
    (" phone", "phone"),
)

# Case-insensitive substrings matched against the vendor (from the MAC OUI).
_VENDOR_KEYWORDS = (
    ("sonos", "audio"), ("bose", "audio"), ("sennheiser", "audio"), ("harman", "audio"),
    ("skullcandy", "audio"), ("jabra", "audio"), ("gn netcom", "audio"),
    ("fitbit", "wearable"), ("garmin", "wearable"), ("polar electro", "wearable"),
    ("suunto", "wearable"), ("huami", "wearable"),
    ("tile", "tag"),
    ("signify", "iot"), ("philips lighting", "iot"), ("espressif", "iot"), ("tuya", "iot"),
    ("govee", "iot"), ("sonoff", "iot"), ("shelly", "iot"), ("lifx", "iot"),
    ("nanoleaf", "iot"), ("yeelight", "iot"), ("sengled", "iot"),
    ("logitech", "peripheral"), ("razer", "peripheral"),
    ("roku", "tv"), ("vizio", "tv"),
)

# parse_device_class() major -> our vocabulary.
_COD_MAJOR_CLASS = {
    "computer": "computer",
    "phone": "phone",
    "audio": "audio",
    "peripheral": "peripheral",
    "imaging": "peripheral",
    "wearable": "wearable",
    "health": "health",
    "network": "iot",
    "toy": "iot",
}

# Bluetooth SIG company identifiers whose BLE traffic maps unambiguously.
_COMPANY_CLASS = {
    0x0087: "wearable",   # Garmin International
    0x0157: "wearable",   # Anhui Huami (Amazfit / Zepp / Mi Band)
    0x038F: "iot",        # Xiaomi (MiBeacon sensors)
    0x0499: "iot",        # Ruuvi Innovations (RuuviTag)
}

# Apple manufacturer-data (company 0x004C) message-type byte -> class.
_APPLE_TYPE_CLASS = {
    0x02: "beacon",   # iBeacon
    0x07: "audio",    # Proximity Pairing (AirPods / Beats)
    0x09: "tv",       # AirPlay target
    0x12: "tag",      # Find My
}

# service-data UUIDs (16-bit) -> class.
_SERVICE_DATA_CLASS = {
    "feaa": "beacon",   # Eddystone
    "fd6f": "beacon",   # Exposure Notification
    "fe95": "iot",      # Xiaomi MiBeacon
    "fdcd": "iot",      # Qingping
}


def _short_uuid(u: str) -> str:
    """Collapses a 128-bit SIG UUID to its 16-bit form; leaves others untouched."""
    u = u.strip().lower()
    if len(u) == 36 and u.startswith("0000") and u.endswith(_BT_BASE_SUFFIX):
        return u[4:8]
    return u


def _from_service_uuids(uuids: Iterable[str] | None) -> set:
    found = set()
    for raw in uuids or ():
        key = _short_uuid(str(raw))
        cls = _SERVICE_UUID_CLASS.get(key) or _VENDOR_UUID_CLASS.get(key)
        if cls:
            found.add(cls)
    return found


def _from_name(name: str | None) -> set:
    if not name:
        return set()
    low = name.lower()
    return {cls for kw, cls in _NAME_KEYWORDS if kw in low}


def _from_vendor(vendor: str | None) -> set:
    if not vendor:
        return set()
    low = vendor.lower()
    return {cls for kw, cls in _VENDOR_KEYWORDS if kw in low}


def _looks_like_beacon(payload: bytes) -> bool:
    """iBeacon (02 15 ...) or AltBeacon (BE AC ...) manufacturer-data shape."""
    return len(payload) >= 4 and payload[:2] in (b"\x02\x15", b"\xbe\xac")


def _from_manufacturer_data(md: Mapping[int, bytes] | None) -> set:
    found = set()
    for company_id, payload in (md or {}).items():
        payload = bytes(payload or b"")

        if company_id in _COMPANY_CLASS:
            found.add(_COMPANY_CLASS[company_id])

        if company_id == 0x004C and payload:  # Apple
            found.add(_APPLE_TYPE_CLASS.get(payload[0], None))
        elif company_id == 0x0006 and len(payload) >= 2 and payload[0] == 0x03:
            found.add("peripheral")           # Microsoft Swift Pair accessory

        if _looks_like_beacon(payload):
            found.add("beacon")

    found.discard(None)
    return found


def _from_service_data(sd: Mapping[str, bytes] | None) -> set:
    found = set()
    for raw_uuid in (sd or {}):
        cls = _SERVICE_DATA_CLASS.get(_short_uuid(str(raw_uuid)))
        if cls:
            found.add(cls)
    return found


def _from_cod(device_class: int | None) -> str:
    if device_class is None:
        return "unknown"
    major, _minor = parse_device_class(device_class)
    return _COD_MAJOR_CLASS.get(major, "unknown")


def _best(cats: set) -> str:
    for cls in _PRIORITY:
        if cls in cats:
            return cls
    return "unknown"


def classify_device(
    *,
    name: str | None = None,
    vendor: str | None = None,
    service_uuids: Iterable[str] | None = None,
    device_class: int | None = None,
    manufacturer_data: Mapping[int, bytes] | None = None,
    service_data: Mapping[str, bytes] | None = None,
) -> str:
    """
    Best-effort device class from the signals available in a scan.

    Returns one of :data:`DEVICE_CLASSES`. A classic Class-of-Device is trusted
    outright when present; otherwise the advertised service UUIDs, manufacturer
    data (incl. Apple message type and iBeacon shape), service data, the device
    name, and the vendor OUI each vote, and the highest-priority class wins.
    """
    cod = _from_cod(device_class)
    if cod != "unknown":
        return cod

    votes = (
        _from_service_uuids(service_uuids)
        | _from_manufacturer_data(manufacturer_data)
        | _from_service_data(service_data)
        | _from_name(name)
        | _from_vendor(vendor)
    )
    return _best(votes)