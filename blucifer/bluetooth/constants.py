# Helper constants for major types
BT_CLASS_MAJOR_PHONE = 0x02
BT_CLASS_MAJOR_AUDIO = 0x04

# Mapping of Bluetooth device codes
# See: https://www.bluetooth.com/specifications/assigned-numbers/baseband/
BLUETOOTH_CLASS_MAJOR: dict[int, str] = {
    0x01: "computer",
    0x02: "phone",
    0x03: "network",     # LAN/Network Access Point
    0x04: "audio",       # Audio/Video
    0x05: "peripheral",  # Keyboard, mouse, etc.
    0x06: "imaging",     # Printer, scanner, camera
    0x07: "wearable",
    0x08: "toy",
    0x09: "health",
}

BLUETOOTH_CLASS_MINOR_AUDIO: dict[int, str] = {
    0x01: "headset",
    0x02: "handsfree",
    0x04: "microphone",
    0x05: "speaker",
    0x06: "headphones",
    0x07: "portable_audio",
    0x08: "car_audio",
}

BLUETOOTH_CLASS_MINOR_PHONE: dict[int, str] = {
    0x01: "cellular",
    0x02: "cordless",
    0x03: "smartphone",
}