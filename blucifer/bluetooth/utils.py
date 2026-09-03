import json
import logging
import platform
import subprocess

from pathlib import Path

from blucifer.bluetooth.constants import BLUETOOTH_CLASS_MAJOR, \
                                         BLUETOOTH_CLASS_MINOR_AUDIO, \
                                         BLUETOOTH_CLASS_MINOR_PHONE, \
                                         BT_CLASS_MAJOR_AUDIO, \
                                         BT_CLASS_MAJOR_PHONE
from blucifer.bluetooth.models import BluetoothAdapter

# The logging instance to use
logger = logging.getLogger(__name__)

# Where the Linux kernel exposes Bluetooth controllers
_SYSFS_BLUETOOTH = Path("/sys/class/bluetooth")

def parse_device_class(device_class: int) -> tuple[str, str | None]:
    """Parses a device class into its major and minor components."""
    if device_class is None:
        return "unknown", None

    # The major device class is in bits 8-12
    major = (device_class >> 8) & 0x1F

    # The minor device class is in bits 2-7
    minor = (device_class >> 2) & 0x3F

    major_type = BLUETOOTH_CLASS_MAJOR.get(major, "unknown")
    minor_type = None

    # Handle the minor type
    if major == BT_CLASS_MAJOR_AUDIO:
        minor_type = BLUETOOTH_CLASS_MINOR_AUDIO.get(minor)
    elif major == BT_CLASS_MAJOR_PHONE:
        minor_type = BLUETOOTH_CLASS_MINOR_PHONE.get(minor)

    return major_type, minor_type

def list_adapters() -> list[BluetoothAdapter]:
    """
    Lists the available Bluetooth adapters.

    Works on Linux (via sysfs) and macOS (via system_profiler). Returns an
    empty list on any other platform, or when none can be found.
    """
    system = platform.system()
    if system == "Linux":
        return _list_adapters_linux()
    if system == "Darwin":
        return _list_adapters_macos()

    logger.warning(f"Adapter enumeration is not supported on {system}")
    return []


def _list_adapters_linux() -> list[BluetoothAdapter]:
    """Reads adapters straight from sysfs - no bluez-utils or D-Bus needed."""
    adapters: list[BluetoothAdapter] = []

    if not _SYSFS_BLUETOOTH.is_dir():
        logger.warning(f"{_SYSFS_BLUETOOTH} is missing - is the Bluetooth stack loaded?")
        return adapters

    for entry in sorted(_SYSFS_BLUETOOTH.iterdir()):
        if not entry.name.startswith("hci"):
            continue

        try:
            address = (entry / "address").read_text().strip().upper()
        except OSError:
            address = ""

        # sysfs has no friendly alias (that lives in BlueZ config), so reuse the name.
        adapters.append(BluetoothAdapter(name=entry.name, address=address, alias=entry.name))

    return adapters


def _list_adapters_macos() -> list[BluetoothAdapter]:
    """
    macOS (CoreBluetooth) exposes exactly one system-managed adapter and no
    enumeration API, so return a single entry with a best-effort address.
    """
    address = ""
    try:
        result = subprocess.run(
            ["system_profiler", "SPBluetoothDataType", "-json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        controllers = json.loads(result.stdout).get("SPBluetoothDataType", [])
        if controllers:
            props = controllers[0].get("controller_properties", {})
            address = props.get("controller_address", "").upper()
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as ex:
        logger.debug(f"Could not read macOS Bluetooth controller info: {ex!r}")

    return [BluetoothAdapter(name="CoreBluetooth", address=address, alias="System Bluetooth")]