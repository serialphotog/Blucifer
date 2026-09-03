"""JSON wire format for :class:`ScannedBluetoothDevice`.

A scanned device carries ``manufacturer_data`` / ``service_data`` as bytes, which
JSON cannot represent. These helpers hex-encode those payloads so a sensor can POST
observations to the web node's ingest endpoint, and the endpoint can rebuild the
dataclass.
"""

import logging

from typing import Any

from blucifer.bluetooth.models import ScannedBluetoothDevice

logger = logging.getLogger(__name__)


def scanned_to_wire(device: ScannedBluetoothDevice) -> dict[str, Any]:
    """Serializes a scanned device to a JSON-safe dict."""
    return {
        "mac": device.mac,
        "name": device.name,
        "rssi": device.rssi,
        "vendor": device.vendor,
        "service_uuids": list(device.service_uuids or []),
        "bt_type": device.bt_type,
        "device_class": device.device_class,
        "manufacturer_data": {
            str(cid): bytes(payload).hex()
            for cid, payload in (device.manufacturer_data or {}).items()
        },
        "service_data": {
            str(uuid): bytes(payload).hex()
            for uuid, payload in (device.service_data or {}).items()
        },
    }


def _decode_bytes_map(raw: Any, key_cast) -> dict:
    out: dict = {}
    if not isinstance(raw, dict):
        return out
    for key, hexstr in raw.items():
        try:
            out[key_cast(key)] = bytes.fromhex(str(hexstr))
        except (ValueError, TypeError):
            logger.debug("Dropping malformed wire entry %r=%r", key, hexstr)
    return out


def scanned_from_wire(data: dict[str, Any]) -> ScannedBluetoothDevice:
    """
    Rebuilds a scanned device from :func:`scanned_to_wire` output.

    Raises ValueError if the mandatory fields (mac, rssi) are missing or the
    wrong type; tolerates missing/garbage optional fields.
    """
    mac = data.get("mac")
    rssi = data.get("rssi")
    if not isinstance(mac, str) or not isinstance(rssi, int):
        raise ValueError("wire device requires string 'mac' and int 'rssi'")

    name = data.get("name")
    vendor = data.get("vendor")
    bt_type = data.get("bt_type") or "ble"
    device_class = data.get("device_class")
    service_uuids = data.get("service_uuids") or []
    if not isinstance(service_uuids, list):
        service_uuids = []

    return ScannedBluetoothDevice(
        mac=mac,
        name=name if isinstance(name, str) else None,
        rssi=rssi,
        vendor=vendor if isinstance(vendor, str) else None,
        service_uuids=[str(u) for u in service_uuids],
        bt_type=str(bt_type),
        device_class=device_class if isinstance(device_class, int) else None,
        manufacturer_data=_decode_bytes_map(data.get("manufacturer_data"), int),
        service_data=_decode_bytes_map(data.get("service_data"), str),
    )
