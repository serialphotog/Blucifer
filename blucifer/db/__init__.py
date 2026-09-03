"""Database package for Blucifer."""

from blucifer.config.config import DB_PATH
from blucifer.db.db import (
    SCHEMA,
    get_settings,
    init_db,
    list_devices,
    record_devices,
    set_device_group,
    set_device_watched,
    set_setting,
    update_settings,
)
from blucifer.db.models import BluciferSettings, Device

__all__ = [
    "DB_PATH",
    "SCHEMA",
    "BluciferSettings",
    "Device",
    "get_settings",
    "init_db",
    "list_devices",
    "record_devices",
    "set_device_group",
    "set_device_watched",
    "set_setting",
    "update_settings",
]
