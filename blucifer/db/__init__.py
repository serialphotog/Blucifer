"""Database package for Blucifer."""

from blucifer.config.config import DB_PATH
from blucifer.db.db import (
    RETENTION_MAX_DAYS,
    RETENTION_MIN_DAYS,
    SCHEMA,
    get_device,
    get_settings,
    init_db,
    list_devices,
    list_sightings,
    prune_sightings,
    record_devices,
    set_device_group,
    set_device_watched,
    set_setting,
    sighting_summary,
    update_settings,
)
from blucifer.db.models import BluciferSettings, Device

__all__ = [
    "DB_PATH",
    "RETENTION_MAX_DAYS",
    "RETENTION_MIN_DAYS",
    "SCHEMA",
    "BluciferSettings",
    "Device",
    "get_device",
    "get_settings",
    "init_db",
    "list_devices",
    "list_sightings",
    "prune_sightings",
    "record_devices",
    "set_device_group",
    "set_device_watched",
    "set_setting",
    "sighting_summary",
    "update_settings",
]
