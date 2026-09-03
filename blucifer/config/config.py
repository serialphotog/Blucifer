"""The basic configuration for Blucifer."""

import os
import socket

from pathlib import Path

# The directory where all Blucifer data is stored
DATA_DIR: Path = Path(os.environ.get("BLUCIFER_DATA_DIR", Path.home() / ".local" / "share" / "blucifer"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# The path to the Blucifer database (web node only)
DB_PATH: Path = Path(os.environ.get("BLUCIFER_DB_PATH", DATA_DIR / "blucifer.db"))

# ---- web node ----
WEB_HOST: str = os.environ.get("BLUCIFER_WEB_HOST", "127.0.0.1")
WEB_PORT: int = int(os.environ.get("BLUCIFER_WEB_PORT", "8080"))
# Default sighting-history retention (days). Overridden once set in the UI
# (Settings -> Data Retention); this value only seeds a fresh install.
SIGHTINGS_RETENTION_DAYS: int = int(os.environ.get("BLUCIFER_SIGHTINGS_RETENTION_DAYS", "30"))

# ---- sensor node ----
# How this sensor identifies itself to the web node (which room / box).
SENSOR_NAME: str = os.environ.get("BLUCIFER_SENSOR_NAME") or socket.gethostname()
# Base URL of the web node the sensor pushes observations to.
SERVER_URL: str | None = os.environ.get("BLUCIFER_SERVER_URL")
# Shared secret for POST /api/ingest (required when sensor and web are on
# different hosts; loopback ingest works without it).
INGEST_TOKEN: str | None = os.environ.get("BLUCIFER_INGEST_TOKEN")
# On-disk store-and-forward queue for un-sent scan batches.
SPOOL_PATH: Path = Path(os.environ.get("BLUCIFER_SPOOL_PATH", DATA_DIR / "spool.db"))
SPOOL_MAX_BATCHES: int = int(os.environ.get("BLUCIFER_SPOOL_MAX_BATCHES", "5000"))

# The scanning interval, in seconds
SCAN_INTERVAL_SECONDS: int = 10

# How long to scan for each cycle, in seconds
SCAN_DURATION: int = 5

# The bluetooth adapter to use. None means auto-select
BLUETOOTH_ADAPTER: str | None = os.environ.get("BLUCIFER_ADAPTER")

# A separate adapter to use for classic Bluetooth scans (None = use the same as
# BLE).
#
# Note: Setting this to a separate adapter (such as a USB dongle), allows both
#       BLE and classic scanning to occur concurrently and reduces adapter
#       contention.
CLASSIC_BLUETOOTH_ADAPTER: str | None = os.environ.get("BLUCIFER_CLASSIC_ADAPTER")