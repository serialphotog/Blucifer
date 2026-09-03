import aiohttp
import asyncio
import logging
import os
import platform
import time

from bleak import BleakScanner
from mac_vendor_lookup import AsyncMacLookup, BaseMacLookup, MacLookup

from blucifer.bluetooth.classifier import is_macos_uuid
from blucifer.bluetooth.models import ScannedBluetoothDevice
from blucifer.config.config import BLUETOOTH_ADAPTER, CLASSIC_BLUETOOTH_ADAPTER, SCAN_DURATION

# The max age of the vendor DB cache, in days
VENDOR_DB_MAX_AGE_DAYS: int = 7

# The timeout, in seconds, to use for the vendor DB updates
VENDOR_DB_UPDATE_TIMEOUT_SECONDS: int = 30

# How long to wait before retrying a vendor DB update that failed or timed out
VENDOR_DB_RETRY_BACKOFF_SECONDS: int = 900 # 15 minutes

# How long a negative vendor lookup (unknown OUI) stays cached before a retry
VENDOR_NEGATIVE_CACHE_TTL_SECONDS: int = 3600 # 1 hour

# Online API for vendor lookup fallback
MACVENDORS_API_URL: str = "https://api.macvendors.com/"

# How long (in seconds) to run classic (BR/EDR) discovery for
CLASSIC_SCAN_DURATION_SECONDS: int = 8

# Path to toggle Bluetooth via sysfs
RFKILL_SYSFS: str = "/sys/class/rfkill/rfkill0/state"

# The time this process started
_PROCESS_START = time.monotonic()

# Timings for crash-loop handling
_MIN_UPTIME_FOR_EXIT_SECONDS: int = 180 # 3 minutes
_BACKOFF_SLEEP_SECONDS: int = 300 # 5 minutes

# The logging instance to use
logger = logging.getLogger(__name__)

class BluetoothScanner:
    def __init__(self, 
                 adapter: str | None = None, 
                 classic_adapter: str | None = None):
        self.adapter = adapter or BLUETOOTH_ADAPTER
        self.classic_adapter = classic_adapter or CLASSIC_BLUETOOTH_ADAPTER or self.adapter
        self._use_dual_adapter = (
            self.classic_adapter is not None and
            self.adapter is not None and
            self.classic_adapter != self.adapter
        )
        self._mac_lookup: AsyncMacLookup | None = None
        self._vendor_cache: dict[str, str | None] = {}   # OUI (first 3 bytes) -> vendor or None
        self._vendor_negative_until: dict[str, float] = {}  # OUI -> monotonic time to retry a miss
        self._vendors_updated: bool = False
        self._vendor_update_task: asyncio.Task | None = None
        self._vendor_update_next_retry: float = 0.0
        self._last_api_call: float = 0.0
        self._ble_stuck: bool = False

    def _is_vendor_db_fresh(self) -> bool:
        """Checks if the cached vendor DB exists and is less than 7 days old."""
        # TODO: Should we make the age configurable?
        cache_path = BaseMacLookup.cache_path
        if not cache_path or not os.path.exists(cache_path):
            return False

        age_days = (time.time() - os.path.getmtime(cache_path)) / 86400
        return age_days < VENDOR_DB_MAX_AGE_DAYS

    def _start_vendor_db_update(self) -> None:
        """Kicks off a background task to update the vendor DB."""
        if self._vendors_updated:
            return

        if self._vendor_update_task and not self._vendor_update_task.done():
            return

        # Back off after a failed/timed-out attempt instead of hammering the network
        # on every scan cycle.
        if time.monotonic() < self._vendor_update_next_retry:
            return

        if self._is_vendor_db_fresh():
            logger.info("The MAC vendor DB cache is up to date.")
            self._vendors_updated = True
            return

        self._vendor_update_task = asyncio.create_task(self._update_vendor_db())

    async def _update_vendor_db(self) -> None:
        """Downloads the vendor MAC DB in the background"""
        try:
            logger.info("Updating the MAC vendor DB...")

            def update_sync():
                mac_lookup = MacLookup()
                mac_lookup.update_vendors()

            await asyncio.wait_for(
                asyncio.to_thread(update_sync),
                timeout=VENDOR_DB_UPDATE_TIMEOUT_SECONDS
            )
            self._vendors_updated = True
            logger.info("Successfully updated the MAC vendor DB!")
        except asyncio.TimeoutError:
            self._vendor_update_next_retry = time.monotonic() + VENDOR_DB_RETRY_BACKOFF_SECONDS
            logger.warning(f"MAC vendor DB update timed out ({VENDOR_DB_UPDATE_TIMEOUT_SECONDS}s), "
                           f"using cached/bundled data for now; retrying in "
                           f"{VENDOR_DB_RETRY_BACKOFF_SECONDS}s.")
        except Exception as ex:
            self._vendor_update_next_retry = time.monotonic() + VENDOR_DB_RETRY_BACKOFF_SECONDS
            logger.warning(f"Could not update the MAC vendor DB: {ex!r}; retrying in "
                           f"{VENDOR_DB_RETRY_BACKOFF_SECONDS}s.")

    def _is_randomized_mac(self, mac: str) -> bool:
        """
        Checks if a MAC address is locally administered (randomized).

        The second least-significant bit of the first byte indicates that a
        MAC is locally administered (a.k.a. randomized for privacy).

        Note: This returns False for MacOS UUID-formatted addresses since the
              bit checking logic here is not applicable to UUIDs.
        """
        if is_macos_uuid(mac):
            return False

        try:
            first_byte = int(mac.split(":")[0], 16)
            return bool(first_byte & 0x02)
        except (ValueError, IndexError):
            return False

    async def _get_vendor(self, mac: str) -> str | None:
        """Looks up the vendor from a MAC address OUI."""
        if is_macos_uuid(mac):
            # MacOS UUIDs have no OUI
            return None

        # Skip randomized MACs as they don't have a vendor
        if self._is_randomized_mac(mac):
            return None

        # The vendor only depends on the OUI (first 3 bytes), so cache by that.
        oui = mac[:8].upper()

        if oui in self._vendor_cache:
            cached = self._vendor_cache[oui]
            if cached is not None:
                return cached
            # Negative hit: honour it until its TTL expires, then re-look up.
            if time.monotonic() < self._vendor_negative_until.get(oui, 0.0):
                return None

        vendor = None

        # Try the local DB first
        try:
            if self._mac_lookup is None:
                self._start_vendor_db_update()
                self._mac_lookup = AsyncMacLookup()

            vendor = await self._mac_lookup.lookup(mac)
        except Exception:
            pass # Just fall through

        # Fallback to the online API if the local lookup fails
        if vendor is None:
            vendor = await self._get_vendor_online(mac)

        if vendor:
            self._vendor_cache[oui] = vendor
            self._vendor_negative_until.pop(oui, None)
        else:
            self._vendor_cache[oui] = None
            self._vendor_negative_until[oui] = time.monotonic() + VENDOR_NEGATIVE_CACHE_TTL_SECONDS

        return vendor

    async def _get_vendor_online(self, mac: str) -> str | None:
        """
        Looks up the vendor using the MACVendors.com API.

        Only sends the OUI (first 3 bytes) to preserve privacy.
        """
        # Extract the OUI (first 3 bytes)
        oui = mac[:8]

        # Rate limit: 1 request per second
        if self._last_api_call:
            elapsed = time.monotonic() - self._last_api_call
            if elapsed < 1.0:
                await asyncio.sleep(1.0 - elapsed)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{MACVENDORS_API_URL}{oui}",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    self._last_api_call = time.monotonic()

                    if response.status == 200:
                        vendor = await response.text()
                        return vendor.strip() if vendor else None
                    elif response.status == 404:
                        return None # No OUI found in DB
                    elif response.status == 429:
                        logger.debug("Vendor API rate limited")
                        return None
                    else:
                        return None
        except asyncio.TimeoutError:
            logger.debug(f"Vendor API timeout for {oui}")
            return None
        except Exception as ex:
            logger.debug(f"Vendor API error for {oui}: {ex!r}")
            return None

    async def _rfkill_toggle(self) -> bool:
        """
        Toggles Bluetooth using sysfs rfkill. Does not require a binary or fork.

        Writing to sysfs works even when FDs are nearly exhausted, unlike
        subprocess.run, which needs to fork.
        """
        try:
            with open(RFKILL_SYSFS, "w") as f:
                f.write("1") # soft-block
            await asyncio.sleep(2)
            with open(RFKILL_SYSFS, "w") as f:
                f.write("0") # unblock
            await asyncio.sleep(3)

            logger.info("Bluetooth adapter reset via sysfs rfkill")
            return True
        except Exception as ex:
            logger.error(f"sysfs rfkill toggle failed: {ex!r}")
            return False

    async def _recover_and_exit(self) -> None:
        """
        Resets the Bluetooth adapter and exits for a clean restart.

        Why exit, you ask? Well, each BleakScanner.discover() leaks D-Bus FDs
        that can't be reclaimed without a new process.

        rfkill clears BlueZ state; exit clears leaked FDs.

        Crash-loop detection: If uptime < 3 minutes, the previous restart did
        not help - sleep another 5 minutes instead of exiting again.
        """
        uptime = time.monotonic() - _PROCESS_START

        if uptime < _MIN_UPTIME_FOR_EXIT_SECONDS:
            logger.warning(f"BLE stuck right after start (uptime {uptime:.0f}s). "
                           f"Sleeping {_BACKOFF_SLEEP_SECONDS}s before retrying")
            self._ble_stuck = False
            await asyncio.sleep(_BACKOFF_SLEEP_SECONDS)
            return

        logger.critical("BLE adapter stuck (InProgress). Toggling rfkill and "
                        "exiting for fresh D-Bus connections.")

        await self._rfkill_toggle()
        os._exit(0)

    async def scan_ble(self, duration: float = SCAN_DURATION) -> list[ScannedBluetoothDevice]:
        """Performs a Bluetooth LE scan"""
        devices: list[ScannedBluetoothDevice] = []

        if self._ble_stuck:
            await self._recover_and_exit()

        try:
            kwargs = {
                "timeout": duration,
                "return_adv": True,
            }
            if self.adapter:
                kwargs["adapter"] = self.adapter

            # Wrap in wait_for as a hard deadline - bleak's timeout parameter
            # only controls the scan window duration, not the underlying D-Bus
            # call which can block indefinitely if the adapter is busy
            discovered = await asyncio.wait_for(
                BleakScanner.discover(**kwargs),
                timeout=duration+10
            )

            for device, adv_data in discovered.values():
                mac = device.address
                vendor = await self._get_vendor(mac)
                service_uuids = list(adv_data.service_uuids) if adv_data.service_uuids else []

                devices.append(ScannedBluetoothDevice(
                    mac=mac,
                    name=device.name or adv_data.local_name,
                    rssi=adv_data.rssi,
                    vendor=vendor,
                    service_uuids=service_uuids,
                    bt_type="ble",
                    manufacturer_data=dict(adv_data.manufacturer_data or {}),
                    service_data=dict(adv_data.service_data or {}),
                ))

            logger.debug(f"BLE Scan found {len(devices)} devices")
        except asyncio.TimeoutError:
            logger.warning("BLE scan time out (adapter may be busy!)")
        except Exception as ex:
            logger.error(f"BLE scan error: {ex!r}")
            if "InProgress" in str(ex):
                self._ble_stuck = True

        return devices

    def _classic_adapter_dbus_path(self) -> str:
        """Resolves the configured classic adapter to a BlueZ object path."""
        adapter = self.classic_adapter
        if not adapter:
            return "/org/bluez/hci0"
        if adapter.startswith("/"):
            return adapter
        return f"/org/bluez/{adapter}"

    async def scan_classic(
        self,
        duration: float = CLASSIC_SCAN_DURATION_SECONDS,
    ) -> list[ScannedBluetoothDevice]:
        """
        Performs a classic (BR/EDR) Bluetooth scan via the BlueZ D-Bus API.

        Linux only: BlueZ is required, and no other platform exposes a
        classic-Bluetooth discovery API. Returns an empty list elsewhere, or
        when BlueZ/D-Bus is unavailable.
        """
        if platform.system() != "Linux":
            return []

        try:
            from dbus_fast import BusType, Variant
            from dbus_fast.aio import MessageBus
        except ImportError:
            logger.warning("dbus-fast is not installed - classic Bluetooth scanning is unavailable")
            return []

        try:
            return await asyncio.wait_for(
                self._scan_classic_dbus(duration, BusType, Variant, MessageBus),
                timeout=duration + 15,
            )
        except asyncio.TimeoutError:
            logger.error("Classic scan timed out")
        except Exception as ex:
            logger.error(f"Classic scan error: {ex!r}")

        return []

    async def _scan_classic_dbus(self, duration, BusType, Variant, MessageBus) -> list[ScannedBluetoothDevice]:
        """Runs one StartDiscovery/StopDiscovery cycle and collects the results."""
        adapter_path = self._classic_adapter_dbus_path()
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        try:
            introspection = await bus.introspect("org.bluez", adapter_path)
            adapter_obj = bus.get_proxy_object("org.bluez", adapter_path, introspection)
            adapter = adapter_obj.get_interface("org.bluez.Adapter1")

            # Restrict discovery to classic (BR/EDR) so we don't double-count BLE.
            await adapter.call_set_discovery_filter({"Transport": Variant("s", "bredr")})
            await adapter.call_start_discovery()
            try:
                await asyncio.sleep(duration)
            finally:
                try:
                    await adapter.call_stop_discovery()
                except Exception as ex:
                    logger.debug(f"StopDiscovery failed: {ex!r}")

            return await self._collect_classic_devices(bus, adapter_path)
        finally:
            bus.disconnect()

    async def _collect_classic_devices(self, bus, adapter_path: str) -> list[ScannedBluetoothDevice]:
        """Reads org.bluez.Device1 objects under the adapter and keeps the BR/EDR ones."""
        root_introspection = await bus.introspect("org.bluez", "/")
        root_obj = bus.get_proxy_object("org.bluez", "/", root_introspection)
        manager = root_obj.get_interface("org.freedesktop.DBus.ObjectManager")
        objects = await manager.call_get_managed_objects()

        devices: list[ScannedBluetoothDevice] = []
        for path, interfaces in objects.items():
            if not path.startswith(adapter_path + "/"):
                continue

            props = interfaces.get("org.bluez.Device1")
            if props is None:
                continue

            # BR/EDR devices carry a class-of-device; BLE-only devices do not.
            if "Class" not in props:
                continue

            mac = props["Address"].value.upper()

            name = None
            if "Alias" in props:
                name = props["Alias"].value or None
            elif "Name" in props:
                name = props["Name"].value or None

            vendor = await self._get_vendor(mac)

            devices.append(ScannedBluetoothDevice(
                mac=mac,
                name=name,
                rssi=props["RSSI"].value if "RSSI" in props else -60,
                vendor=vendor,
                service_uuids=[],
                bt_type="classic",
                device_class=props["Class"].value,
            ))

        logger.debug(f"Classic scan found {len(devices)} devices")
        return devices

    async def scan(self, duration: float = SCAN_DURATION) -> list[ScannedBluetoothDevice]:
        """
        Performs both a BLE scan and a classic scan.

        Note: When a dedicated classic adapter is configured, the scans run
              concurrently. Otherwise, they run sequentially - a single adapter
              cannot hold two BlueZ discovery sessions with different transport
              filters at once.
        """
        ble_devices: list[ScannedBluetoothDevice] = []
        classic_devices: list[ScannedBluetoothDevice] = []

        if self._use_dual_adapter:
            # Separate adapters - we can run concurrently
            ble_task = asyncio.create_task(self.scan_ble(duration=duration))
            classic_task = asyncio.create_task(self.scan_classic())

            results = await asyncio.gather(ble_task, classic_task, return_exceptions=True)

            if isinstance(results[0], Exception):
                logger.error(f"BLE scan failed: {results[0]}")
            else:
                ble_devices = results[0]

            if isinstance(results[1], Exception):
                logger.error(f"Classic scan failed: {results[1]}")
            else:
                classic_devices = results[1]
        else:
            # Same adapter - run sequentially
            try:
                ble_devices = await self.scan_ble(duration)
            except Exception as ex:
                logger.error(f"BLE scan failed: {ex!r}")

            try:
                classic_devices = await self.scan_classic()
            except Exception as ex:
                logger.error(f"Classic scan failed: {ex!r}")

        # Merge the results, preferring BLE data if device is in both
        seen_macs = set()
        devices = []

        for device in ble_devices:
            seen_macs.add(device.mac.upper())
            devices.append(device)

        for device in classic_devices:
            if device.mac.upper() not in seen_macs:
                devices.append(device)

        logger.info(f"Scan complete: {len(ble_devices)} BLE + {len(classic_devices)} class = {len(devices)} unique devices")

        return devices