import asyncio
import logging
import time

from collections.abc import Awaitable, Callable

from blucifer.bluetooth.models import ScannedBluetoothDevice
from blucifer.bluetooth.scanner import BluetoothScanner
from blucifer.config.config import SCAN_INTERVAL_SECONDS

# The logging instance to use
logger = logging.getLogger(__name__)

# A sink consumes a batch of scanned devices (spool + POST, or in-process record).
IngestSink = Callable[[list[ScannedBluetoothDevice]], Awaitable[None]]


class BluciferDaemon:
    """The scanning sensor: scans on an interval and hands each batch to a sink."""

    def __init__(
        self,
        adapter: str | None,
        classic_adapter: str | None,
        ingest_sink: IngestSink,
        interval: int = SCAN_INTERVAL_SECONDS,
    ):
        self.scanner = BluetoothScanner(adapter=adapter, classic_adapter=classic_adapter)
        self._ingest_sink = ingest_sink
        self._interval = interval
        self.running: bool = False
        self._start_time: float = time.monotonic()
        self._scan_task: asyncio.Task | None = None

    async def _scan_loop(self) -> None:
        """Runs the main Bluetooth scanning loop."""
        logger.info(f"Starting scan loop (interval {self._interval}s)")

        while self.running:
            try:
                start = time.monotonic()
                devices = await self.scanner.scan()
                duration = time.monotonic() - start

                await self._ingest_sink(devices)
                logger.info(
                    f"Scan complete in {duration:.1f}s: {len(devices)} device(s) handed off"
                )
            except Exception as ex:
                logger.error(f"Scan error: {ex!r}")

            await asyncio.sleep(self._interval)

    async def start(self) -> None:
        """Starts the scan loop in the background and returns."""
        logger.info("Starting Blucifer sensor...")
        self.running = True
        self._scan_task = asyncio.create_task(self._scan_loop())
        logger.info("Blucifer sensor running.")

    async def stop(self) -> None:
        """Stops the scan loop."""
        if not self.running:
            return
        logger.info("Stopping the Blucifer sensor...")
        self.running = False

        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass

        logger.info("Blucifer sensor stopped.")
