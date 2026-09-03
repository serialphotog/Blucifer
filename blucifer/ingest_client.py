"""Sensor-side client that ships scan batches to the web node's ingest endpoint."""

import logging

import aiohttp

from blucifer.bluetooth.models import ScannedBluetoothDevice
from blucifer.bluetooth.wire import scanned_to_wire
from blucifer.spool import Spool

logger = logging.getLogger(__name__)

_TIMEOUT = aiohttp.ClientTimeout(total=15)


class HttpIngestClient:
    """
    Store-and-forward ingest client.

    Every batch is written to the local :class:`Spool` first (write-ahead), then
    the spool is drained oldest-first to ``{server_url}/api/ingest``. A UI outage
    just leaves batches queued for the next scan cycle.
    """

    def __init__(self, server_url: str, token: str | None, spool: Spool,
                 sensor_name: str | None = None):
        self._url = server_url.rstrip("/") + "/api/ingest"
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._sensor_name = (sensor_name or "").strip()[:64] or None
        self._spool = spool
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        await self._spool.open()
        self._session = aiohttp.ClientSession(timeout=_TIMEOUT)

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
        await self._spool.close()

    async def send(self, devices: list[ScannedBluetoothDevice]) -> None:
        """Spools this batch, then flushes as much of the backlog as it can."""
        await self._spool.add([scanned_to_wire(d) for d in devices])
        flushed = await self._spool.drain(self._post_batch)
        pending = await self._spool.pending()
        if pending:
            logger.warning(
                "Ingest backlog: %d batch(es) queued (flushed %d this cycle)",
                pending, flushed,
            )

    async def _post_batch(self, wire_devices: list[dict]) -> bool:
        assert self._session is not None, "HttpIngestClient.start() not called"
        payload: dict = {"devices": wire_devices}
        if self._sensor_name:
            payload["sensor"] = self._sensor_name
        try:
            async with self._session.post(
                self._url, json=payload, headers=self._headers
            ) as resp:
                if resp.status == 200:
                    return True
                body = (await resp.text())[:200]
                # A 400 is a malformed batch that will never succeed - drop it so
                # it doesn't wedge the queue. Anything else (401/403 auth, 5xx)
                # stays spooled for retry; the operator must fix the token/server.
                if resp.status == 400:
                    logger.error("Ingest rejected batch (400), dropping it: %s", body)
                    return True
                logger.warning("Ingest POST -> %s: %s", resp.status, body)
                return False
        except aiohttp.ClientError as ex:
            logger.warning("Ingest POST failed: %r", ex)
            return False
