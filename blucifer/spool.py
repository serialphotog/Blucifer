"""Durable store-and-forward spool for un-sent scan batches.

Lives on the sensor node (not the web node). Each row is one batch of wire-format
device dicts. Batches are added write-ahead (before the network POST is attempted)
and deleted only once the web node has acknowledged them, so a sensor restart or a
UI outage never drops observations.
"""

import json
import logging

from collections.abc import Awaitable, Callable
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS spool (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    batch      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""

# A sender returns True when the web node accepted the batch.
Sender = Callable[[list[dict]], Awaitable[bool]]


class Spool:
    """A bounded, on-disk FIFO of scan batches."""

    def __init__(self, path: Path, max_batches: int = 5000):
        self._path = Path(path)
        self._max = max(1, max_batches)
        self._conn: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._path)
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def add(self, batch: list[dict]) -> None:
        """Appends a batch, pruning the oldest rows past the size cap."""
        assert self._conn is not None, "Spool.open() not called"
        await self._conn.execute(
            "INSERT INTO spool (batch) VALUES (?)", (json.dumps(batch),)
        )
        await self._conn.execute(
            """
            DELETE FROM spool WHERE id NOT IN (
                SELECT id FROM spool ORDER BY id DESC LIMIT ?
            )
            """,
            (self._max,),
        )
        await self._conn.commit()

    async def pending(self) -> int:
        assert self._conn is not None, "Spool.open() not called"
        async with self._conn.execute("SELECT COUNT(*) FROM spool") as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async def drain(self, send: Sender) -> int:
        """
        Replays queued batches oldest-first, deleting each once ``send`` accepts it.

        Stops at the first batch ``send`` cannot deliver (returns False or raises)
        and leaves it, and everything after it, in the spool. Returns the number
        of batches successfully flushed.
        """
        assert self._conn is not None, "Spool.open() not called"
        flushed = 0
        while True:
            async with self._conn.execute(
                "SELECT id, batch FROM spool ORDER BY id ASC LIMIT 1"
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                return flushed

            row_id, raw = row
            try:
                ok = await send(json.loads(raw))
            except Exception as ex:  # network error, bad response, ...
                logger.debug("Spool send failed: %r", ex)
                return flushed

            if not ok:
                return flushed

            await self._conn.execute("DELETE FROM spool WHERE id = ?", (row_id,))
            await self._conn.commit()
            flushed += 1
