"""Shared service lifecycle: start, wait for a signal, stop once."""

import asyncio
import logging
import signal

from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

StartFn = Callable[[], Awaitable[None]]
StopFn = Callable[[], Awaitable[None]]


async def run_service(start: StartFn, stop: StopFn) -> None:
    """
    Runs a service until SIGINT/SIGTERM, then shuts it down gracefully.

    ``start`` is awaited once, then the coroutine blocks until a termination
    signal arrives (or ``start`` itself returns), after which ``stop`` is awaited
    exactly once.
    """
    shutdown = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_shutdown() -> None:
        if not shutdown.is_set():
            logger.info("Shutdown signal received.")
            shutdown.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _request_shutdown)

    try:
        await start()
        await shutdown.wait()
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
        await stop()
