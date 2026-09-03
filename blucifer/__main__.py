"""Command-line entry point for Blucifer.

Two independent services:

  blucifer web    - the dashboard + database + ingest API (system of record)
  blucifer scan   - a Bluetooth sensor that pushes observations to a web node

They talk over HTTP, so they can run on the same box or on different ones.
"""
import argparse
import asyncio
import logging
import sys

from blucifer.bluetooth.utils import list_adapters
from blucifer.config.config import (
    INGEST_TOKEN,
    SCAN_INTERVAL_SECONDS,
    SERVER_URL,
    SPOOL_MAX_BATCHES,
    SPOOL_PATH,
    WEB_HOST,
    WEB_PORT,
)
from blucifer.runner import run_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _print_adapters() -> None:
    adapters = list_adapters()
    if not adapters:
        print("No Bluetooth adapters found")
        return
    print("Available Bluetooth adapters:")
    for adapter in adapters:
        print(f"\t{adapter.name}: {adapter.address} ({adapter.alias})")


async def _run_web(args: argparse.Namespace) -> None:
    from blucifer.web.server import WebServer

    server = WebServer(host=args.host, port=args.port, ingest_token=args.ingest_token)
    await run_service(server.start, server.stop)


async def _run_scan(args: argparse.Namespace) -> None:
    from blucifer.daemon import BluciferDaemon
    from blucifer.ingest_client import HttpIngestClient
    from blucifer.spool import Spool

    spool = Spool(SPOOL_PATH, max_batches=SPOOL_MAX_BATCHES)
    client = HttpIngestClient(args.server_url, args.ingest_token, spool)
    daemon = BluciferDaemon(
        adapter=args.adapter,
        classic_adapter=args.classic_adapter,
        ingest_sink=client.send,
        interval=args.interval,
    )

    async def start() -> None:
        await client.start()
        await daemon.start()

    async def stop() -> None:
        await daemon.stop()
        await client.close()

    await run_service(start, stop)


def main() -> None:
    parser = argparse.ArgumentParser(prog="blucifer", description=__doc__.splitlines()[0])
    parser.add_argument("-l", "--list-adapters", action="store_true",
                        help="List the available Bluetooth adapters and exit.")
    sub = parser.add_subparsers(dest="command")

    web = sub.add_parser("web", help="Run the dashboard / database / ingest API.")
    web.add_argument("--host", default=WEB_HOST, help=f"Bind address (default {WEB_HOST}).")
    web.add_argument("-p", "--port", type=int, default=WEB_PORT,
                     help=f"Port to serve on (default {WEB_PORT}).")
    web.add_argument("--ingest-token", default=INGEST_TOKEN,
                     help="Shared secret sensors must present on /api/ingest. "
                          "Without it, only loopback sensors may ingest.")

    scan = sub.add_parser("scan", help="Run a Bluetooth sensor that feeds a web node.")
    scan.add_argument("--server-url", default=SERVER_URL,
                      help="Base URL of the web node (e.g. http://ui-host:8080).")
    scan.add_argument("--ingest-token", default=INGEST_TOKEN,
                      help="Shared secret for the web node's /api/ingest.")
    scan.add_argument("-a", "--adapter",
                      help="Bluetooth adapter for BLE scanning (e.g. hci0).")
    scan.add_argument("--classic-adapter",
                      help="Separate adapter for classic Bluetooth scanning (e.g. hci1).")
    scan.add_argument("--interval", type=int, default=SCAN_INTERVAL_SECONDS,
                      help=f"Seconds between scan cycles (default {SCAN_INTERVAL_SECONDS}).")

    args = parser.parse_args()

    if args.list_adapters:
        _print_adapters()
        return

    if args.command == "web":
        asyncio.run(_run_web(args))
    elif args.command == "scan":
        if not args.server_url:
            scan.error("--server-url is required (or set BLUCIFER_SERVER_URL)")
        asyncio.run(_run_scan(args))
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
