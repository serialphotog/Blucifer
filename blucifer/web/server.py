import aiohttp_jinja2
import asyncio
import jinja2
import json
import logging
import secrets
import time

from aiohttp import web
from datetime import datetime, timedelta
from pathlib import Path

import blucifer.db as db

from blucifer.bluetooth.classifier import address_type, classify_device
from blucifer.bluetooth.wire import scanned_from_wire
from blucifer.config.config import SCAN_INTERVAL_SECONDS
from blucifer.db.models import BluciferSettings, Device
from blucifer.util.auth_utils import hash_password, verify_password

# The routes that are reachable without a valid session (when auth is enabled).
# /api/ingest is here because it is bearer-token authed, not session authed - the
# handler enforces its own auth.
PUBLIC_ROUTES: list[str] = [
    "/login",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/status",
    "/api/ingest",
]

# Loopback source addresses accepted for token-less ingest.
_LOOPBACK = {"127.0.0.1", "::1"}

# Name of the session cookie
SESSION_COOKIE: str = "session"

# Minimum length we accept for a new password
MIN_PASSWORD_LENGTH: int = 8

# Bound on a single SSE subscriber's pending-update queue
SSE_QUEUE_MAXSIZE: int = 2000

# How often the SSE stream emits a sensor-status event (also serves as keepalive)
SSE_STATUS_INTERVAL_SECONDS: int = 10

# No ingest within this window => the dashboard shows "no sensor" rather than
# "scanning". Generous enough to tolerate a slow / long-interval sensor.
SENSOR_STALE_SECONDS: int = max(45, SCAN_INTERVAL_SECONDS * 3)

# The logging instance to use
logger = logging.getLogger(__name__)

# The directory holding the Jinja2 templates
TEMPLATE_DIR: Path = Path(__file__).parent / "templates"

class WebServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 secure_cookies: bool = False, ingest_token: str | None = None):
        self.host = host
        self.port = port
        # Set True when the dashboard is served over HTTPS so the session cookie
        # gets the Secure attribute.
        self._secure_cookies = secure_cookies
        # Shared secret a remote sensor must present on POST /api/ingest. When
        # unset, only loopback callers may ingest.
        self._ingest_token = ingest_token
        self.app = web.Application(middlewares=[self._auth_middleware])
        self._runner: web.AppRunner | None = None
        self._sessions: dict[str, datetime] = {} # session_token -> expiry time
        self._session_duration: timedelta = timedelta(hours=24)

        # Per-connection queues for the device SSE stream.
        self._device_subscribers: set[asyncio.Queue] = set()
        # monotonic timestamp of the last accepted ingest, or None if never.
        self._last_ingest_at: float | None = None
        self.app.on_shutdown.append(self._on_shutdown)

        aiohttp_jinja2.setup(
            self.app,
            loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
            context_processors=[aiohttp_jinja2.request_processor],
        )

        self._setup_routes()

    def _setup_routes(self) -> None:
        self.app.router.add_get("/", self.index)
        self.app.router.add_get("/login", self.login_page)
        self.app.router.add_get("/settings", self.settings_page)
        self.app.router.add_post("/settings", self.settings_save)
        self.app.router.add_post("/api/auth/login", self.auth_login)
        self.app.router.add_post("/api/auth/logout", self.auth_logout)
        self.app.router.add_get("/api/auth/status", self.auth_status)
        self.app.router.add_get("/api/devices", self.devices_list)
        self.app.router.add_get("/api/devices/stream", self.devices_stream)
        self.app.router.add_post("/api/devices/group", self.devices_set_group)
        self.app.router.add_post("/api/devices/watch", self.devices_set_watch)
        self.app.router.add_post("/api/ingest", self.devices_ingest)

    def _sweep_sessions(self) -> None:
        """Drops expired session tokens so the store doesn't grow unbounded."""
        now = datetime.now()
        for token in [t for t, exp in self._sessions.items() if now > exp]:
            del self._sessions[token]

    def _create_session(self) -> str:
        """Creates a new session and returns its token."""
        self._sweep_sessions()
        token = secrets.token_urlsafe(32)
        self._sessions[token] = datetime.now() + self._session_duration
        return token

    def _validate_session(self, token: str | None) -> bool:
        """Validates that a session token is known and unexpired."""
        if not token or token not in self._sessions:
            return False

        if datetime.now() > self._sessions[token]:
            # Expired - drop it and report invalid
            del self._sessions[token]
            return False

        return True

    def _destroy_session(self, token: str | None) -> None:
        """Removes a session token if it exists."""
        if token:
            self._sessions.pop(token, None)

    def _set_session_cookie(self, response: web.StreamResponse, token: str) -> None:
        response.set_cookie(
            SESSION_COOKIE, token,
            max_age=int(self._session_duration.total_seconds()),
            httponly=True,
            samesite="Lax",
            secure=self._secure_cookies,
            path="/",
        )

    def _clear_session_cookie(self, response: web.StreamResponse) -> None:
        response.del_cookie(SESSION_COOKIE, path="/")

    async def _check_auth(self, request: web.Request) -> bool:
        """Checks if a given request is authenticated."""
        settings = await db.get_settings()

        # Auth is off, or it's enabled but no credentials are configured yet
        # (fail open so a half-configured install can't lock everyone out).
        if not settings.auth_enabled or not settings.auth_username \
                or not settings.auth_password_hash:
            return True

        return self._validate_session(request.cookies.get(SESSION_COOKIE))

    @web.middleware
    async def _auth_middleware(self, request: web.Request, handler):
        """The authentication middleware for our server."""
        if request.path in PUBLIC_ROUTES:
            # This is a public route, authentication doesn't apply here
            return await handler(request)

        if not await self._check_auth(request):
            if request.path.startswith("/api/"):
                return web.json_response({ "error": "Unauthorized" }, status=401)
            raise web.HTTPFound("/login")

        return await handler(request)

    @aiohttp_jinja2.template("index.html")
    async def index(self, request: web.Request) -> dict:
        """Serves the main (index) page."""
        settings = await db.get_settings()
        return {"auth_enabled": settings.auth_enabled}

    async def login_page(self, request: web.Request) -> web.Response:
        """Serves the login form."""
        settings = await db.get_settings()

        # Nothing to log into, or the caller is already authenticated.
        if not settings.auth_enabled \
                or self._validate_session(request.cookies.get(SESSION_COOKIE)):
            return web.HTTPFound("/")

        error = None
        if request.query.get("error") == "invalid":
            error = "Invalid username or password."

        return aiohttp_jinja2.render_template("login.html", request, {"error": error})

    async def settings_page(self, request: web.Request) -> web.Response:
        """Serves the settings page."""
        message = "Settings saved." if request.query.get("saved") else None
        return await self._render_settings(request, message=message)

    async def _render_settings(self, request: web.Request, *,
                               message: str | None = None,
                               error: str | None = None,
                               status: int = 200) -> web.Response:
        settings = await db.get_settings()
        context = {
            "auth_enabled": settings.auth_enabled,
            "username": settings.auth_username or "",
            "has_password": bool(settings.auth_password_hash),
            "min_password_length": MIN_PASSWORD_LENGTH,
            "message": message,
            "error": error,
        }
        return aiohttp_jinja2.render_template("settings.html", request, context, status=status)

    async def auth_login(self, request: web.Request) -> web.Response:
        """Validates credentials and starts a session."""
        settings = await db.get_settings()
        if not settings.auth_enabled:
            return web.HTTPSeeOther("/")

        form = await request.post()
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))

        valid = (
            settings.auth_username is not None
            and secrets.compare_digest(username, settings.auth_username)
            and verify_password(password, settings.auth_password_hash or "")
        )
        if not valid:
            logger.warning(f"Failed login attempt for username={username!r}")
            return web.HTTPSeeOther("/login?error=invalid")

        response = web.HTTPSeeOther("/")
        self._set_session_cookie(response, self._create_session())
        logger.info(f"User {username!r} logged in")
        return response

    async def auth_logout(self, request: web.Request) -> web.Response:
        """Ends the current session."""
        self._destroy_session(request.cookies.get(SESSION_COOKIE))
        response = web.HTTPSeeOther("/login")
        self._clear_session_cookie(response)
        return response

    async def auth_status(self, request: web.Request) -> web.Response:
        """Reports the current auth state as JSON."""
        settings = await db.get_settings()
        authenticated = (
            not settings.auth_enabled
            or self._validate_session(request.cookies.get(SESSION_COOKIE))
        )
        return web.json_response({
            "auth_enabled": settings.auth_enabled,
            "authenticated": authenticated,
            "username": settings.auth_username,
        })

    async def settings_save(self, request: web.Request) -> web.Response:
        """Persists the settings form."""
        current = await db.get_settings()
        form = await request.post()

        auth_enabled = form.get("auth_enabled") is not None
        username = str(form.get("username", "")).strip()
        new_password = str(form.get("new_password", ""))
        confirm_password = str(form.get("confirm_password", ""))

        password_hash = current.auth_password_hash

        # A password change is optional - only act if either field was filled.
        if new_password or confirm_password:
            if new_password != confirm_password:
                return await self._render_settings(
                    request, error="Passwords do not match.", status=400)
            if len(new_password) < MIN_PASSWORD_LENGTH:
                return await self._render_settings(
                    request,
                    error=f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
                    status=400)
            password_hash = hash_password(new_password)

        if auth_enabled:
            if not username:
                return await self._render_settings(
                    request, error="A username is required to enable authentication.",
                    status=400)
            if not password_hash:
                return await self._render_settings(
                    request, error="Set a password to enable authentication.", status=400)

        await db.update_settings(BluciferSettings(
            auth_enabled=auth_enabled,
            auth_username=username or None,
            auth_password_hash=password_hash,
        ))
        logger.info(f"Settings updated (auth_enabled={auth_enabled})")

        # Post/redirect/get. If auth was just turned on, hand the caller a
        # session so saving the form doesn't immediately lock them out.
        response = web.HTTPSeeOther("/settings?saved=1")
        if auth_enabled and not self._validate_session(request.cookies.get(SESSION_COOKIE)):
            self._set_session_cookie(response, self._create_session())
        return response

    def _device_payload(self, device: Device) -> dict:
        """Serializes a Device for the dashboard, adding class + address labels."""
        payload = device.to_dict()
        payload["class_label"] = device.device_type or classify_device(
            name=device.friendly_name,
            vendor=device.vendor,
            service_uuids=device.service_uuids,
            device_class=device.device_class,
        )
        payload["address_type"] = address_type(device.mac)
        return payload

    def publish_device(self, device: Device, is_new: bool) -> None:
        """
        Fans a device observation out to connected SSE clients.

        Called by the daemon's scan loop; safe to call with no subscribers.
        """
        if not self._device_subscribers:
            return

        message = {"device": self._device_payload(device), "is_new": is_new}
        for queue in list(self._device_subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                logger.debug("SSE subscriber queue full - dropping a device update")

    async def ingest(self, devices: list) -> tuple[int, int]:
        """
        Records a batch of scanned devices and fans them out to SSE clients.

        The single funnel for observations, whether they arrive over HTTP from a
        remote sensor or in-process. Returns (recorded, new_count).
        """
        results = await db.record_devices(devices)
        new_count = 0
        for device, is_new in results:
            self.publish_device(device, is_new)
            if is_new:
                new_count += 1

        self._last_ingest_at = time.monotonic()
        self._broadcast_status()  # flip the dashboard to "scanning" immediately
        return len(results), new_count

    def _sensor_status(self) -> dict:
        """Whether a sensor has fed us recently, for the dashboard header."""
        age = (
            None if self._last_ingest_at is None
            else round(time.monotonic() - self._last_ingest_at, 1)
        )
        return {
            "ingesting": age is not None and age <= SENSOR_STALE_SECONDS,
            "last_ingest_age_s": age,
            "stale_after_s": SENSOR_STALE_SECONDS,
        }

    def _broadcast_status(self) -> None:
        for queue in list(self._device_subscribers):
            try:
                queue.put_nowait({"status": self._sensor_status()})
            except asyncio.QueueFull:
                pass

    def _ingest_authorized(self, request: web.Request) -> bool:
        if self._ingest_token:
            header = request.headers.get("Authorization", "")
            scheme, _, token = header.partition(" ")
            return scheme.lower() == "bearer" and secrets.compare_digest(
                token, self._ingest_token
            )
        return (request.remote or "") in _LOOPBACK

    async def devices_ingest(self, request: web.Request) -> web.Response:
        """Accepts scan batches from a sensor. Body: {"devices": [<wire dict>, ...]}."""
        if not self._ingest_authorized(request):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await request.json()
            wire_devices = body["devices"]
            if not isinstance(wire_devices, list):
                raise ValueError("'devices' must be a list")
            devices = [scanned_from_wire(d) for d in wire_devices]
        except (ValueError, KeyError, TypeError) as ex:
            return web.json_response({"error": f"bad request: {ex}"}, status=400)

        recorded, new_count = await self.ingest(devices)
        return web.json_response({"recorded": recorded, "new": new_count})

    async def devices_list(self, request: web.Request) -> web.Response:
        """
        Returns stored devices as JSON (most recently seen first).

        Optional ?since= / ?until= ISO-8601 query params bound last_seen.
        """
        since = self._iso_or_none(request.query.get("since"))
        until = self._iso_or_none(request.query.get("until"))
        devices = await db.list_devices(since=since, until=until)
        return web.json_response(
            {"devices": [self._device_payload(d) for d in devices]}
        )

    @staticmethod
    def _iso_or_none(value: str | None) -> str | None:
        """Validates an ISO-8601 timestamp, returning None for missing/garbage."""
        if not value:
            return None
        try:
            return datetime.fromisoformat(value).isoformat()
        except ValueError:
            return None

    async def devices_set_group(self, request: web.Request) -> web.Response:
        """Assigns (or clears) a group for a set of devices. Body: {macs, group}."""
        try:
            body = await request.json()
        except ValueError:
            return web.json_response({"error": "invalid JSON"}, status=400)

        macs = body.get("macs")
        if not isinstance(macs, list) or not all(isinstance(m, str) for m in macs):
            return web.json_response({"error": "macs must be a list of strings"}, status=400)

        group = body.get("group")
        if group is not None and not isinstance(group, str):
            return web.json_response({"error": "group must be a string or null"}, status=400)

        updated = await db.set_device_group(macs, group)
        logger.info(f"Group {'cleared' if not group else repr(group)} for {updated} device(s)")
        return web.json_response({"updated": updated})

    async def devices_set_watch(self, request: web.Request) -> web.Response:
        """Sets the watched flag for a set of devices. Body: {macs, watched}."""
        try:
            body = await request.json()
        except ValueError:
            return web.json_response({"error": "invalid JSON"}, status=400)

        macs = body.get("macs")
        if not isinstance(macs, list) or not all(isinstance(m, str) for m in macs):
            return web.json_response({"error": "macs must be a list of strings"}, status=400)

        watched = bool(body.get("watched", True))
        updated = await db.set_device_watched(macs, watched)
        logger.info(f"Watch={'on' if watched else 'off'} for {updated} device(s)")
        return web.json_response({"updated": updated})

    async def devices_stream(self, request: web.Request) -> web.StreamResponse:
        """Server-Sent Events stream of device observations."""
        response = web.StreamResponse(headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # don't let a reverse proxy buffer the stream
        })
        await response.prepare(request)

        queue: asyncio.Queue = asyncio.Queue(maxsize=SSE_QUEUE_MAXSIZE)
        self._device_subscribers.add(queue)

        async def send_event(name: str, payload: dict) -> None:
            data = json.dumps(payload).encode("utf-8")
            await response.write(f"event: {name}\ndata: ".encode() + data + b"\n\n")

        try:
            await response.write(b": connected\n\n")
            await send_event("status", self._sensor_status())
            while True:
                try:
                    message = await asyncio.wait_for(
                        queue.get(), timeout=SSE_STATUS_INTERVAL_SECONDS
                    )
                except asyncio.TimeoutError:
                    # periodic status doubles as the keepalive
                    await send_event("status", self._sensor_status())
                    continue

                if message is None:
                    break  # shutdown sentinel

                if "status" in message:
                    await send_event("status", message["status"])
                else:
                    await send_event("device", message)
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            self._device_subscribers.discard(queue)

        return response

    async def _on_shutdown(self, app: web.Application) -> None:
        """Releases open SSE streams so cleanup() doesn't hang."""
        for queue in list(self._device_subscribers):
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                pass

    async def start(self) -> web.AppRunner:
        """Initializes the database and starts serving."""
        await db.init_db()
        logger.info(f"Database ready at {db.DB_PATH}")

        self._runner = web.AppRunner(self.app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        logger.info(f"Web dashboard available at: http://{self.host}:{self.port}")
        return self._runner

    async def stop(self) -> None:
        """Stops the web server."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            logger.info("Web server successfully stopped.")
