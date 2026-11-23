"""Pure ASGI security, rate-limiting, request-size enforcement, and observability middleware."""

from __future__ import annotations

import json
import re
import time
import uuid
from collections import OrderedDict, deque
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from packages.common.logging import request_id_ctx

_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cache-Control", "no-store"),
)


class RequestIdMiddleware:
    """Attach a validated or freshly generated X-Request-ID to every HTTP request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = ""
        for raw_key, raw_val in scope.get("headers", []):
            if raw_key.lower() == b"x-request-id":
                incoming = raw_val.decode("latin-1").strip()
                break

        request_id = incoming if _SAFE_REQUEST_ID_RE.match(incoming) else str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        token = request_id_ctx.set(request_id)

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            request_id_ctx.reset(token)


class SecurityHeadersMiddleware:
    """Apply baseline defensive HTTP headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for header_name, header_value in _SECURITY_HEADERS:
                    headers.setdefault(header_name, header_value)
            await send(message)

        await self.app(scope, receive, send_with_security_headers)


class RequestSizeLimitMiddleware:
    """Enforce a maximum HTTP request body size (default 1 MB) to prevent memory exhaustion."""

    def __init__(self, app: ASGIApp, max_body_bytes: int = 1_048_576) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def _send_413(self, scope: Scope, send: Send) -> None:
        request_id = str(scope.get("state", {}).get("request_id", "unknown"))
        body = json.dumps(
            {
                "error": {
                    "code": "payload_too_large",
                    "message": f"Request body exceeds maximum allowed size of {self.max_body_bytes} bytes.",
                    "request_id": request_id,
                }
            }
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for raw_key, raw_val in scope.get("headers", []):
            if raw_key.lower() == b"content-length":
                try:
                    content_length = int(raw_val.decode("latin-1").strip())
                except ValueError:
                    content_length = 0
                if content_length > self.max_body_bytes:
                    await self._send_413(scope, send)
                    return
                break

        received_bytes = 0
        exceeded = False

        async def bounded_receive() -> Message:
            nonlocal received_bytes, exceeded
            msg = await receive()
            if msg["type"] == "http.request":
                chunk = msg.get("body", b"")
                received_bytes += len(chunk)
                if received_bytes > self.max_body_bytes:
                    exceeded = True
                    raise ValueError("request_body_too_large")
            return msg

        try:
            await self.app(scope, bounded_receive, send)
        except ValueError as exc:
            if exceeded and str(exc) == "request_body_too_large":
                await self._send_413(scope, send)
                return
            raise


class RateLimitMiddleware:
    """Route-aware sliding-window rate limiter with Redis support, bounded LRU fallback, and trusted-proxy IP extraction."""

    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 120,
        trusted_proxy_hosts: str = "127.0.0.1,::1",
        max_memory_keys: int = 10_000,
        redis_client: Any | None = None,
    ) -> None:
        self.app = app
        self.limit = requests_per_minute
        self.trusted_proxies = {h.strip() for h in trusted_proxy_hosts.split(",") if h.strip()}
        self.max_memory_keys = max_memory_keys
        self._redis_client = redis_client
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()

    def _resolve_client_ip(self, scope: Scope) -> str:
        client = scope.get("client")
        peer_ip = str(client[0]) if isinstance(client, tuple) and client else "unknown"
        if peer_ip in self.trusted_proxies:
            for raw_key, raw_val in scope.get("headers", []):
                if raw_key.lower() == b"x-forwarded-for":
                    forwarded = raw_val.decode("latin-1").split(",")[0].strip()
                    if forwarded:
                        return str(forwarded)
        return peer_ip

    def _classify_route(self, path: str, method: str) -> tuple[str, int]:
        """Return (route_bucket_name, effective_requests_per_minute)."""
        if path.startswith("/api/v1/auth/"):
            return "auth", max(10, min(self.limit, 30))
        if path.startswith("/api/v1/remediations/") and method in ("POST", "PATCH", "DELETE"):
            return "remediation_write", max(10, min(self.limit, 30))
        if path.startswith("/api/v1/assessments") and method == "POST":
            return "assessment_trigger", max(10, min(self.limit, 30))
        if path.startswith("/api/v1/detections/ingest"):
            return "detection_ingest", max(10, min(self.limit, 60))
        return "default", self.limit

    async def _check_rate_limit(self, key: str, route_limit: int) -> bool:
        """Return True if request is within limit, False if rate-limited."""
        if self._redis_client is not None:
            try:
                window_minute = int(time.time() // 60)
                redis_key = f"cloudsentinel:rl:{key}:{window_minute}"
                current = int(await self._redis_client.incr(redis_key))
                if current == 1:
                    await self._redis_client.expire(redis_key, 65)
                return current <= route_limit
            except Exception:
                # Gracefully degrade to bounded in-memory limiter if Redis is unreachable
                self._redis_client = None

        now = time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            while len(self._buckets) >= self.max_memory_keys:
                self._buckets.popitem(last=False)
            bucket = deque()
            self._buckets[key] = bucket
        else:
            self._buckets.move_to_end(key)

        while bucket and now - bucket[0] > 60.0:
            bucket.popleft()

        if len(bucket) >= route_limit:
            return False

        bucket.append(now)
        return True

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        if path in ("/health", "/ready"):
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "GET")).upper()
        client_ip = self._resolve_client_ip(scope)
        route_class, route_limit = self._classify_route(path, method)
        bucket_key = f"{client_ip}:{route_class}"

        allowed = await self._check_rate_limit(bucket_key, route_limit)
        if not allowed:
            request_id = str(scope.get("state", {}).get("request_id", "unknown"))
            body = json.dumps(
                {
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": "Too many requests. Please retry shortly.",
                        "request_id": request_id,
                    }
                }
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"retry-after", b"60"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)
