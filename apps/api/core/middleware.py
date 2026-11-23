"""Pure ASGI security, rate-limiting, and observability middleware."""

from __future__ import annotations

import json
import re
import time
import uuid
from collections import defaultdict, deque

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


class RateLimitMiddleware:
    """In-memory per-client sliding-window rate limiter protecting API endpoints."""

    def __init__(self, app: ASGIApp, requests_per_minute: int = 120) -> None:
        self.app = app
        self.limit = requests_per_minute
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        if path in ("/health", "/ready"):
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        client_key = client[0] if isinstance(client, tuple) and client else "unknown"
        now = time.monotonic()
        bucket = self._buckets[client_key]
        while bucket and now - bucket[0] > 60.0:
            bucket.popleft()

        if len(bucket) >= self.limit:
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

        bucket.append(now)
        await self.app(scope, receive, send)
