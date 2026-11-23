"""Security baseline tests: headers, CORS, request ID sanitization, and error redaction."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from apps.api.main import create_app
from packages.common.config import Settings


@pytest.mark.security
async def test_defensive_security_headers_are_applied() -> None:
    app = create_app(settings=Settings(CLOUDSENTINEL_ENV="test"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"
    assert "Permissions-Policy" in response.headers


@pytest.mark.security
async def test_malformed_request_id_is_rejected_and_replaced() -> None:
    app = create_app(settings=Settings(CLOUDSENTINEL_ENV="test"))
    malicious_id = "bad\r\nX-Injected: true"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health", headers={"X-Request-ID": "invalid id with spaces!"})

    returned_id = response.headers["X-Request-ID"]
    assert returned_id != "invalid id with spaces!"
    assert returned_id != malicious_id
    assert len(returned_id) == 36


@pytest.mark.security
async def test_cors_allows_configured_origin_and_blocks_untrusted_origin() -> None:
    settings = Settings(
        CLOUDSENTINEL_ENV="test",
        CLOUDSENTINEL_CORS_ORIGINS="http://localhost:5173",
    )
    app = create_app(settings=settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        allowed = await client.get("/health", headers={"Origin": "http://localhost:5173"})
        blocked = await client.get("/health", headers={"Origin": "https://evil.example"})

    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in blocked.headers


@pytest.mark.security
async def test_unhandled_exception_does_not_leak_stack_trace_or_secrets() -> None:
    app = create_app(settings=Settings(CLOUDSENTINEL_ENV="test"))

    @app.get("/_test_internal_error")
    async def trigger_error() -> None:
        raise RuntimeError("Sensitive secret_token=AKIA_FAKE_INTERNAL_LEAK")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/_test_internal_error")

    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_server_error"
    assert body["error"]["message"] == "An unexpected error occurred."
    assert body["error"]["request_id"]
    assert "AKIA_FAKE_INTERNAL_LEAK" not in response.text
    assert "Traceback" not in response.text
