"""Integration tests for FastAPI /health, /ready, /api/v1/system/info, and OpenAPI."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from apps.api.main import create_app
from packages.common.config import Settings
from packages.contracts.system import DependencyCheck


@pytest.mark.integration
async def test_health_endpoint_returns_ok() -> None:
    app = create_app(settings=Settings(CLOUDSENTINEL_ENV="test"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "cloudsentinel-api"
    assert body["environment"] == "test"
    assert "timestamp" in body
    assert "X-Request-ID" in response.headers


@pytest.mark.integration
async def test_system_info_reports_implemented_capabilities() -> None:
    app = create_app(settings=Settings(CLOUDSENTINEL_ENV="test"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/system/info")

    assert response.status_code == 200
    body = response.json()
    assert body["product"] == "CloudSentinel"
    assert body["default_mode"] == "read_only"
    assert body["capabilities"]["health_probes"] is True
    assert body["capabilities"]["oidc_auth"] is True
    assert body["capabilities"]["aws_connector"] is True
    assert body["capabilities"]["azure_connector"] is True
    assert body["capabilities"]["remediation_engine"] is True


@pytest.mark.integration
async def test_ready_endpoint_returns_200_when_dependencies_are_up() -> None:
    async def pg_up() -> DependencyCheck:
        return DependencyCheck(status="up", latency_ms=1.2, detail=None)

    async def redis_up() -> DependencyCheck:
        return DependencyCheck(status="up", latency_ms=0.7, detail=None)

    app = create_app(
        settings=Settings(CLOUDSENTINEL_ENV="test"),
        readiness_probes={"postgres": pg_up, "redis": redis_up},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["dependencies"]["postgres"]["status"] == "up"
    assert body["dependencies"]["redis"]["status"] == "up"


@pytest.mark.integration
async def test_ready_endpoint_returns_503_when_dependency_is_down() -> None:
    async def pg_down() -> DependencyCheck:
        return DependencyCheck(
            status="down",
            latency_ms=2.4,
            detail="PostgreSQL probe failed (ConnectionRefusedError)",
        )

    async def redis_up() -> DependencyCheck:
        return DependencyCheck(status="up", latency_ms=0.5, detail=None)

    app = create_app(
        settings=Settings(CLOUDSENTINEL_ENV="test"),
        readiness_probes={"postgres": pg_down, "redis": redis_up},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["dependencies"]["postgres"]["status"] == "down"
    assert body["dependencies"]["redis"]["status"] == "up"


@pytest.mark.integration
async def test_ready_endpoint_with_unreachable_ports_never_fakes_ready() -> None:
    settings = Settings(
        CLOUDSENTINEL_ENV="test",
        CLOUDSENTINEL_READINESS_TIMEOUT_SECONDS=0.5,
        DATABASE_URL="postgresql+asyncpg://user:secretpass@127.0.0.1:1/nonexistent",
        REDIS_URL="redis://127.0.0.1:1/0",
    )
    app = create_app(settings=settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["dependencies"]["postgres"]["status"] == "down"
    assert body["dependencies"]["redis"]["status"] == "down"
    # Verify credentials from DATABASE_URL are never leaked in probe diagnostics.
    assert "secretpass" not in response.text


@pytest.mark.integration
async def test_openapi_schema_is_generated() -> None:
    app = create_app(settings=Settings(CLOUDSENTINEL_ENV="test"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    assert "/health" in schema["paths"]
    assert "/ready" in schema["paths"]
    assert "/api/v1/system/info" in schema["paths"]
