"""FastAPI application factory for the CloudSentinel control plane."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncEngine

from apps.api.api.v1.cspm import router as cspm_v1_router
from apps.api.api.v1.dashboard import router as dashboard_v1_router
from apps.api.api.v1.operations import router as operations_v1_router
from apps.api.api.v1.system import router as system_v1_router
from apps.api.core.exceptions import register_exception_handlers
from apps.api.core.middleware import (
    RateLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from apps.api.core.probes import ProbeFunc, build_default_probes
from packages.auth.oidc import OIDCVerifier
from packages.common.config import Settings, get_settings
from packages.common.logging import configure_logging
from packages.contracts.system import DependencyCheck, HealthResponse, ReadinessResponse
from packages.db.session import create_db_engine, create_session_factory


def create_app(
    settings: Settings | None = None,
    readiness_probes: dict[str, ProbeFunc] | None = None,
    db_engine: AsyncEngine | None = None,
) -> FastAPI:
    """Create and configure the CloudSentinel FastAPI application."""
    runtime_settings = settings or get_settings()
    configure_logging(runtime_settings.log_level)

    app = FastAPI(
        title="CloudSentinel API",
        description=(
            "Multi-Cloud Security Posture Management & Threat Detection Platform "
            "(AWS & Microsoft Azure)"
        ),
        version=runtime_settings.version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    engine = db_engine or create_db_engine(runtime_settings.database_url)
    app.state.settings = runtime_settings
    app.state.db_engine = engine
    app.state.session_factory = create_session_factory(engine)
    app.state.oidc_verifier = OIDCVerifier(runtime_settings)

    probes = (
        readiness_probes if readiness_probes is not None else build_default_probes(runtime_settings)
    )

    # Outermost middleware executes first.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=runtime_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=runtime_settings.rate_limit_requests_per_minute,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)
    register_exception_handlers(app)

    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["operations"],
        summary="Process liveness probe",
    )
    async def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service=runtime_settings.service_name,
            version=runtime_settings.version,
            environment=runtime_settings.env,
            timestamp=datetime.now(UTC),
        )

    @app.get(
        "/ready",
        response_model=ReadinessResponse,
        responses={503: {"model": ReadinessResponse}},
        tags=["operations"],
        summary="Dependency readiness probe (PostgreSQL and Redis)",
    )
    async def ready() -> JSONResponse:
        names = list(probes.keys())
        checks_raw = await asyncio.gather(*(probes[name]() for name in names))
        dependencies: dict[str, DependencyCheck] = dict(zip(names, checks_raw, strict=True))
        all_up = bool(dependencies) and all(item.status == "up" for item in dependencies.values())

        payload = ReadinessResponse(
            status="ready" if all_up else "not_ready",
            service=runtime_settings.service_name,
            version=runtime_settings.version,
            timestamp=datetime.now(UTC),
            dependencies=dependencies,
        )
        http_status = status.HTTP_200_OK if all_up else status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse(status_code=http_status, content=payload.model_dump(mode="json"))

    app.include_router(system_v1_router)
    app.include_router(dashboard_v1_router)
    app.include_router(cspm_v1_router)
    app.include_router(operations_v1_router)
    return app


app = create_app()
