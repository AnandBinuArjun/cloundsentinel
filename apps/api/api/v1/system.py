"""System metadata endpoint under /api/v1."""

from __future__ import annotations

from fastapi import APIRouter, Request

from packages.common.config import Settings, get_settings
from packages.contracts.system import SystemCapabilities, SystemInfoResponse

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get(
    "/system/info",
    response_model=SystemInfoResponse,
    summary="Return implemented platform capability metadata",
)
async def get_system_info(request: Request) -> SystemInfoResponse:
    """Return non-sensitive runtime status and implemented milestone flags."""
    settings: Settings = getattr(request.app.state, "settings", get_settings())
    return SystemInfoResponse(
        version=settings.version,
        environment=settings.env,
        current_milestone="M9 — Full Platform Foundation (v1.0)",
        default_mode="read_only",
        capabilities=SystemCapabilities(
            health_probes=True,
            oidc_auth=True,
            aws_connector=True,
            azure_connector=True,
            assessment_engine=True,
            threat_detection=True,
            compliance_mapping=True,
            remediation_engine=True,
        ),
    )
