"""System operational, readiness, and error response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Liveness probe response."""

    status: Literal["ok"] = "ok"
    service: str
    version: str
    environment: str
    timestamp: datetime


class DependencyCheck(BaseModel):
    """Result of probing a single backing infrastructure dependency."""

    status: Literal["up", "down"]
    latency_ms: float = Field(ge=0.0)
    detail: str | None = None


class ReadinessResponse(BaseModel):
    """Readiness probe response reflecting actual dependency reachability."""

    status: Literal["ready", "not_ready"]
    service: str
    version: str
    timestamp: datetime
    dependencies: dict[str, DependencyCheck]


class SystemCapabilities(BaseModel):
    """Explicit feature flags showing what is genuinely implemented vs planned."""

    health_probes: bool = True
    oidc_auth: bool = False
    aws_connector: bool = False
    azure_connector: bool = False
    assessment_engine: bool = False
    threat_detection: bool = False
    compliance_mapping: bool = False
    remediation_engine: bool = False


class SystemInfoResponse(BaseModel):
    """Non-sensitive control-plane metadata."""

    product: Literal["CloudSentinel"] = "CloudSentinel"
    version: str
    environment: str
    current_milestone: str
    default_mode: Literal["read_only"] = "read_only"
    capabilities: SystemCapabilities


class ErrorDetail(BaseModel):
    """Sanitized error object returned to API clients."""

    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    """Top-level error envelope."""

    error: ErrorDetail
