"""Pydantic v2 domain request/response schemas for all /api/v1 resources."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ConnectionCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    provider: Literal["aws", "azure"]
    auth_mode: str = Field(min_length=3, max_length=48)
    account_or_subscription_id: str = Field(min_length=4, max_length=128)
    role_arn: str | None = Field(default=None, max_length=256)
    external_id: str | None = Field(default=None, max_length=128)
    azure_tenant_id: str | None = Field(default=None, max_length=128)
    azure_client_id: str | None = Field(default=None, max_length=128)
    secret_ref: str | None = Field(default=None, max_length=256)
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"])
    data_source: Literal["live", "synthetic_fixture"] = "live"

    @field_validator("role_arn")
    @classmethod
    def reject_root_role_arn(cls, value: str | None) -> str | None:
        if value and ":root" in value:
            raise ValueError("AWS root ARNs or root credentials are strictly prohibited.")
        return value


class ConnectionResponse(BaseModel):
    id: uuid.UUID
    name: str
    provider: str
    auth_mode: str
    account_or_subscription_id: str
    role_arn: str | None
    azure_tenant_id: str | None
    regions: list[str]
    status: str
    data_source: str
    preflight_summary: dict[str, Any]
    last_validated_at: datetime | None
    created_at: datetime


class AssessmentTriggerRequest(BaseModel):
    connection_id: uuid.UUID
    idempotency_key: str | None = Field(default=None, max_length=128)


class AssessmentRunResponse(BaseModel):
    id: uuid.UUID
    connection_id: uuid.UUID
    provider: str
    status: str
    data_source: str
    job_id: str | None = None
    idempotency_key: str | None = None
    progress_pct: int = 0
    failure_reason: str | None = None
    assets_discovered: int
    checks_passed: int
    checks_failed: int
    checks_not_assessed: int
    checks_errored: int
    partial_failures: list[dict[str, Any]]
    queued_at: datetime | None = None
    started_at: datetime
    completed_at: datetime | None
    cancelled_at: datetime | None = None


class AssessmentResultResponse(BaseModel):
    id: uuid.UUID
    assessment_run_id: uuid.UUID
    asset_id: uuid.UUID | None
    rule_id: str
    rule_version: str
    provider: str
    account_ref: str
    resource_id: str
    region: str
    status: str
    severity: str
    confidence: str
    expected_config: dict[str, Any]
    observed_config: dict[str, Any]
    explanation: str
    evaluated_at: datetime


class AssetResponse(BaseModel):
    id: uuid.UUID
    connection_id: uuid.UUID
    provider: str
    account_ref: str
    resource_id: str
    resource_name: str
    resource_type: str
    region: str
    tags: dict[str, Any]
    configuration: dict[str, Any]
    collection_status: str
    data_source: str
    discovered_at: datetime
    last_observed_at: datetime


class FindingResponse(BaseModel):
    id: uuid.UUID
    rule_id: str
    rule_version: str
    provider: str
    account_ref: str
    resource_id: str
    resource_type: str
    region: str
    title: str
    description: str
    severity: str
    confidence: str
    status: str
    risk_score: float
    risk_explanation: dict[str, Any]
    remediation_guidance: str
    framework_mappings: list[str]
    limitations: str | None
    data_source: str
    first_seen_at: datetime
    last_seen_at: datetime


class FindingUpdateRequest(BaseModel):
    status: Literal["open", "resolved", "risk_accepted", "false_positive"]
    justification: str = Field(min_length=5, max_length=1000)


class DetectionIngestRequest(BaseModel):
    provider: Literal["aws", "azure"]
    events: list[dict[str, Any]] = Field(min_length=1, max_length=200)
    data_source: Literal["live", "synthetic_fixture"] = "live"


class DetectionDispositionRequest(BaseModel):
    disposition: Literal["open", "true_positive", "false_positive", "resolved"]
    reason: str = Field(min_length=3, max_length=1000)


class DetectionEventResponse(BaseModel):
    id: uuid.UUID
    rule_id: str
    provider: str
    provider_event_id: str = ""
    account_ref: str
    region: str
    event_name: str
    actor_identity: str
    source_ip: str | None
    severity: str
    confidence: str
    mitre_tactic: str
    mitre_technique: str
    title: str
    explanation: str
    disposition: str
    disposition_reason: str | None
    correlated_event_ids: list[str]
    evidence_payload: dict[str, Any]
    data_source: str
    event_time: datetime
    detected_at: datetime


class RemediationPreviewRequest(BaseModel):
    finding_id: uuid.UUID
    idempotency_key: str | None = Field(default=None, max_length=128)


class RemediationApprovalRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    comment: str = Field(default="", max_length=1000)


class RemediationExecuteRequest(BaseModel):
    confirm_live: bool = False
    idempotency_key: str | None = Field(default=None, max_length=128)


class RemediationResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    provider: str
    resource_id: str
    action_type: str
    stage: str
    execution_mode: str
    proposal: dict[str, Any]
    impact_analysis: dict[str, Any]
    rollback_guidance: str
    proposed_by: uuid.UUID
    approved_by: uuid.UUID | None
    executed_by: uuid.UUID | None
    idempotency_key: str | None = None
    operation_id: str | None = None
    verification_rule_id: str | None = None
    verification_status: str = "unverified"
    failure_reason: str | None = None
    verification_evidence: dict[str, Any]
    executed_at: datetime | None = None
    verified_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class AuditEventResponse(BaseModel):
    id: uuid.UUID
    actor_user_id: uuid.UUID | None
    actor_role: str
    action: str
    resource_type: str
    resource_id: str
    request_id: str
    details: dict[str, Any]
    created_at: datetime
