"""Complete CloudSentinel SQLAlchemy 2 relational models (21 core entities).

Security invariants:
- UUID primary keys across all entities.
- Every tenant-owned entity carries a non-null indexed `tenant_id` foreign key.
- Raw cloud access keys, client secrets, or tokens are NEVER stored in database columns.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from packages.db.base import Base, JSONBVariant, UTCTimestamp, utcnow


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UTCTimestamp, nullable=False, default=utcnow, onupdate=utcnow
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("oidc_issuer", "oidc_subject", name="uq_users_oidc_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    oidc_issuer: Mapped[str] = mapped_column(String(255), nullable=False)
    oidc_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_memberships_tenant_user"),
        Index("ix_memberships_tenant_role", "tenant_id", "role"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class CloudConnection(Base):
    __tablename__ = "cloud_connections"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_cloud_connections_tenant_name"),
        Index("ix_cloud_connections_tenant_provider", "tenant_id", "provider"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)  # aws | azure
    auth_mode: Mapped[str] = mapped_column(String(48), nullable=False)
    # Non-secret cloud identity metadata ONLY (never raw keys or passwords)
    account_or_subscription_id: Mapped[str] = mapped_column(String(128), nullable=False)
    role_arn: Mapped[str | None] = mapped_column(String(256), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    azure_tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    azure_client_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    secret_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    regions: Mapped[list[str]] = mapped_column(JSONBVariant, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending_validation")
    data_source: Mapped[str] = mapped_column(String(32), nullable=False, default="live")
    preflight_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    last_validated_at: Mapped[datetime | None] = mapped_column(UTCTimestamp, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UTCTimestamp, nullable=False, default=utcnow, onupdate=utcnow
    )


class CloudAccount(Base):
    __tablename__ = "cloud_accounts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "provider", "external_account_id", name="uq_cloud_accounts_tenant_ext"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connection_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cloud_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    external_account_id: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    discovered_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "provider",
            "account_ref",
            "resource_id",
            name="uq_assets_tenant_resource",
        ),
        Index("ix_assets_tenant_provider_type", "tenant_id", "provider", "resource_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connection_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cloud_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    account_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    resource_name: Mapped[str] = mapped_column(String(256), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    tags: Mapped[dict[str, Any]] = mapped_column(JSONBVariant, nullable=False, default=dict)
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    collection_status: Mapped[str] = mapped_column(String(32), nullable=False, default="collected")
    data_source: Mapped[str] = mapped_column(String(32), nullable=False, default="live")
    discovered_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)
    last_observed_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class AssessmentProfile(Base):
    __tablename__ = "assessment_profiles"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    included_rules: Mapped[list[str]] = mapped_column(JSONBVariant, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class SecurityRule(Base):
    __tablename__ = "security_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    required_permissions: Mapped[list[str]] = mapped_column(
        JSONBVariant, nullable=False, default=list
    )
    expected_configuration: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    framework_mappings: Mapped[list[str]] = mapped_column(
        JSONBVariant, nullable=False, default=list
    )
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")


class AssessmentRun(Base):
    __tablename__ = "assessment_runs"
    __table_args__ = (Index("ix_assessment_runs_tenant_created", "tenant_id", "started_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connection_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cloud_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    data_source: Mapped[str] = mapped_column(String(32), nullable=False, default="live")
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    assets_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_passed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_not_assessed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_errored: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    partial_failures: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONBVariant, nullable=False, default=list
    )
    started_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UTCTimestamp, nullable=True)


class AssessmentResult(Base):
    __tablename__ = "assessment_results"
    __table_args__ = (Index("ix_assessment_results_tenant_run", "tenant_id", "assessment_run_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    assessment_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assessment_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    account_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # PASS|FAIL|NOT_ASSESSED|ERROR
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    expected_config: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    observed_config: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "rule_id", "resource_id", name="uq_findings_dedup"),
        Index("ix_findings_tenant_severity_status", "tenant_id", "severity", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    latest_result_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assessment_results.id", ondelete="SET NULL"), nullable=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    account_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # critical|high|medium|low
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)  # high|medium|low
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="open")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_explanation: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    remediation_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    framework_mappings: Mapped[list[str]] = mapped_column(
        JSONBVariant, nullable=False, default=list
    )
    limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    data_source: Mapped[str] = mapped_column(String(32), nullable=False, default="live")
    first_seen_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class FindingHistory(Base):
    __tablename__ = "finding_history"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    previous_status: Mapped[str] = mapped_column(String(24), nullable=False)
    new_status: Mapped[str] = mapped_column(String(24), nullable=False)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    detection_event_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_config: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    observed_config: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    raw_evidence_redacted: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    collected_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    mitre_tactic: Mapped[str] = mapped_column(String(64), nullable=False)
    mitre_technique: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")


class DetectionEvent(Base):
    __tablename__ = "detection_events"
    __table_args__ = (Index("ix_detection_events_tenant_detected", "tenant_id", "detected_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    account_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="global")
    event_name: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_identity: Mapped[str] = mapped_column(String(256), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    mitre_tactic: Mapped[str] = mapped_column(String(64), nullable=False)
    mitre_technique: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    disposition: Mapped[str] = mapped_column(String(24), nullable=False, default="open")
    disposition_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlated_event_ids: Mapped[list[str]] = mapped_column(
        JSONBVariant, nullable=False, default=list
    )
    evidence_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    data_source: Mapped[str] = mapped_column(String(32), nullable=False, default="live")
    event_time: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    framework_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False
    )
    control_code: Mapped[str] = mapped_column(String(48), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    limitations: Mapped[str] = mapped_column(Text, nullable=False)


class ComplianceMapping(Base):
    __tablename__ = "compliance_mappings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id: Mapped[str] = mapped_column(
        String(96), ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    coverage_status: Mapped[str] = mapped_column(String(32), nullable=False, default="partial")


class RemediationRequest(Base):
    __tablename__ = "remediation_requests"
    __table_args__ = (Index("ix_remediation_requests_tenant_stage", "tenant_id", "stage"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False, default="previewed")
    execution_mode: Mapped[str] = mapped_column(String(24), nullable=False, default="dry_run")
    proposal: Mapped[dict[str, Any]] = mapped_column(JSONBVariant, nullable=False, default=dict)
    impact_analysis: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    rollback_guidance: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_by: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    executed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    verification_evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONBVariant, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UTCTimestamp, nullable=False, default=utcnow, onupdate=utcnow
    )


class RemediationApproval(Base):
    __tablename__ = "remediation_approvals"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    remediation_request_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("remediation_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    approver_user_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)  # approved | rejected
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_tenant_created", "tenant_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    actor_role: Mapped[str] = mapped_column(String(40), nullable=False)
    action: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONBVariant, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCTimestamp, nullable=False, default=utcnow)
