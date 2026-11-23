"""Safe, approval-gated remediation lifecycle enforcing separation of duties and verified execution (Phase 1).

Security invariants:
- Read-only mode is the default.
- Strict state machine:
  DRAFT / PREVIEWED / PENDING_APPROVAL -> APPROVED -> EXECUTING -> EXECUTED_UNVERIFIED -> VERIFYING -> VERIFIED
  with terminal/exception states: REJECTED, CANCELLED, FAILED, ROLLBACK_REQUIRED.
- Dry-run (`confirm_live=False`) is NEVER represented as live execution (`execution_mode="dry_run"`),
  stops at `stage="executed_unverified"` (`verification_status="dry_run_simulated"`), and NEVER resolves
  any finding (neither `live` nor `synthetic_fixture`).
- Approved does not mean executed; executed does not mean verified.
- Only a verified post-remediation reassessment returning `CheckStatus.PASS` for the finding's rule and
  resource can transition a request to `stage="verified"` and auto-resolve the finding.
- If a live provider executor is not implemented/registered for an action, live execution (`confirm_live=True`)
  is rejected with `UnsupportedRemediationOperationError` (`HTTP 501`) and never simulated.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.services.audit import record_audit_event
from packages.assessment.interface import CheckStatus
from packages.auth.rbac import AuthContext, Permission
from packages.common.config import Settings
from packages.common.redaction import redact_data
from packages.db.models import Finding, FindingHistory, RemediationApproval, RemediationRequest


class RemediationStage(StrEnum):
    DRAFT = "draft"
    PREVIEWED = "previewed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    EXECUTED_UNVERIFIED = "executed_unverified"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    ROLLBACK_REQUIRED = "rollback_required"


class UnsupportedRemediationOperationError(NotImplementedError):
    """Raised when live execution is requested for an action without a registered live provider executor."""


@dataclass(frozen=True)
class ProviderMutationOutcome:
    success: bool
    operation_id: str
    provider_response: dict[str, Any]
    error_message: str | None = None
    rollback_required: bool = False


@dataclass(frozen=True)
class ReassessmentVerificationOutcome:
    rule_id: str
    resource_id: str
    status: CheckStatus
    observed_config: dict[str, Any]
    explanation: str


ProviderExecutor = Callable[[RemediationRequest, Finding, Settings], ProviderMutationOutcome]
PostureVerifier = Callable[[RemediationRequest, Finding, Settings], ReassessmentVerificationOutcome]

_REMEDIATION_TEMPLATES: dict[str, dict[str, Any]] = {
    "AWS-S3-001": {
        "action_type": "aws.s3.put_public_access_block",
        "provider": "aws",
        "resource_prefix": "arn:aws:s3:::",
        "proposed_changes": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        "impact": {
            "risk_of_disruption": "medium",
            "summary": "Blocks public ACLs and public bucket policies. Applications relying on unauthenticated S3 URLs will receive HTTP 403.",
            "requires_separate_remediation_role": True,
            "reversible": True,
        },
        "rollback": "Restore previous PublicAccessBlockConfiguration via s3:PutPublicAccessBlock using the pre-change snapshot.",
    },
    "AWS-EC2-001": {
        "action_type": "aws.ec2.revoke_public_ssh_ingress",
        "provider": "aws",
        "resource_prefix": "arn:aws:ec2:",
        "proposed_changes": {"revoke_port": 22, "revoke_cidrs": ["0.0.0.0/0", "::/0"]},
        "impact": {
            "risk_of_disruption": "medium",
            "summary": "Revokes direct internet SSH access on port 22. Administrators must use AWS SSM Session Manager or corporate VPN.",
            "requires_separate_remediation_role": True,
            "reversible": True,
        },
        "rollback": "Re-add scoped CIDR ingress rule via ec2:AuthorizeSecurityGroupIngress.",
    },
    "AZ-STG-001": {
        "action_type": "azure.storage.disable_public_blob_access",
        "provider": "azure",
        "resource_prefix": "/subscriptions/",
        "proposed_changes": {"allowBlobPublicAccess": False},
        "impact": {
            "risk_of_disruption": "medium",
            "summary": "Disables anonymous public blob reads across all containers in the storage account.",
            "requires_separate_remediation_role": True,
            "reversible": True,
        },
        "rollback": "Re-enable allowBlobPublicAccess=true only if a formally approved public static asset exception exists.",
    },
}

ALLOWED_REMEDIATION_ACTIONS: frozenset[str] = frozenset(
    {
        "aws.s3.put_public_access_block",
        "aws.ec2.revoke_public_ssh_ingress",
        "azure.storage.disable_public_blob_access",
        "aws.manual_guided_remediation",
        "azure.manual_guided_remediation",
    }
)


def _compute_evidence_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_resource_and_action_scope(finding: Finding, action_type: str) -> None:
    if action_type not in ALLOWED_REMEDIATION_ACTIONS:
        raise ValueError(f"Action type '{action_type}' is not in the remediation allowlist.")
    if not action_type.startswith(f"{finding.provider}."):
        raise ValueError(
            f"Action type '{action_type}' does not match finding provider '{finding.provider}'."
        )
    if finding.provider == "aws" and not finding.resource_id.startswith("arn:aws:"):
        raise ValueError(f"Invalid AWS resource ARN scope: '{finding.resource_id}'.")
    if finding.provider == "azure" and not finding.resource_id.startswith("/subscriptions/"):
        raise ValueError(f"Invalid Azure resource ID scope: '{finding.resource_id}'.")


async def preview_remediation(
    session: AsyncSession,
    *,
    auth: AuthContext,
    finding: Finding,
    idempotency_key: str | None = None,
) -> RemediationRequest:
    """Generate a dry-run remediation proposal with impact analysis and rollback guidance."""
    auth.require_permission(Permission.REMEDIATIONS_PREVIEW)
    if finding.tenant_id != auth.tenant_id:
        raise PermissionError("Cross-tenant remediation preview denied.")

    if idempotency_key:
        existing = (
            await session.execute(
                select(RemediationRequest).where(
                    RemediationRequest.tenant_id == auth.tenant_id,
                    RemediationRequest.idempotency_key == idempotency_key,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

    template = _REMEDIATION_TEMPLATES.get(
        finding.rule_id,
        {
            "action_type": f"{finding.provider}.manual_guided_remediation",
            "proposed_changes": {"guidance": finding.remediation_guidance},
            "impact": {
                "risk_of_disruption": "low",
                "summary": "Guided configuration hardening; review service dependencies before execution.",
                "requires_separate_remediation_role": True,
                "reversible": True,
            },
            "rollback": "Revert configuration to the observed pre-remediation snapshot stored in finding evidence.",
        },
    )

    action_type = str(template["action_type"])
    _validate_resource_and_action_scope(finding, action_type)

    req = RemediationRequest(
        tenant_id=auth.tenant_id,
        finding_id=finding.id,
        provider=finding.provider,
        resource_id=finding.resource_id,
        action_type=action_type,
        stage=RemediationStage.PREVIEWED.value,
        execution_mode="dry_run",
        idempotency_key=idempotency_key,
        verification_rule_id=finding.rule_id,
        verification_status="unverified",
        proposal={
            "rule_id": finding.rule_id,
            "account_ref": finding.account_ref,
            "resource_id": finding.resource_id,
            "proposed_changes": template["proposed_changes"],
            "read_only_default_notice": "Preview only — no cloud API mutations were executed.",
        },
        impact_analysis=dict(template["impact"]),
        rollback_guidance=str(template["rollback"]),
        proposed_by=auth.user_id,
    )
    session.add(req)
    await session.flush()

    await record_audit_event(
        session,
        auth=auth,
        action="remediation.previewed",
        resource_type="remediation_request",
        resource_id=str(req.id),
        details={
            "finding_id": str(finding.id),
            "action_type": req.action_type,
            "stage": req.stage,
        },
    )
    await session.commit()
    await session.refresh(req)
    return req


async def approve_remediation(
    session: AsyncSession,
    *,
    auth: AuthContext,
    remediation: RemediationRequest,
    decision: str,
    comment: str | None = None,
) -> RemediationRequest:
    """Approve or reject a previewed remediation request, enforcing separation of duties."""
    auth.require_permission(Permission.REMEDIATIONS_APPROVE)
    if remediation.tenant_id != auth.tenant_id:
        raise PermissionError("Cross-tenant remediation approval denied.")
    if remediation.stage not in (
        RemediationStage.DRAFT.value,
        RemediationStage.PREVIEWED.value,
        RemediationStage.PENDING_APPROVAL.value,
    ):
        raise ValueError(f"Remediation cannot be decided from stage '{remediation.stage}'.")
    if decision not in ("approved", "rejected"):
        raise ValueError("Decision must be 'approved' or 'rejected'.")
    if decision == "approved" and remediation.proposed_by == auth.user_id:
        raise PermissionError(
            "Separation of duties violation: the proposer cannot approve their own remediation."
        )

    approval = RemediationApproval(
        tenant_id=auth.tenant_id,
        remediation_request_id=remediation.id,
        approver_user_id=auth.user_id,
        decision=decision,
        comment=comment,
    )
    session.add(approval)
    remediation.stage = (
        RemediationStage.APPROVED.value
        if decision == "approved"
        else RemediationStage.REJECTED.value
    )
    remediation.approved_by = auth.user_id if decision == "approved" else None

    await record_audit_event(
        session,
        auth=auth,
        action=f"remediation.{decision}",
        resource_type="remediation_request",
        resource_id=str(remediation.id),
        details={"comment": comment or "", "proposed_by": str(remediation.proposed_by)},
    )
    await session.commit()
    await session.refresh(remediation)
    return remediation


async def cancel_remediation(
    session: AsyncSession,
    *,
    auth: AuthContext,
    remediation: RemediationRequest,
    reason: str = "Cancelled by operator",
) -> RemediationRequest:
    """Cancel a remediation request that has not yet been executed."""
    auth.require_permission(Permission.REMEDIATIONS_APPROVE)
    if remediation.tenant_id != auth.tenant_id:
        raise PermissionError("Cross-tenant remediation cancellation denied.")
    if remediation.stage in (
        RemediationStage.EXECUTING.value,
        RemediationStage.EXECUTED_UNVERIFIED.value,
        RemediationStage.VERIFYING.value,
        RemediationStage.VERIFIED.value,
    ):
        raise ValueError(f"Cannot cancel remediation in stage '{remediation.stage}'.")

    remediation.stage = RemediationStage.CANCELLED.value
    remediation.failure_reason = reason
    await record_audit_event(
        session,
        auth=auth,
        action="remediation.cancelled",
        resource_type="remediation_request",
        resource_id=str(remediation.id),
        details={"reason": reason},
    )
    await session.commit()
    await session.refresh(remediation)
    return remediation


async def execute_remediation(
    session: AsyncSession,
    *,
    auth: AuthContext,
    settings: Settings,
    remediation: RemediationRequest,
    finding: Finding,
    confirm_live: bool = False,
    idempotency_key: str | None = None,
    provider_executor: ProviderExecutor | None = None,
    posture_verifier: PostureVerifier | None = None,
) -> RemediationRequest:
    """Execute an approved remediation following the strict state machine.

    - Dry-run (`confirm_live=False`): simulates the proposed plan without mutating cloud state,
      transitions to `stage='executed_unverified'` (`verification_status='dry_run_simulated'`),
      and NEVER resolves the finding.
    - Live execution (`confirm_live=True`): requires `live_remediation_enabled=True`, separate
      remediation credentials, an implemented `provider_executor`, and a `posture_verifier`
      read-back reassessment that returns `CheckStatus.PASS` before marking `stage='verified'`
      and resolving the finding.
    """
    auth.require_permission(Permission.REMEDIATIONS_EXECUTE)
    if remediation.tenant_id != auth.tenant_id or finding.tenant_id != auth.tenant_id:
        raise PermissionError("Cross-tenant remediation execution denied.")
    if remediation.finding_id != finding.id or remediation.resource_id != finding.resource_id:
        raise ValueError("Remediation request resource scope does not match target finding.")

    _validate_resource_and_action_scope(finding, remediation.action_type)

    # Idempotency & replay protection: reject duplicate execution from non-approved stages.
    if remediation.stage != RemediationStage.APPROVED.value:
        raise ValueError(
            f"Remediation must be in 'approved' stage before execution (current stage: '{remediation.stage}')."
        )
    if not remediation.approved_by:
        raise ValueError("Remediation lacks a verified approver user ID.")
    if remediation.approved_by == remediation.proposed_by:
        raise PermissionError("Separation of duties violation detected on remediation record.")

    now = datetime.now(UTC)
    op_id = f"op-{uuid.uuid4().hex[:16]}"
    if idempotency_key:
        remediation.idempotency_key = idempotency_key

    # Branch 1: Dry-run simulation (never mutates cloud, never marks verified, never resolves finding)
    if not confirm_live:
        remediation.stage = RemediationStage.EXECUTED_UNVERIFIED.value
        remediation.execution_mode = "dry_run"
        remediation.executed_by = auth.user_id
        remediation.executed_at = now
        remediation.operation_id = op_id
        remediation.verification_rule_id = finding.rule_id
        remediation.verification_status = "dry_run_simulated"
        evidence_body: dict[str, Any] = {
            "simulated_at": now.isoformat().replace("+00:00", "Z"),
            "execution_mode": "dry_run",
            "operation_id": op_id,
            "action_type": remediation.action_type,
            "resource_id": remediation.resource_id,
            "verification_rule_id": finding.rule_id,
            "verification_outcome": "NOT_EXECUTED_DRY_RUN",
            "finding_resolved": False,
            "note": (
                "Dry-run simulation completed. No cloud resource was mutated and the finding "
                "remains open until a real remediation is verified by reassessment."
            ),
        }
        evidence_body["integrity_sha256"] = _compute_evidence_digest(evidence_body)
        remediation.verification_evidence = evidence_body

        await record_audit_event(
            session,
            auth=auth,
            action="remediation.executed",
            resource_type="remediation_request",
            resource_id=str(remediation.id),
            details={
                "execution_mode": "dry_run",
                "stage": remediation.stage,
                "finding_id": str(finding.id),
                "finding_resolved": False,
            },
        )
        await session.commit()
        await session.refresh(remediation)
        return remediation

    # Branch 2: Live execution requested (confirm_live=True)
    if not settings.live_remediation_enabled:
        raise PermissionError(
            "Live cloud remediation is disabled by default. Set CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=true."
        )
    if finding.provider == "aws" and not settings.remediation_aws_role_arn:
        raise PermissionError(
            "Separate AWS remediation role ARN (CLOUDSENTINEL_REMEDIATION_AWS_ROLE_ARN) is required for live remediation."
        )

    if provider_executor is None:
        raise UnsupportedRemediationOperationError(
            f"Live provider executor for action '{remediation.action_type}' is not enabled in this environment."
        )

    # Transition: APPROVED -> EXECUTING
    remediation.stage = RemediationStage.EXECUTING.value
    remediation.execution_mode = "live_authorized"
    remediation.executed_by = auth.user_id
    remediation.executed_at = now
    remediation.operation_id = op_id
    await session.flush()

    mutation = provider_executor(remediation, finding, settings)
    redacted_resp = redact_data(mutation.provider_response)

    if not mutation.success:
        remediation.stage = (
            RemediationStage.ROLLBACK_REQUIRED.value
            if mutation.rollback_required
            else RemediationStage.FAILED.value
        )
        remediation.verification_status = "mutation_failed"
        remediation.failure_reason = mutation.error_message or "Cloud provider mutation failed."
        fail_ev: dict[str, Any] = {
            "executed_at": now.isoformat().replace("+00:00", "Z"),
            "execution_mode": "live_authorized",
            "operation_id": mutation.operation_id or op_id,
            "action_type": remediation.action_type,
            "resource_id": remediation.resource_id,
            "provider_response": redacted_resp,
            "verification_outcome": "MUTATION_FAILED",
            "error": remediation.failure_reason,
        }
        fail_ev["integrity_sha256"] = _compute_evidence_digest(fail_ev)
        remediation.verification_evidence = fail_ev
        await record_audit_event(
            session,
            auth=auth,
            action="remediation.failed",
            resource_type="remediation_request",
            resource_id=str(remediation.id),
            details={"stage": remediation.stage, "error": remediation.failure_reason},
        )
        await session.commit()
        await session.refresh(remediation)
        return remediation

    # Transition: EXECUTING -> EXECUTED_UNVERIFIED
    remediation.stage = RemediationStage.EXECUTED_UNVERIFIED.value
    remediation.operation_id = mutation.operation_id or op_id
    remediation.verification_rule_id = finding.rule_id
    remediation.verification_status = "pending_reassessment"
    await session.flush()

    if posture_verifier is None:
        unverified_ev: dict[str, Any] = {
            "executed_at": now.isoformat().replace("+00:00", "Z"),
            "execution_mode": "live_authorized",
            "operation_id": remediation.operation_id,
            "action_type": remediation.action_type,
            "resource_id": remediation.resource_id,
            "provider_response": redacted_resp,
            "verification_rule_id": finding.rule_id,
            "verification_outcome": "EXECUTED_AWAITING_REASSESSMENT",
            "finding_resolved": False,
        }
        unverified_ev["integrity_sha256"] = _compute_evidence_digest(unverified_ev)
        remediation.verification_evidence = unverified_ev
        await session.commit()
        await session.refresh(remediation)
        return remediation

    # Transition: EXECUTED_UNVERIFIED -> VERIFYING
    remediation.stage = RemediationStage.VERIFYING.value
    await session.flush()

    verification = posture_verifier(remediation, finding, settings)
    verified_now = datetime.now(UTC)

    if (
        verification.status == CheckStatus.PASS
        and verification.rule_id == finding.rule_id
        and verification.resource_id == finding.resource_id
    ):
        remediation.stage = RemediationStage.VERIFIED.value
        remediation.verification_status = "verified_pass"
        remediation.verified_at = verified_now
        ver_ev: dict[str, Any] = {
            "executed_at": now.isoformat().replace("+00:00", "Z"),
            "verified_at": verified_now.isoformat().replace("+00:00", "Z"),
            "execution_mode": "live_authorized",
            "operation_id": remediation.operation_id,
            "action_type": remediation.action_type,
            "resource_id": remediation.resource_id,
            "provider_response": redacted_resp,
            "verification_rule_id": verification.rule_id,
            "verification_outcome": CheckStatus.PASS.value,
            "observed_config_after": redact_data(verification.observed_config),
            "explanation": verification.explanation,
            "finding_resolved": True,
        }
        ver_ev["integrity_sha256"] = _compute_evidence_digest(ver_ev)
        remediation.verification_evidence = ver_ev

        prev_status = finding.status
        finding.status = "resolved"
        finding.last_seen_at = verified_now
        session.add(
            FindingHistory(
                tenant_id=auth.tenant_id,
                finding_id=finding.id,
                actor_user_id=auth.user_id,
                previous_status=prev_status,
                new_status="resolved",
                justification=(
                    f"Resolved after verified live remediation {remediation.id} "
                    f"(operation {remediation.operation_id}, rule {verification.rule_id} PASS)."
                ),
            )
        )
        await record_audit_event(
            session,
            auth=auth,
            action="remediation.verified",
            resource_type="remediation_request",
            resource_id=str(remediation.id),
            details={
                "operation_id": remediation.operation_id,
                "finding_id": str(finding.id),
                "verification_outcome": "PASS",
            },
        )
    else:
        remediation.stage = RemediationStage.FAILED.value
        remediation.verification_status = f"verification_{verification.status.value.lower()}"
        remediation.failure_reason = (
            f"Post-remediation reassessment for rule {finding.rule_id} returned "
            f"{verification.status.value}: {verification.explanation}"
        )
        failed_ver_ev: dict[str, Any] = {
            "executed_at": now.isoformat().replace("+00:00", "Z"),
            "verified_at": verified_now.isoformat().replace("+00:00", "Z"),
            "execution_mode": "live_authorized",
            "operation_id": remediation.operation_id,
            "action_type": remediation.action_type,
            "resource_id": remediation.resource_id,
            "provider_response": redacted_resp,
            "verification_rule_id": verification.rule_id,
            "verification_outcome": verification.status.value,
            "observed_config_after": redact_data(verification.observed_config),
            "explanation": verification.explanation,
            "finding_resolved": False,
        }
        failed_ver_ev["integrity_sha256"] = _compute_evidence_digest(failed_ver_ev)
        remediation.verification_evidence = failed_ver_ev
        await record_audit_event(
            session,
            auth=auth,
            action="remediation.verification_failed",
            resource_type="remediation_request",
            resource_id=str(remediation.id),
            details={
                "operation_id": remediation.operation_id,
                "finding_id": str(finding.id),
                "verification_outcome": verification.status.value,
            },
        )

    await session.commit()
    await session.refresh(remediation)
    return remediation
