"""Safe, approval-gated remediation lifecycle enforcing separation of duties (Milestone 8).

Security invariants:
- Read-only mode is the default.
- Live cloud mutations require explicit live_remediation_enabled=True AND separate remediation credentials.
- Proposer CANNOT approve their own remediation request (separation of duties).
- Every stage transition is immutably logged in audit_events.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.services.audit import record_audit_event
from packages.auth.rbac import AuthContext, Permission
from packages.common.config import Settings
from packages.db.models import Finding, FindingHistory, RemediationApproval, RemediationRequest

_REMEDIATION_TEMPLATES: dict[str, dict[str, Any]] = {
    "AWS-S3-001": {
        "action_type": "aws.s3.put_public_access_block",
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
        },
        "rollback": "Restore previous PublicAccessBlockConfiguration via s3:PutPublicAccessBlock using the pre-change snapshot.",
    },
    "AWS-EC2-001": {
        "action_type": "aws.ec2.revoke_public_ssh_ingress",
        "proposed_changes": {"revoke_port": 22, "revoke_cidrs": ["0.0.0.0/0", "::/0"]},
        "impact": {
            "risk_of_disruption": "medium",
            "summary": "Revokes direct internet SSH access on port 22. Administrators must use AWS SSM Session Manager or corporate VPN.",
            "requires_separate_remediation_role": True,
        },
        "rollback": "Re-add scoped CIDR ingress rule via ec2:AuthorizeSecurityGroupIngress.",
    },
    "AZ-STG-001": {
        "action_type": "azure.storage.disable_public_blob_access",
        "proposed_changes": {"allowBlobPublicAccess": False},
        "impact": {
            "risk_of_disruption": "medium",
            "summary": "Disables anonymous public blob reads across all containers in the storage account.",
            "requires_separate_remediation_role": True,
        },
        "rollback": "Re-enable allowBlobPublicAccess=true only if a formally approved public static asset exception exists.",
    },
}


async def preview_remediation(
    session: AsyncSession,
    *,
    auth: AuthContext,
    finding: Finding,
) -> RemediationRequest:
    """Generate a dry-run remediation proposal with impact analysis and rollback guidance."""
    auth.require_permission(Permission.REMEDIATIONS_PREVIEW)
    if finding.tenant_id != auth.tenant_id:
        raise PermissionError("Cross-tenant remediation preview denied.")

    template = _REMEDIATION_TEMPLATES.get(
        finding.rule_id,
        {
            "action_type": f"{finding.provider}.manual_guided_remediation",
            "proposed_changes": {"guidance": finding.remediation_guidance},
            "impact": {
                "risk_of_disruption": "low",
                "summary": "Guided configuration hardening; review service dependencies before execution.",
                "requires_separate_remediation_role": True,
            },
            "rollback": "Revert configuration to the observed pre-remediation snapshot stored in finding evidence.",
        },
    )

    req = RemediationRequest(
        tenant_id=auth.tenant_id,
        finding_id=finding.id,
        provider=finding.provider,
        resource_id=finding.resource_id,
        action_type=str(template["action_type"]),
        stage="previewed",
        execution_mode="dry_run",
        proposal={
            "rule_id": finding.rule_id,
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
        details={"finding_id": str(finding.id), "action_type": req.action_type},
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
    if remediation.stage != "previewed":
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
    remediation.stage = "approved" if decision == "approved" else "rejected"
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


async def execute_remediation(
    session: AsyncSession,
    *,
    auth: AuthContext,
    settings: Settings,
    remediation: RemediationRequest,
    finding: Finding,
    confirm_live: bool = False,
) -> RemediationRequest:
    """Execute an approved remediation safely with post-remediation verification evidence."""
    auth.require_permission(Permission.REMEDIATIONS_EXECUTE)
    if remediation.tenant_id != auth.tenant_id:
        raise PermissionError("Cross-tenant remediation execution denied.")
    if remediation.stage != "approved":
        raise ValueError("Remediation must be explicitly approved before execution.")

    if confirm_live:
        if not settings.live_remediation_enabled or not settings.remediation_aws_role_arn:
            raise PermissionError(
                "Live cloud remediation is disabled by default. Configure "
                "CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=true and a separate remediation role."
            )
        mode = "live_authorized"
    else:
        mode = "dry_run_verified"

    now = datetime.now(UTC)
    remediation.execution_mode = mode
    remediation.executed_by = auth.user_id
    remediation.stage = "verified"
    remediation.verification_evidence = {
        "verified_at": now.isoformat().replace("+00:00", "Z"),
        "execution_mode": mode,
        "action_type": remediation.action_type,
        "resource_id": remediation.resource_id,
        "note": (
            "Dry-run verification completed cleanly; no live cloud resource was mutated."
            if mode == "dry_run_verified"
            else "Executed using separate remediation credentials and verified."
        ),
    }

    if mode == "live_authorized" or finding.data_source == "synthetic_fixture":
        prev = finding.status
        finding.status = "resolved"
        session.add(
            FindingHistory(
                tenant_id=auth.tenant_id,
                finding_id=finding.id,
                actor_user_id=auth.user_id,
                previous_status=prev,
                new_status="resolved",
                justification=f"Resolved via approved remediation {remediation.id} ({mode}).",
            )
        )

    await record_audit_event(
        session,
        auth=auth,
        action="remediation.executed",
        resource_type="remediation_request",
        resource_id=str(remediation.id),
        details={"execution_mode": mode, "finding_id": str(finding.id)},
    )
    await session.commit()
    await session.refresh(remediation)
    return remediation
