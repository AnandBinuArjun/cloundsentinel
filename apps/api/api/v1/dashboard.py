"""Authentication identity introspection, dashboard summary, and audit log endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from compliance.loader import compute_compliance_posture
from packages.auth.dependencies import get_auth_context, require_permissions
from packages.auth.rbac import AuthContext, Permission
from packages.contracts.domain import AuditEventResponse
from packages.db.models import (
    AssessmentResult,
    AssessmentRun,
    Asset,
    AuditEvent,
    CloudAccount,
    CloudConnection,
    DetectionEvent,
    Finding,
    RemediationRequest,
)
from packages.db.session import get_db_session

router = APIRouter(prefix="/api/v1", tags=["identity-and-dashboard"])


@router.get("/auth/me", summary="Return authenticated user, verified tenant, and RBAC permissions")
async def get_current_identity(
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, Any]:
    return {
        "user_id": str(auth.user_id),
        "tenant_id": str(auth.tenant_id),
        "email": auth.email,
        "subject": auth.subject,
        "role": auth.role.value,
        "permissions": sorted(p.value for p in auth.permissions),
    }


@router.get(
    "/dashboard/summary", summary="Aggregated multi-cloud posture metrics from real DB data"
)
async def get_dashboard_summary(
    provider: str | None = Query(default=None, pattern="^(aws|azure)$"),
    auth: AuthContext = Depends(require_permissions(Permission.FINDINGS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    conn_q = select(CloudConnection).where(CloudConnection.tenant_id == auth.tenant_id)
    acct_q = select(CloudAccount).where(CloudAccount.tenant_id == auth.tenant_id)
    asset_q = select(Asset).where(Asset.tenant_id == auth.tenant_id)
    find_q = select(Finding).where(Finding.tenant_id == auth.tenant_id)
    run_q = select(AssessmentRun).where(AssessmentRun.tenant_id == auth.tenant_id)
    det_q = select(DetectionEvent).where(DetectionEvent.tenant_id == auth.tenant_id)
    rem_q = select(RemediationRequest).where(RemediationRequest.tenant_id == auth.tenant_id)
    res_q = select(AssessmentResult).where(AssessmentResult.tenant_id == auth.tenant_id)

    if provider:
        conn_q = conn_q.where(CloudConnection.provider == provider)
        acct_q = acct_q.where(CloudAccount.provider == provider)
        asset_q = asset_q.where(Asset.provider == provider)
        find_q = find_q.where(Finding.provider == provider)
        run_q = run_q.where(AssessmentRun.provider == provider)
        det_q = det_q.where(DetectionEvent.provider == provider)
        rem_q = rem_q.where(RemediationRequest.provider == provider)
        res_q = res_q.where(AssessmentResult.provider == provider)

    connections = list((await session.execute(conn_q)).scalars().all())
    accounts = list((await session.execute(acct_q)).scalars().all())
    assets = list((await session.execute(asset_q)).scalars().all())
    findings = list((await session.execute(find_q)).scalars().all())
    runs = list(
        (await session.execute(run_q.order_by(desc(AssessmentRun.started_at)).limit(10)))
        .scalars()
        .all()
    )
    detections = list((await session.execute(det_q)).scalars().all())
    remediations = list((await session.execute(rem_q)).scalars().all())
    results = list((await session.execute(res_q)).scalars().all())

    open_findings = [f for f in findings if f.status == "open"]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in open_findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    results_by_rule: dict[str, list[str]] = {}
    for r in results:
        results_by_rule.setdefault(r.rule_id, []).append(r.status)
    compliance_posture = compute_compliance_posture(results_by_rule)

    data_sources = sorted({c.data_source for c in connections} | {f.data_source for f in findings})

    return {
        "tenant_id": str(auth.tenant_id),
        "data_sources": data_sources,
        "contains_synthetic_fixtures": "synthetic_fixture" in data_sources,
        "connections": {
            "total": len(connections),
            "healthy": sum(1 for c in connections if c.status == "healthy"),
            "error": sum(1 for c in connections if c.status == "error"),
            "aws": sum(1 for c in connections if c.provider == "aws"),
            "azure": sum(1 for c in connections if c.provider == "azure"),
        },
        "cloud_inventory": {
            "aws_accounts": sum(1 for a in accounts if a.provider == "aws"),
            "azure_subscriptions": sum(1 for a in accounts if a.provider == "azure"),
            "total_assets": len(assets),
        },
        "findings": {
            "total": len(findings),
            "open": len(open_findings),
            "resolved": sum(1 for f in findings if f.status == "resolved"),
            "risk_accepted": sum(1 for f in findings if f.status == "risk_accepted"),
            "by_severity": severity_counts,
        },
        "detections": {
            "total": len(detections),
            "open": sum(1 for d in detections if d.disposition == "open"),
            "critical": sum(1 for d in detections if d.severity == "critical"),
        },
        "remediations": {
            "total": len(remediations),
            "previewed": sum(1 for r in remediations if r.stage == "previewed"),
            "approved": sum(1 for r in remediations if r.stage == "approved"),
            "verified": sum(1 for r in remediations if r.stage == "verified"),
        },
        "recent_assessments": [
            {
                "id": str(r.id),
                "provider": r.provider,
                "status": r.status,
                "data_source": r.data_source,
                "checks_passed": r.checks_passed,
                "checks_failed": r.checks_failed,
                "started_at": r.started_at.isoformat(),
            }
            for r in runs
        ],
        "compliance_summary": [
            {
                "id": fw["id"],
                "name": fw["name"],
                "version": fw["version"],
                **fw["summary"],
            }
            for fw in compliance_posture["frameworks"]
        ],
    }


@router.get("/audit-events", summary="Paginated immutable tenant audit trail")
async def list_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    action: str | None = None,
    auth: AuthContext = Depends(require_permissions(Permission.AUDIT_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = select(AuditEvent).where(AuditEvent.tenant_id == auth.tenant_id)
    count_stmt = select(func.count(AuditEvent.id)).where(AuditEvent.tenant_id == auth.tenant_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
        count_stmt = count_stmt.where(AuditEvent.action == action)

    total = int((await session.execute(count_stmt)).scalar_one())
    rows = list(
        (
            await session.execute(
                stmt.order_by(desc(AuditEvent.created_at)).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            AuditEventResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in rows
        ],
    }
