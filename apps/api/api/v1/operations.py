"""Threat detection, compliance, reporting, and safe remediation endpoints."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.services.audit import record_audit_event
from apps.api.services.remediation_service import (
    UnsupportedRemediationOperationError,
    approve_remediation,
    cancel_remediation,
    execute_remediation,
    preview_remediation,
)
from apps.api.services.reporting_service import (
    build_report_payload,
    render_report_csv,
    render_report_json,
    render_report_pdf,
)
from compliance.loader import compute_compliance_posture
from detections.engine import (
    evaluate_events,
    normalize_aws_cloudtrail_event,
    normalize_azure_activity_event,
)
from packages.auth.dependencies import require_permissions
from packages.auth.rbac import AuthContext, Permission
from packages.common.config import Settings, get_settings
from packages.common.redaction import redact_data
from packages.contracts.domain import (
    DetectionDispositionRequest,
    DetectionEventResponse,
    DetectionIngestRequest,
    RemediationApprovalRequest,
    RemediationExecuteRequest,
    RemediationPreviewRequest,
    RemediationResponse,
)
from packages.db.models import (
    AssessmentResult,
    AssessmentRun,
    CloudConnection,
    DetectionEvent,
    DetectionRule,
    Finding,
    RemediationRequest,
)
from packages.db.session import get_db_session

router = APIRouter(prefix="/api/v1", tags=["detections-compliance-remediation"])


@router.post(
    "/detections/ingest",
    status_code=status.HTTP_201_CREATED,
    summary="Ingest & evaluate cloud events",
)
async def ingest_detection_events(
    payload: DetectionIngestRequest,
    auth: AuthContext = Depends(require_permissions(Permission.DETECTIONS_WRITE)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    try:
        normalized = [
            normalize_aws_cloudtrail_event(ev, data_source=payload.data_source)
            if payload.provider == "aws"
            else normalize_azure_activity_event(ev, data_source=payload.data_source)
            for ev in payload.events
        ]
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    # Verify every event account_ref belongs to a registered CloudConnection in this tenant
    tenant_conns = list(
        (
            await session.execute(
                select(CloudConnection).where(
                    CloudConnection.tenant_id == auth.tenant_id,
                    CloudConnection.provider == payload.provider,
                )
            )
        )
        .scalars()
        .all()
    )
    conn_by_account: dict[str, CloudConnection] = {
        c.account_or_subscription_id: c for c in tenant_conns
    }
    for ev_item in normalized:
        if ev_item.account_ref not in conn_by_account:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Event account_ref '{ev_item.account_ref}' does not belong to any registered "
                    f"{payload.provider} cloud connection in this tenant."
                ),
            )

    triggered = evaluate_events(normalized)

    created_rows: list[DetectionEvent] = []
    duplicates_skipped = 0
    seen_in_batch: set[tuple[str, str]] = set()
    for item in triggered:
        dedup_pair = (item.event.event_id, item.rule.rule_id)
        if dedup_pair in seen_in_batch:
            duplicates_skipped += 1
            continue
        seen_in_batch.add(dedup_pair)

        existing_det = (
            await session.execute(
                select(DetectionEvent).where(
                    DetectionEvent.tenant_id == auth.tenant_id,
                    DetectionEvent.provider == item.event.provider,
                    DetectionEvent.provider_event_id == item.event.event_id,
                    DetectionEvent.rule_id == item.rule.rule_id,
                )
            )
        ).scalar_one_or_none()
        if existing_det is not None:
            duplicates_skipped += 1
            continue

        existing_rule = await session.get(DetectionRule, item.rule.rule_id)
        if existing_rule is None:
            session.add(
                DetectionRule(
                    id=item.rule.rule_id,
                    provider=item.rule.provider,
                    name=item.rule.name,
                    description=item.rule.description,
                    severity=item.rule.severity,
                    confidence=item.rule.confidence,
                    mitre_tactic=item.rule.mitre_tactic,
                    mitre_technique=item.rule.mitre_technique,
                    version=item.rule.version,
                )
            )
            await session.flush()

        # Prevent synthetic connections from spoofing live event provenance
        matched_conn = conn_by_account[item.event.account_ref]
        effective_data_source = (
            "synthetic_fixture"
            if matched_conn.data_source == "synthetic_fixture"
            else item.event.data_source
        )

        row = DetectionEvent(
            tenant_id=auth.tenant_id,
            rule_id=item.rule.rule_id,
            provider_event_id=item.event.event_id,
            provider=item.event.provider,
            account_ref=item.event.account_ref,
            region=item.event.region,
            event_name=item.event.event_name,
            actor_identity=item.event.actor_identity,
            source_ip=item.event.source_ip,
            severity=item.rule.severity,
            confidence=item.rule.confidence,
            mitre_tactic=item.rule.mitre_tactic,
            mitre_technique=item.rule.mitre_technique,
            title=item.rule.name,
            explanation=item.explanation,
            disposition="open",
            correlated_event_ids=item.correlated_event_ids,
            evidence_payload=redact_data(item.evidence_payload),
            data_source=effective_data_source,
            event_time=item.event.event_time,
        )
        session.add(row)
        created_rows.append(row)

    await session.flush()
    await record_audit_event(
        session,
        auth=auth,
        action="detections.ingested",
        resource_type="detection_event",
        resource_id=payload.provider,
        details={
            "events_received": len(payload.events),
            "detections_triggered": len(created_rows),
            "duplicates_skipped": duplicates_skipped,
            "data_source": payload.data_source,
        },
    )
    await session.commit()
    return {
        "events_processed": len(normalized),
        "detections_triggered": len(created_rows),
        "duplicates_skipped": duplicates_skipped,
        "items": [
            DetectionEventResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in created_rows
        ],
    }


@router.get("/detections", summary="List threat detection events")
async def list_detections(
    provider: str | None = Query(default=None, pattern="^(aws|azure)$"),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    disposition: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_permissions(Permission.DETECTIONS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = select(DetectionEvent).where(DetectionEvent.tenant_id == auth.tenant_id)
    count_stmt = select(func.count(DetectionEvent.id)).where(
        DetectionEvent.tenant_id == auth.tenant_id
    )
    if provider:
        stmt = stmt.where(DetectionEvent.provider == provider)
        count_stmt = count_stmt.where(DetectionEvent.provider == provider)
    if severity:
        stmt = stmt.where(DetectionEvent.severity == severity)
        count_stmt = count_stmt.where(DetectionEvent.severity == severity)
    if disposition:
        stmt = stmt.where(DetectionEvent.disposition == disposition)
        count_stmt = count_stmt.where(DetectionEvent.disposition == disposition)

    total = int((await session.execute(count_stmt)).scalar_one())
    rows = list(
        (
            await session.execute(
                stmt.order_by(desc(DetectionEvent.event_time)).limit(limit).offset(offset)
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
            DetectionEventResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in rows
        ],
    }


@router.get("/detections/{detection_id}", response_model=DetectionEventResponse)
async def get_detection(
    detection_id: uuid.UUID,
    auth: AuthContext = Depends(require_permissions(Permission.DETECTIONS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> DetectionEventResponse:
    stmt = select(DetectionEvent).where(
        DetectionEvent.id == detection_id,
        DetectionEvent.tenant_id == auth.tenant_id,
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Detection event not found."
        )
    return DetectionEventResponse.model_validate(row, from_attributes=True)


@router.patch("/detections/{detection_id}", response_model=DetectionEventResponse)
async def update_detection_disposition(
    detection_id: uuid.UUID,
    payload: DetectionDispositionRequest,
    auth: AuthContext = Depends(require_permissions(Permission.DETECTIONS_WRITE)),
    session: AsyncSession = Depends(get_db_session),
) -> DetectionEventResponse:
    stmt = select(DetectionEvent).where(
        DetectionEvent.id == detection_id,
        DetectionEvent.tenant_id == auth.tenant_id,
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Detection event not found."
        )
    row.disposition = payload.disposition
    row.disposition_reason = payload.reason
    await record_audit_event(
        session,
        auth=auth,
        action="detection.disposition_updated",
        resource_type="detection_event",
        resource_id=str(row.id),
        details={"disposition": payload.disposition, "reason": payload.reason},
    )
    await session.commit()
    await session.refresh(row)
    return DetectionEventResponse.model_validate(row, from_attributes=True)


async def _latest_run_results_by_rule(
    session: AsyncSession, tenant_id: uuid.UUID
) -> dict[str, list[str]]:
    """Aggregate AssessmentResult statuses scoped to the latest completed/partial run per connection."""
    runs = list(
        (
            await session.execute(
                select(AssessmentRun)
                .where(
                    AssessmentRun.tenant_id == tenant_id,
                    AssessmentRun.status.in_(("completed", "completed_with_warnings", "partial")),
                )
                .order_by(desc(AssessmentRun.started_at))
            )
        )
        .scalars()
        .all()
    )
    latest_run_ids: list[uuid.UUID] = []
    seen_connections: set[uuid.UUID] = set()
    for r in runs:
        if r.connection_id not in seen_connections:
            seen_connections.add(r.connection_id)
            latest_run_ids.append(r.id)

    if not latest_run_ids:
        return {}

    rows = list(
        (
            await session.execute(
                select(AssessmentResult).where(
                    AssessmentResult.tenant_id == tenant_id,
                    AssessmentResult.assessment_run_id.in_(latest_run_ids),
                )
            )
        )
        .scalars()
        .all()
    )
    results_by_rule: dict[str, list[str]] = {}
    for row in rows:
        results_by_rule.setdefault(row.rule_id, []).append(row.status)
    return results_by_rule


@router.get("/compliance", summary="Compliance framework mappings & posture with limitations")
async def get_compliance_posture(
    framework_id: str | None = None,
    auth: AuthContext = Depends(require_permissions(Permission.COMPLIANCE_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    results_by_rule = await _latest_run_results_by_rule(session, auth.tenant_id)
    posture = compute_compliance_posture(results_by_rule)
    if framework_id:
        posture["frameworks"] = [fw for fw in posture["frameworks"] if fw["id"] == framework_id]
    return posture


@router.get(
    "/reports", summary="Generate JSON, CSV, or PDF security reports with optional redaction"
)
async def export_report(
    report_type: str = Query(
        default="posture",
        pattern="^(posture|assessment|vulnerability|identity|compliance|remediation|threat_detection)$",
    ),
    export_format: str = Query(default="json", alias="format", pattern="^(json|csv|pdf)$"),
    provider: str | None = Query(default=None, pattern="^(aws|azure)$"),
    redact: bool = Query(default=False),
    auth: AuthContext = Depends(require_permissions(Permission.REPORTS_EXPORT)),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    records: list[dict[str, Any]] = []
    if report_type in ("posture", "vulnerability", "identity"):
        q = select(Finding).where(Finding.tenant_id == auth.tenant_id)
        if provider:
            q = q.where(Finding.provider == provider)
        if report_type == "identity":
            q = q.where(Finding.rule_id.like("%-IAM-%"))
        rows = list((await session.execute(q.order_by(desc(Finding.risk_score)))).scalars().all())
        records = [
            {
                "id": str(f.id),
                "rule_id": f.rule_id,
                "provider": f.provider,
                "account_ref": f.account_ref,
                "resource_id": f.resource_id,
                "severity": f.severity,
                "status": f.status,
                "risk_score": f.risk_score,
                "title": f.title,
                "data_source": f.data_source,
            }
            for f in rows
        ]
    elif report_type == "assessment":
        q_runs = select(AssessmentRun).where(AssessmentRun.tenant_id == auth.tenant_id)
        if provider:
            q_runs = q_runs.where(AssessmentRun.provider == provider)
        runs = list(
            (await session.execute(q_runs.order_by(desc(AssessmentRun.started_at)))).scalars().all()
        )
        records = [
            {
                "id": str(r.id),
                "provider": r.provider,
                "status": r.status,
                "assets_discovered": r.assets_discovered,
                "checks_passed": r.checks_passed,
                "checks_failed": r.checks_failed,
                "checks_errored": r.checks_errored,
                "data_source": r.data_source,
                "started_at": r.started_at.isoformat(),
            }
            for r in runs
        ]
    elif report_type == "threat_detection":
        q_det = select(DetectionEvent).where(DetectionEvent.tenant_id == auth.tenant_id)
        if provider:
            q_det = q_det.where(DetectionEvent.provider == provider)
        dets = list(
            (await session.execute(q_det.order_by(desc(DetectionEvent.event_time)))).scalars().all()
        )
        records = [
            {
                "id": str(d.id),
                "rule_id": d.rule_id,
                "provider": d.provider,
                "account_ref": d.account_ref,
                "actor_identity": d.actor_identity,
                "source_ip": d.source_ip,
                "severity": d.severity,
                "mitre_technique": d.mitre_technique,
                "disposition": d.disposition,
                "title": d.title,
            }
            for d in dets
        ]
    elif report_type == "remediation":
        rems = list(
            (
                await session.execute(
                    select(RemediationRequest).where(RemediationRequest.tenant_id == auth.tenant_id)
                )
            )
            .scalars()
            .all()
        )
        records = [
            {
                "id": str(r.id),
                "finding_id": str(r.finding_id),
                "provider": r.provider,
                "resource_id": r.resource_id,
                "action_type": r.action_type,
                "stage": r.stage,
                "execution_mode": r.execution_mode,
            }
            for r in rems
        ]
    elif report_type == "compliance":
        by_rule = await _latest_run_results_by_rule(session, auth.tenant_id)
        posture = compute_compliance_posture(by_rule)
        for fw in posture["frameworks"]:
            for ctrl in fw["controls"]:
                records.append(
                    {
                        "framework": fw["name"],
                        "version": fw["version"],
                        "control_id": ctrl["control_id"],
                        "status": ctrl["status"],
                        "title": ctrl["title"],
                        "limitations": ctrl["limitations"],
                    }
                )

    payload = build_report_payload(
        report_type=report_type,
        provider_scope=provider or "aws+azure",
        tenant_id=str(auth.tenant_id),
        records=records,
        collection_status="collected" if records else "no_records",
        redact_external=redact,
    )

    await record_audit_event(
        session,
        auth=auth,
        action="report.exported",
        resource_type="report",
        resource_id=report_type,
        details={"format": export_format, "redacted": redact, "record_count": len(records)},
    )
    await session.commit()

    if export_format == "csv":
        return Response(
            content=render_report_csv(payload),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="cloudsentinel-{report_type}.csv"'
            },
        )
    if export_format == "pdf":
        return Response(
            content=render_report_pdf(payload),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="cloudsentinel-{report_type}.pdf"'
            },
        )
    return Response(content=render_report_json(payload), media_type="application/json")


@router.get("/remediations", summary="List remediation requests")
async def list_remediations(
    auth: AuthContext = Depends(require_permissions(Permission.FINDINGS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    rows = list(
        (
            await session.execute(
                select(RemediationRequest)
                .where(RemediationRequest.tenant_id == auth.tenant_id)
                .order_by(desc(RemediationRequest.created_at))
            )
        )
        .scalars()
        .all()
    )
    return {
        "total": len(rows),
        "items": [
            RemediationResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in rows
        ],
    }


@router.post(
    "/remediations/preview", status_code=status.HTTP_201_CREATED, response_model=RemediationResponse
)
async def preview_remediation_endpoint(
    payload: RemediationPreviewRequest,
    auth: AuthContext = Depends(require_permissions(Permission.REMEDIATIONS_PREVIEW)),
    session: AsyncSession = Depends(get_db_session),
) -> RemediationResponse:
    finding = (
        await session.execute(
            select(Finding).where(
                Finding.id == payload.finding_id, Finding.tenant_id == auth.tenant_id
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    try:
        req = await preview_remediation(
            session,
            auth=auth,
            finding=finding,
            idempotency_key=payload.idempotency_key,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return RemediationResponse.model_validate(req, from_attributes=True)


@router.post("/remediations/{remediation_id}/approve", response_model=RemediationResponse)
async def approve_remediation_endpoint(
    remediation_id: uuid.UUID,
    payload: RemediationApprovalRequest,
    auth: AuthContext = Depends(require_permissions(Permission.REMEDIATIONS_APPROVE)),
    session: AsyncSession = Depends(get_db_session),
) -> RemediationResponse:
    remediation = (
        await session.execute(
            select(RemediationRequest).where(
                RemediationRequest.id == remediation_id,
                RemediationRequest.tenant_id == auth.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if remediation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Remediation request not found."
        )
    try:
        updated = await approve_remediation(
            session,
            auth=auth,
            remediation=remediation,
            decision=payload.decision,
            comment=payload.comment,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return RemediationResponse.model_validate(updated, from_attributes=True)


@router.post("/remediations/{remediation_id}/cancel", response_model=RemediationResponse)
async def cancel_remediation_endpoint(
    remediation_id: uuid.UUID,
    auth: AuthContext = Depends(require_permissions(Permission.REMEDIATIONS_PREVIEW)),
    session: AsyncSession = Depends(get_db_session),
) -> RemediationResponse:
    remediation = (
        await session.execute(
            select(RemediationRequest).where(
                RemediationRequest.id == remediation_id,
                RemediationRequest.tenant_id == auth.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if remediation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Remediation request not found."
        )
    try:
        updated = await cancel_remediation(
            session,
            auth=auth,
            remediation=remediation,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return RemediationResponse.model_validate(updated, from_attributes=True)


@router.post("/remediations/{remediation_id}/execute", response_model=RemediationResponse)
async def execute_remediation_endpoint(
    remediation_id: uuid.UUID,
    payload: RemediationExecuteRequest,
    request: Request,
    auth: AuthContext = Depends(require_permissions(Permission.REMEDIATIONS_EXECUTE)),
    session: AsyncSession = Depends(get_db_session),
) -> RemediationResponse:
    remediation = (
        await session.execute(
            select(RemediationRequest).where(
                RemediationRequest.id == remediation_id,
                RemediationRequest.tenant_id == auth.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if remediation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Remediation request not found."
        )
    finding = (
        await session.execute(
            select(Finding).where(
                Finding.id == remediation.finding_id, Finding.tenant_id == auth.tenant_id
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Associated finding not found."
        )

    settings: Settings = getattr(request.app.state, "settings", get_settings())
    provider_executor = getattr(request.app.state, "remediation_provider_executor", None)
    posture_verifier = getattr(request.app.state, "remediation_posture_verifier", None)
    try:
        updated = await execute_remediation(
            session,
            auth=auth,
            settings=settings,
            remediation=remediation,
            finding=finding,
            confirm_live=payload.confirm_live,
            idempotency_key=payload.idempotency_key,
            provider_executor=provider_executor,
            posture_verifier=posture_verifier,
        )
    except UnsupportedRemediationOperationError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return RemediationResponse.model_validate(updated, from_attributes=True)
