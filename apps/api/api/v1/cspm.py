"""Cloud connections, assets, assessments, findings, and identity analysis endpoints."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.services.assessment_service import (
    build_connector,
    cancel_assessment_run,
    enqueue_assessment_run,
    execute_queued_assessment_run,
    validate_cloud_connection,
)
from apps.api.services.audit import record_audit_event
from packages.auth.dependencies import require_permissions
from packages.auth.rbac import AuthContext, Permission
from packages.contracts.domain import (
    AssessmentResultResponse,
    AssessmentRunResponse,
    AssessmentTriggerRequest,
    AssetResponse,
    ConnectionCreateRequest,
    ConnectionResponse,
    FindingResponse,
    FindingUpdateRequest,
)
from packages.db.models import (
    AssessmentResult,
    AssessmentRun,
    Asset,
    CloudConnection,
    Evidence,
    Finding,
    FindingHistory,
)
from packages.db.session import get_db_session

router = APIRouter(prefix="/api/v1", tags=["cspm"])


@router.get("/connections", summary="List tenant cloud connectors")
async def list_connections(
    provider: str | None = Query(default=None, pattern="^(aws|azure)$"),
    auth: AuthContext = Depends(require_permissions(Permission.CONNECTIONS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = select(CloudConnection).where(CloudConnection.tenant_id == auth.tenant_id)
    if provider:
        stmt = stmt.where(CloudConnection.provider == provider)
    rows = list(
        (await session.execute(stmt.order_by(desc(CloudConnection.created_at)))).scalars().all()
    )
    return {
        "total": len(rows),
        "items": [
            ConnectionResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in rows
        ],
    }


@router.post(
    "/connections", status_code=status.HTTP_201_CREATED, summary="Create AWS or Azure connector"
)
async def create_connection(
    payload: ConnectionCreateRequest,
    auth: AuthContext = Depends(require_permissions(Permission.CONNECTIONS_WRITE)),
    session: AsyncSession = Depends(get_db_session),
) -> ConnectionResponse:
    conn = CloudConnection(
        tenant_id=auth.tenant_id,
        name=payload.name,
        provider=payload.provider,
        auth_mode=payload.auth_mode,
        account_or_subscription_id=payload.account_or_subscription_id,
        role_arn=payload.role_arn,
        external_id=payload.external_id,
        azure_tenant_id=payload.azure_tenant_id,
        azure_client_id=payload.azure_client_id,
        secret_ref=payload.secret_ref,
        regions=payload.regions,
        data_source=payload.data_source,
        status="pending_validation",
    )
    session.add(conn)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A connection with this name already exists in the tenant.",
        ) from exc

    await record_audit_event(
        session,
        auth=auth,
        action="connection.created",
        resource_type="cloud_connection",
        resource_id=str(conn.id),
        details={
            "provider": conn.provider,
            "auth_mode": conn.auth_mode,
            "data_source": conn.data_source,
        },
    )
    await session.commit()
    await session.refresh(conn)
    return ConnectionResponse.model_validate(conn, from_attributes=True)


@router.post(
    "/connections/{connection_id}/validate", summary="Validate connector identity & permissions"
)
async def validate_connection_endpoint(
    connection_id: uuid.UUID,
    auth: AuthContext = Depends(require_permissions(Permission.CONNECTIONS_WRITE)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = select(CloudConnection).where(
        CloudConnection.id == connection_id,
        CloudConnection.tenant_id == auth.tenant_id,
    )
    conn = (await session.execute(stmt)).scalar_one_or_none()
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found.")

    preflight = await validate_cloud_connection(session, auth=auth, connection=conn)
    return {
        "connection_id": str(conn.id),
        "valid": preflight.valid,
        "provider": preflight.provider,
        "account_or_subscription_id": preflight.account_or_subscription_id,
        "identity": preflight.identity_arn_or_principal,
        "auth_mode": preflight.auth_mode,
        "data_source": preflight.data_source,
        "checked_permissions": preflight.checked_permissions,
        "errors": preflight.errors,
        "validated_at": preflight.validated_at.isoformat(),
    }


@router.get("/assets", summary="List discovered cloud assets with filtering & pagination")
async def list_assets(
    provider: str | None = Query(default=None, pattern="^(aws|azure)$"),
    resource_type: str | None = None,
    region: str | None = None,
    search: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_permissions(Permission.ASSETS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = select(Asset).where(Asset.tenant_id == auth.tenant_id)
    count_stmt = select(func.count(Asset.id)).where(Asset.tenant_id == auth.tenant_id)

    if provider:
        stmt = stmt.where(Asset.provider == provider)
        count_stmt = count_stmt.where(Asset.provider == provider)
    if resource_type:
        stmt = stmt.where(Asset.resource_type == resource_type)
        count_stmt = count_stmt.where(Asset.resource_type == resource_type)
    if region:
        stmt = stmt.where(Asset.region == region)
        count_stmt = count_stmt.where(Asset.region == region)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(Asset.resource_name.ilike(pattern) | Asset.resource_id.ilike(pattern))
        count_stmt = count_stmt.where(
            Asset.resource_name.ilike(pattern) | Asset.resource_id.ilike(pattern)
        )

    total = int((await session.execute(count_stmt)).scalar_one())
    rows = list(
        (
            await session.execute(
                stmt.order_by(desc(Asset.last_observed_at)).limit(limit).offset(offset)
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
            AssetResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in rows
        ],
    }


@router.get("/assets/{asset_id}", response_model=AssetResponse, summary="Get asset detail")
async def get_asset(
    asset_id: uuid.UUID,
    auth: AuthContext = Depends(require_permissions(Permission.ASSETS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> AssetResponse:
    stmt = select(Asset).where(Asset.id == asset_id, Asset.tenant_id == auth.tenant_id)
    asset = (await session.execute(stmt)).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    return AssetResponse.model_validate(asset, from_attributes=True)


@router.post(
    "/assessments", status_code=status.HTTP_202_ACCEPTED, response_model=AssessmentRunResponse
)
async def trigger_assessment(
    payload: AssessmentTriggerRequest,
    request: Request,
    queue_only: bool = Query(default=False, description="Queue assessment without eager execution"),
    auth: AuthContext = Depends(require_permissions(Permission.ASSESSMENTS_RUN)),
    session: AsyncSession = Depends(get_db_session),
) -> AssessmentRunResponse:
    stmt = select(CloudConnection).where(
        CloudConnection.id == payload.connection_id,
        CloudConnection.tenant_id == auth.tenant_id,
    )
    conn = (await session.execute(stmt)).scalar_one_or_none()
    if conn is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found.")

    try:
        run, newly_created = await enqueue_assessment_run(
            session,
            auth=auth,
            connection=conn,
            idempotency_key=payload.idempotency_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    async_queue_mode = (
        bool(getattr(request.app.state, "assessment_queue_only", False)) or queue_only
    )
    if newly_created and not async_queue_mode:
        run = await execute_queued_assessment_run(
            session,
            auth=auth,
            run=run,
            connection=conn,
        )
    return AssessmentRunResponse.model_validate(run, from_attributes=True)


@router.get(
    "/assessments/{assessment_id}/results",
    summary="List individual check evaluation results for an assessment run",
)
async def get_assessment_results(
    assessment_id: uuid.UUID,
    auth: AuthContext = Depends(require_permissions(Permission.ASSESSMENTS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    run_stmt = select(AssessmentRun).where(
        AssessmentRun.id == assessment_id,
        AssessmentRun.tenant_id == auth.tenant_id,
    )
    run = (await session.execute(run_stmt)).scalar_one_or_none()
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Assessment run not found."
        )

    rows = list(
        (
            await session.execute(
                select(AssessmentResult)
                .where(
                    AssessmentResult.assessment_run_id == run.id,
                    AssessmentResult.tenant_id == auth.tenant_id,
                )
                .order_by(AssessmentResult.rule_id, AssessmentResult.resource_id)
            )
        )
        .scalars()
        .all()
    )
    return {
        "assessment_run_id": str(run.id),
        "status": run.status,
        "total": len(rows),
        "items": [
            AssessmentResultResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in rows
        ],
    }


@router.post(
    "/assessments/{assessment_id}/cancel",
    response_model=AssessmentRunResponse,
    summary="Cancel a queued or running assessment run",
)
async def cancel_assessment_endpoint(
    assessment_id: uuid.UUID,
    auth: AuthContext = Depends(require_permissions(Permission.ASSESSMENTS_RUN)),
    session: AsyncSession = Depends(get_db_session),
) -> AssessmentRunResponse:
    run_stmt = select(AssessmentRun).where(
        AssessmentRun.id == assessment_id,
        AssessmentRun.tenant_id == auth.tenant_id,
    )
    run = (await session.execute(run_stmt)).scalar_one_or_none()
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Assessment run not found."
        )
    try:
        cancelled = await cancel_assessment_run(session, auth=auth, run=run)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return AssessmentRunResponse.model_validate(cancelled, from_attributes=True)


@router.get("/assessments", summary="List assessment runs")
async def list_assessments(
    provider: str | None = Query(default=None, pattern="^(aws|azure)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_permissions(Permission.ASSESSMENTS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = select(AssessmentRun).where(AssessmentRun.tenant_id == auth.tenant_id)
    count_stmt = select(func.count(AssessmentRun.id)).where(
        AssessmentRun.tenant_id == auth.tenant_id
    )
    if provider:
        stmt = stmt.where(AssessmentRun.provider == provider)
        count_stmt = count_stmt.where(AssessmentRun.provider == provider)
    total = int((await session.execute(count_stmt)).scalar_one())
    rows = list(
        (
            await session.execute(
                stmt.order_by(desc(AssessmentRun.started_at)).limit(limit).offset(offset)
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
            AssessmentRunResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in rows
        ],
    }


@router.get("/assessments/{assessment_id}", response_model=AssessmentRunResponse)
async def get_assessment(
    assessment_id: uuid.UUID,
    auth: AuthContext = Depends(require_permissions(Permission.ASSESSMENTS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> AssessmentRunResponse:
    stmt = select(AssessmentRun).where(
        AssessmentRun.id == assessment_id,
        AssessmentRun.tenant_id == auth.tenant_id,
    )
    run = (await session.execute(stmt)).scalar_one_or_none()
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Assessment run not found."
        )
    return AssessmentRunResponse.model_validate(run, from_attributes=True)


@router.get("/findings", summary="List risk-ranked security findings with filtering & pagination")
async def list_findings(
    provider: str | None = Query(default=None, pattern="^(aws|azure)$"),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    finding_status: str | None = Query(
        default=None, alias="status", pattern="^(open|resolved|risk_accepted|false_positive)$"
    ),
    region: str | None = None,
    search: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_permissions(Permission.FINDINGS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = select(Finding).where(Finding.tenant_id == auth.tenant_id)
    count_stmt = select(func.count(Finding.id)).where(Finding.tenant_id == auth.tenant_id)

    if provider:
        stmt = stmt.where(Finding.provider == provider)
        count_stmt = count_stmt.where(Finding.provider == provider)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
        count_stmt = count_stmt.where(Finding.severity == severity)
    if finding_status:
        stmt = stmt.where(Finding.status == finding_status)
        count_stmt = count_stmt.where(Finding.status == finding_status)
    if region:
        stmt = stmt.where(Finding.region == region)
        count_stmt = count_stmt.where(Finding.region == region)
    if search:
        pattern = f"%{search}%"
        stmt = stmt.where(
            Finding.title.ilike(pattern)
            | Finding.rule_id.ilike(pattern)
            | Finding.resource_id.ilike(pattern)
        )
        count_stmt = count_stmt.where(
            Finding.title.ilike(pattern)
            | Finding.rule_id.ilike(pattern)
            | Finding.resource_id.ilike(pattern)
        )

    total = int((await session.execute(count_stmt)).scalar_one())
    rows = list(
        (
            await session.execute(
                stmt.order_by(desc(Finding.risk_score), desc(Finding.last_seen_at))
                .limit(limit)
                .offset(offset)
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
            FindingResponse.model_validate(r, from_attributes=True).model_dump(mode="json")
            for r in rows
        ],
    }


@router.get(
    "/findings/{finding_id}",
    summary="Get finding detail, evidence snapshots, and lifecycle history",
)
async def get_finding_detail(
    finding_id: uuid.UUID,
    auth: AuthContext = Depends(require_permissions(Permission.FINDINGS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = select(Finding).where(Finding.id == finding_id, Finding.tenant_id == auth.tenant_id)
    finding = (await session.execute(stmt)).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    ev_rows = list(
        (
            await session.execute(
                select(Evidence)
                .where(Evidence.finding_id == finding.id, Evidence.tenant_id == auth.tenant_id)
                .order_by(desc(Evidence.collected_at))
                .limit(10)
            )
        )
        .scalars()
        .all()
    )
    hist_rows = list(
        (
            await session.execute(
                select(FindingHistory)
                .where(
                    FindingHistory.finding_id == finding.id,
                    FindingHistory.tenant_id == auth.tenant_id,
                )
                .order_by(desc(FindingHistory.created_at))
                .limit(20)
            )
        )
        .scalars()
        .all()
    )

    return {
        "finding": FindingResponse.model_validate(finding, from_attributes=True).model_dump(
            mode="json"
        ),
        "evidence": [
            {
                "id": str(e.id),
                "source": e.source,
                "expected_config": e.expected_config,
                "observed_config": e.observed_config,
                "raw_evidence_redacted": e.raw_evidence_redacted,
                "collected_at": e.collected_at.isoformat(),
            }
            for e in ev_rows
        ],
        "history": [
            {
                "id": str(h.id),
                "actor_user_id": str(h.actor_user_id) if h.actor_user_id else None,
                "previous_status": h.previous_status,
                "new_status": h.new_status,
                "justification": h.justification,
                "created_at": h.created_at.isoformat(),
            }
            for h in hist_rows
        ],
    }


@router.patch(
    "/findings/{finding_id}",
    response_model=FindingResponse,
    summary="Update finding disposition / risk acceptance",
)
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdateRequest,
    auth: AuthContext = Depends(require_permissions(Permission.FINDINGS_WRITE)),
    session: AsyncSession = Depends(get_db_session),
) -> FindingResponse:
    stmt = select(Finding).where(Finding.id == finding_id, Finding.tenant_id == auth.tenant_id)
    finding = (await session.execute(stmt)).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    previous_status = finding.status
    finding.status = payload.status
    session.add(
        FindingHistory(
            tenant_id=auth.tenant_id,
            finding_id=finding.id,
            actor_user_id=auth.user_id,
            previous_status=previous_status,
            new_status=payload.status,
            justification=payload.justification,
        )
    )
    await record_audit_event(
        session,
        auth=auth,
        action="finding.status_updated",
        resource_type="finding",
        resource_id=str(finding.id),
        details={
            "previous_status": previous_status,
            "new_status": payload.status,
            "justification": payload.justification,
        },
    )
    await session.commit()
    await session.refresh(finding)
    return FindingResponse.model_validate(finding, from_attributes=True)


@router.get(
    "/identity/analysis",
    summary="Run IAM & Azure RBAC identity posture analysis with explicit limitations",
)
async def get_identity_analysis(
    auth: AuthContext = Depends(require_permissions(Permission.FINDINGS_READ)),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    conns = list(
        (
            await session.execute(
                select(CloudConnection).where(CloudConnection.tenant_id == auth.tenant_id)
            )
        )
        .scalars()
        .all()
    )
    reports = []
    for conn in conns:
        connector = build_connector(conn)
        report = await asyncio.to_thread(connector.analyze_identities)
        reports.append(
            {
                "connection_id": str(conn.id),
                "connection_name": conn.name,
                "provider": report.provider,
                "account_ref": report.account_ref,
                "data_source": report.data_source,
                "principals_reviewed": report.principals_reviewed,
                "findings": [
                    {
                        "principal_id": f.principal_id,
                        "principal_type": f.principal_type,
                        "risk_category": f.risk_category,
                        "severity": f.severity.value,
                        "evidence": f.evidence,
                        "recommendation": f.recommendation,
                    }
                    for f in report.findings
                ],
                "limitations": report.limitations,
                "generated_at": report.generated_at.isoformat(),
            }
        )
    return {"reports": reports}
