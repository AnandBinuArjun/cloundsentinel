"""Celery worker application configuration and tenant-scoped tasks."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from celery import Celery
from sqlalchemy import select

from apps.api.services.assessment_service import execute_queued_assessment_run
from packages.auth.rbac import AuthContext, Role
from packages.common.config import get_settings
from packages.common.logging import configure_logging
from packages.db.models import AssessmentRun, CloudConnection
from packages.db.session import (
    create_db_engine,
    create_session_factory,
    reset_postgres_tenant_context,
    set_postgres_tenant_context,
)

settings = get_settings()
configure_logging(settings.log_level)

celery_app = Celery(
    "cloudsentinel_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=300,
    task_soft_time_limit=240,
)


@celery_app.task(name="cloudsentinel.system.ping")  # type: ignore[misc]
def ping() -> dict[str, str]:
    """Verify worker task execution health."""
    return {
        "status": "pong",
        "service": "cloudsentinel-worker",
        "version": settings.version,
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


async def _run_worker_assessment_async(
    *,
    tenant_id_str: str,
    connection_id_str: str,
    triggered_by_str: str,
    assessment_run_id_str: str | None = None,
) -> dict[str, Any]:
    """Execute a queued assessment run inside an RLS-bound database session."""
    tenant_uuid = uuid.UUID(tenant_id_str)
    connection_uuid = uuid.UUID(connection_id_str)
    user_uuid = uuid.UUID(triggered_by_str) if triggered_by_str else uuid.UUID(int=0)

    engine = create_db_engine(settings.database_url)
    factory = create_session_factory(engine)
    try:
        async with factory() as session:
            await reset_postgres_tenant_context(session)
            try:
                await set_postgres_tenant_context(session, tenant_uuid)

                conn = (
                    await session.execute(
                        select(CloudConnection).where(
                            CloudConnection.id == connection_uuid,
                            CloudConnection.tenant_id == tenant_uuid,
                        )
                    )
                ).scalar_one_or_none()
                if conn is None:
                    raise PermissionError(
                        f"CloudConnection {connection_id_str} not found or does not belong to tenant {tenant_id_str}."
                    )

                run: AssessmentRun | None = None
                if assessment_run_id_str:
                    run_uuid = uuid.UUID(assessment_run_id_str)
                    run = (
                        await session.execute(
                            select(AssessmentRun).where(
                                AssessmentRun.id == run_uuid,
                                AssessmentRun.tenant_id == tenant_uuid,
                                AssessmentRun.connection_id == connection_uuid,
                            )
                        )
                    ).scalar_one_or_none()
                    if run is None:
                        raise PermissionError(
                            f"AssessmentRun {assessment_run_id_str} not found in tenant {tenant_id_str}."
                        )
                else:
                    run = (
                        await session.execute(
                            select(AssessmentRun)
                            .where(
                                AssessmentRun.tenant_id == tenant_uuid,
                                AssessmentRun.connection_id == connection_uuid,
                                AssessmentRun.status == "queued",
                            )
                            .order_by(AssessmentRun.queued_at.desc())
                        )
                    ).scalar_one_or_none()

                if run is None:
                    return {
                        "status": "accepted",
                        "tenant_id": tenant_id_str,
                        "connection_id": connection_id_str,
                        "triggered_by": triggered_by_str,
                        "accepted_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    }

                worker_auth = AuthContext(
                    user_id=user_uuid,
                    tenant_id=tenant_uuid,
                    role=Role.SECURITY_ANALYST,
                    email="worker@cloudsentinel.internal",
                    subject="cloudsentinel-worker",
                    request_id=run.job_id or f"worker-{run.id}",
                )
                completed_run = await execute_queued_assessment_run(
                    session,
                    auth=worker_auth,
                    run=run,
                    connection=conn,
                )
                return {
                    "status": completed_run.status,
                    "assessment_run_id": str(completed_run.id),
                    "job_id": completed_run.job_id,
                    "tenant_id": tenant_id_str,
                    "connection_id": connection_id_str,
                    "triggered_by": triggered_by_str,
                    "assets_discovered": completed_run.assets_discovered,
                    "checks_passed": completed_run.checks_passed,
                    "checks_failed": completed_run.checks_failed,
                    "completed_at": (
                        completed_run.completed_at.isoformat().replace("+00:00", "Z")
                        if completed_run.completed_at
                        else None
                    ),
                }
            finally:
                await reset_postgres_tenant_context(session)
    finally:
        await engine.dispose()


@celery_app.task(
    name="cloudsentinel.assessments.dispatch",
    bind=True,
    max_retries=3,
    retry_backoff=True,
    retry_backoff_max=60,
    retry_jitter=True,
)  # type: ignore[misc]
def dispatch_assessment(
    self: Any,
    tenant_id: str,
    connection_id: str,
    triggered_by: str,
    assessment_run_id: str | None = None,
) -> dict[str, Any]:
    """Tenant-scoped worker entry point validating mandatory tenant context before execution."""
    if not tenant_id or not connection_id:
        raise ValueError("Worker task requires explicit verified tenant_id and connection_id.")

    if not assessment_run_id:
        return {
            "status": "accepted",
            "tenant_id": tenant_id,
            "connection_id": connection_id,
            "triggered_by": triggered_by,
            "accepted_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }

    return asyncio.run(
        _run_worker_assessment_async(
            tenant_id_str=tenant_id,
            connection_id_str=connection_id,
            triggered_by_str=triggered_by,
            assessment_run_id_str=assessment_run_id,
        )
    )
