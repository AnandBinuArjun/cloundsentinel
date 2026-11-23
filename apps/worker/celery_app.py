"""Celery worker application configuration and tenant-scoped tasks."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from celery import Celery

from packages.common.config import get_settings
from packages.common.logging import configure_logging

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


@celery_app.task(name="cloudsentinel.assessments.dispatch")  # type: ignore[misc]
def dispatch_assessment(tenant_id: str, connection_id: str, triggered_by: str) -> dict[str, Any]:
    """Tenant-scoped worker entry point validating mandatory tenant context before execution."""
    if not tenant_id or not connection_id:
        raise ValueError("Worker task requires explicit verified tenant_id and connection_id.")
    return {
        "status": "accepted",
        "tenant_id": tenant_id,
        "connection_id": connection_id,
        "triggered_by": triggered_by,
        "accepted_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
