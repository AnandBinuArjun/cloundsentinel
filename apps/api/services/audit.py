"""Immutable tenant-scoped audit logging service."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from packages.auth.rbac import AuthContext
from packages.common.redaction import redact_data
from packages.db.models import AuditEvent


async def record_audit_event(
    session: AsyncSession,
    *,
    auth: AuthContext,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append a redacted, immutable audit record for a security-relevant operation."""
    event = AuditEvent(
        tenant_id=auth.tenant_id,
        actor_user_id=auth.user_id,
        actor_role=auth.role.value,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=auth.request_id,
        details=redact_data(details or {}),
    )
    session.add(event)
    await session.flush()
    return event
