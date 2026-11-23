"""Role-Based Access Control (RBAC) definitions enforced at API and service layers."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    PLATFORM_ADMIN = "platform_admin"
    TENANT_ADMIN = "tenant_admin"
    SECURITY_ANALYST = "security_analyst"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


class Permission(StrEnum):
    CONNECTIONS_READ = "connections:read"
    CONNECTIONS_WRITE = "connections:write"
    ASSETS_READ = "assets:read"
    ASSESSMENTS_READ = "assessments:read"
    ASSESSMENTS_RUN = "assessments:run"
    FINDINGS_READ = "findings:read"
    FINDINGS_WRITE = "findings:write"
    DETECTIONS_READ = "detections:read"
    DETECTIONS_WRITE = "detections:write"
    COMPLIANCE_READ = "compliance:read"
    REPORTS_EXPORT = "reports:export"
    REMEDIATIONS_PREVIEW = "remediations:preview"
    REMEDIATIONS_APPROVE = "remediations:approve"
    REMEDIATIONS_EXECUTE = "remediations:execute"
    AUDIT_READ = "audit:read"
    TENANTS_ADMIN = "tenants:admin"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.PLATFORM_ADMIN: frozenset(Permission),
    Role.TENANT_ADMIN: frozenset(
        {
            Permission.CONNECTIONS_READ,
            Permission.CONNECTIONS_WRITE,
            Permission.ASSETS_READ,
            Permission.ASSESSMENTS_READ,
            Permission.ASSESSMENTS_RUN,
            Permission.FINDINGS_READ,
            Permission.FINDINGS_WRITE,
            Permission.DETECTIONS_READ,
            Permission.DETECTIONS_WRITE,
            Permission.COMPLIANCE_READ,
            Permission.REPORTS_EXPORT,
            Permission.REMEDIATIONS_PREVIEW,
            Permission.REMEDIATIONS_APPROVE,
            Permission.REMEDIATIONS_EXECUTE,
            Permission.AUDIT_READ,
        }
    ),
    Role.SECURITY_ANALYST: frozenset(
        {
            Permission.CONNECTIONS_READ,
            Permission.ASSETS_READ,
            Permission.ASSESSMENTS_READ,
            Permission.ASSESSMENTS_RUN,
            Permission.FINDINGS_READ,
            Permission.FINDINGS_WRITE,
            Permission.DETECTIONS_READ,
            Permission.DETECTIONS_WRITE,
            Permission.COMPLIANCE_READ,
            Permission.REPORTS_EXPORT,
            Permission.REMEDIATIONS_PREVIEW,
        }
    ),
    Role.AUDITOR: frozenset(
        {
            Permission.CONNECTIONS_READ,
            Permission.ASSETS_READ,
            Permission.ASSESSMENTS_READ,
            Permission.FINDINGS_READ,
            Permission.DETECTIONS_READ,
            Permission.COMPLIANCE_READ,
            Permission.REPORTS_EXPORT,
            Permission.AUDIT_READ,
        }
    ),
    Role.READ_ONLY: frozenset(
        {
            Permission.CONNECTIONS_READ,
            Permission.ASSETS_READ,
            Permission.ASSESSMENTS_READ,
            Permission.FINDINGS_READ,
            Permission.DETECTIONS_READ,
            Permission.COMPLIANCE_READ,
        }
    ),
}


class AuthorizationError(PermissionError):
    """Raised when an authenticated actor lacks required RBAC permissions."""


@dataclass(frozen=True)
class AuthContext:
    """Verified authentication and tenant-isolation context derived strictly server-side."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: Role
    email: str
    subject: str
    request_id: str

    @property
    def permissions(self) -> frozenset[Permission]:
        return ROLE_PERMISSIONS[self.role]

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require_permission(self, permission: Permission) -> None:
        """Service-layer authorization check."""
        if not self.has_permission(permission):
            raise AuthorizationError(
                f"Role '{self.role.value}' lacks required permission '{permission.value}'."
            )
