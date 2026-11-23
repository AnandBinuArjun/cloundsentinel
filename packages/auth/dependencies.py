"""FastAPI authentication, tenant resolution, and RBAC dependencies."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from packages.auth.oidc import AuthenticationError, OIDCVerifier
from packages.auth.rbac import AuthContext, Permission, Role
from packages.common.config import Settings, get_settings
from packages.db.models import Membership, Tenant, User
from packages.db.session import get_db_session, set_postgres_tenant_context


async def get_auth_context(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> AuthContext:
    """Authenticate Bearer JWT and resolve verified tenant membership from PostgreSQL.

    SECURITY: `tenant_id` is derived exclusively from the verified token claim and validated
    against the persisted `memberships` table. Client query/body tenant IDs are never trusted.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raw_token = auth_header[len("Bearer ") :].strip()
    settings: Settings = getattr(request.app.state, "settings", get_settings())
    verifier: OIDCVerifier = getattr(request.app.state, "oidc_verifier", OIDCVerifier(settings))

    try:
        claims = verifier.verify_token(raw_token)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    stmt = (
        select(User, Membership, Tenant)
        .join(Membership, Membership.user_id == User.id)
        .join(Tenant, Tenant.id == Membership.tenant_id)
        .where(
            User.oidc_issuer == claims.issuer,
            User.oidc_subject == claims.subject,
            User.is_active.is_(True),
            Tenant.id == claims.tenant_id,
            Tenant.is_active.is_(True),
        )
    )
    row = (await session.execute(stmt)).first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User has no active membership for the requested tenant.",
        )

    user, membership, tenant = row
    try:
        role = Role(membership.role)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Assigned role is invalid.",
        ) from exc

    await set_postgres_tenant_context(session, tenant.id)
    request_id = str(getattr(request.state, "request_id", "unknown"))
    return AuthContext(
        user_id=user.id,
        tenant_id=tenant.id,
        role=role,
        email=user.email,
        subject=user.oidc_subject,
        request_id=request_id,
    )


def require_permissions(*required: Permission) -> Callable[[AuthContext], AuthContext]:
    """FastAPI dependency enforcing RBAC permissions at the API boundary."""

    def _checker(auth: AuthContext = Depends(get_auth_context)) -> AuthContext:
        for perm in required:
            if not auth.has_permission(perm):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions: '{perm.value}' required.",
                )
        return auth

    return _checker
