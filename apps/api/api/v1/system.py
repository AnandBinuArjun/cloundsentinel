"""System metadata and OIDC PKCE / BFF session endpoints under /api/v1."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from packages.auth.dependencies import get_auth_context
from packages.auth.oidc import (
    SESSION_COOKIE_NAME,
    AuthenticationError,
    OIDCVerifier,
)
from packages.auth.rbac import AuthContext
from packages.common.config import Settings, get_settings
from packages.contracts.system import SystemCapabilities, SystemInfoResponse
from packages.db.models import Membership, Tenant, User
from packages.db.session import get_db_session, set_postgres_tenant_context

router = APIRouter(prefix="/api/v1", tags=["system"])


class OIDCAuthorizeRequest(BaseModel):
    redirect_uri: str = Field(min_length=8, max_length=512)
    client_id: str = Field(default="cloudsentinel-console", min_length=2, max_length=128)
    code_challenge: str | None = Field(default=None, max_length=256)


class OIDCCallbackRequest(BaseModel):
    state: str = Field(min_length=8, max_length=256)
    code_verifier: str = Field(min_length=16, max_length=256)
    redirect_uri: str = Field(min_length=8, max_length=512)
    id_token: str = Field(min_length=16)


@router.get(
    "/system/info",
    response_model=SystemInfoResponse,
    summary="Return implemented platform capability metadata",
)
async def get_system_info(request: Request) -> SystemInfoResponse:
    """Return non-sensitive runtime status and implemented milestone flags."""
    settings: Settings = getattr(request.app.state, "settings", get_settings())
    return SystemInfoResponse(
        version=settings.version,
        environment=settings.env,
        current_milestone="M9 — Full Platform Foundation (v1.0)",
        default_mode="read_only",
        capabilities=SystemCapabilities(
            health_probes=True,
            oidc_auth=True,
            aws_connector=True,
            azure_connector=True,
            assessment_engine=True,
            threat_detection=True,
            compliance_mapping=True,
            remediation_engine=True,
        ),
    )


@router.post("/auth/oidc/authorize", summary="Initiate OIDC Authorization Code Flow with PKCE")
async def oidc_authorize(
    payload: OIDCAuthorizeRequest,
    request: Request,
) -> dict[str, str]:
    settings: Settings = getattr(request.app.state, "settings", get_settings())
    verifier: OIDCVerifier = getattr(request.app.state, "oidc_verifier", OIDCVerifier(settings))
    try:
        req = verifier.create_pkce_authorization_request(
            redirect_uri=payload.redirect_uri,
            client_id=payload.client_id,
            code_challenge=payload.code_challenge,
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "authorize_url": req.authorize_url,
        "state": req.state,
        "nonce": req.nonce,
        "code_challenge": req.code_challenge,
        "code_challenge_method": req.code_challenge_method,
    }


@router.post(
    "/auth/oidc/callback",
    summary="Complete OIDC PKCE callback and issue HttpOnly BFF session cookie",
)
async def oidc_callback(
    payload: OIDCCallbackRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    settings: Settings = getattr(request.app.state, "settings", get_settings())
    verifier: OIDCVerifier = getattr(request.app.state, "oidc_verifier", OIDCVerifier(settings))
    try:
        claims = verifier.consume_pkce_callback(
            state=payload.state,
            code_verifier=payload.code_verifier,
            redirect_uri=payload.redirect_uri,
            id_token=payload.id_token,
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    await set_postgres_tenant_context(session, claims.tenant_id)
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
    cookie_val, csrf_token = verifier.issue_bff_session_cookie(claims)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=cookie_val,
        httponly=True,
        secure=settings.env == "production",
        samesite="lax",
        max_age=1800,
        path="/",
    )
    return {
        "status": "authenticated",
        "csrf_token": csrf_token,
        "user_id": str(user.id),
        "tenant_id": str(tenant.id),
        "email": user.email,
        "role": membership.role,
    }


@router.post("/auth/logout", summary="Revoke active session or bearer token and clear cookie")
async def logout(
    request: Request,
    response: Response,
    _auth: AuthContext = Depends(get_auth_context),
) -> dict[str, str]:
    settings: Settings = getattr(request.app.state, "settings", get_settings())
    verifier: OIDCVerifier = getattr(request.app.state, "oidc_verifier", OIDCVerifier(settings))
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        verifier.revoke_token(auth_header[len("Bearer ") :].strip())
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    if cookie_token:
        verifier.revoke_token(cookie_token)
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    return {"status": "logged_out"}
