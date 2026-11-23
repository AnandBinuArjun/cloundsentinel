"""OIDC JWT token verification using JWKS (production) or controlled local keys (dev/test)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt import InvalidTokenError, PyJWKClient

from packages.common.config import Settings
from packages.common.ssrf import validate_outbound_https_url


class AuthenticationError(ValueError):
    """Raised when an access token is missing, malformed, expired, or invalid."""


@dataclass(frozen=True)
class VerifiedTokenClaims:
    issuer: str
    subject: str
    email: str
    display_name: str
    tenant_id: uuid.UUID
    expires_at: datetime


class OIDCVerifier:
    """Verify OIDC JWT tokens with strict issuer, audience, and expiration enforcement."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        if settings.oidc_jwks_url:
            safe_jwks_url = validate_outbound_https_url(settings.oidc_jwks_url)
            self._jwks_client: PyJWKClient | None = PyJWKClient(safe_jwks_url)
        else:
            self._jwks_client = None

    def verify_token(self, raw_token: str) -> VerifiedTokenClaims:
        if not raw_token or raw_token.count(".") != 2:
            raise AuthenticationError("Malformed bearer token.")

        try:
            header = jwt.get_unverified_header(raw_token)
            alg = str(header.get("alg", ""))
            if alg == "none" or not alg:
                raise AuthenticationError("Unsigned tokens are rejected.")

            if self._jwks_client is not None and alg in {"RS256", "RS384", "RS512", "ES256"}:
                signing_key = self._jwks_client.get_signing_key_from_jwt(raw_token)
                payload = jwt.decode(
                    raw_token,
                    signing_key.key,
                    algorithms=["RS256", "RS384", "RS512", "ES256"],
                    audience=self._settings.oidc_audience,
                    issuer=self._settings.oidc_issuer_url,
                    leeway=self._settings.oidc_leeway_seconds,
                    options={"require": ["sub", "iss", "aud", "exp", "tenant_id"]},
                )
            elif (
                self._settings.env in ("development", "test")
                and self._settings.dev_jwt_secret
                and alg == "HS256"
            ):
                payload = jwt.decode(
                    raw_token,
                    self._settings.dev_jwt_secret,
                    algorithms=["HS256"],
                    audience=self._settings.oidc_audience,
                    issuer=self._settings.oidc_issuer_url,
                    leeway=self._settings.oidc_leeway_seconds,
                    options={"require": ["sub", "iss", "aud", "exp", "tenant_id"]},
                )
            else:
                raise AuthenticationError("Token signing algorithm or OIDC configuration invalid.")
        except InvalidTokenError as exc:
            raise AuthenticationError("Token validation failed.") from exc

        return self._parse_claims(payload)

    @staticmethod
    def _parse_claims(payload: dict[str, Any]) -> VerifiedTokenClaims:
        try:
            tenant_uuid = uuid.UUID(str(payload["tenant_id"]))
            exp_ts = float(payload["exp"])
            expires_at = datetime.fromtimestamp(exp_ts, tz=UTC)
        except (KeyError, ValueError, TypeError) as exc:
            raise AuthenticationError("Invalid required token claims.") from exc

        subject = str(payload.get("sub", "")).strip()
        email = str(payload.get("email", f"{subject}@local.invalid")).strip()
        display_name = str(payload.get("name", email)).strip()
        issuer = str(payload.get("iss", "")).strip()
        if not subject or not issuer:
            raise AuthenticationError("Missing subject or issuer claim.")

        return VerifiedTokenClaims(
            issuer=issuer,
            subject=subject,
            email=email,
            display_name=display_name,
            tenant_id=tenant_uuid,
            expires_at=expires_at,
        )


def issue_dev_token(
    *,
    settings: Settings,
    subject: str,
    email: str,
    tenant_id: uuid.UUID,
    display_name: str = "Local Developer",
    expires_in_minutes: int = 30,
) -> str:
    """Mint a short-lived HS256 JWT exclusively in development/test environments."""
    if settings.env not in ("development", "test") or not settings.dev_jwt_secret:
        raise RuntimeError("Development token issuance is disabled outside development/test.")
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": settings.oidc_issuer_url,
        "aud": settings.oidc_audience,
        "sub": subject,
        "email": email,
        "name": display_name,
        "tenant_id": str(tenant_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_in_minutes)).timestamp()),
    }
    return jwt.encode(claims, settings.dev_jwt_secret, algorithm="HS256")
