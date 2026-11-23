"""OIDC JWT verification, Authorization Code + PKCE flow, and BFF HttpOnly session manager (Phase 4)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt import InvalidTokenError, PyJWKClient

from packages.common.config import Settings
from packages.common.ssrf import validate_outbound_https_url

SESSION_COOKIE_NAME = "cloudsentinel_session"
CSRF_HEADER_NAME = "X-CSRF-Token"


class AuthenticationError(ValueError):
    """Raised when an access token, PKCE state, or session is missing, malformed, expired, or revoked."""


@dataclass(frozen=True)
class VerifiedTokenClaims:
    issuer: str
    subject: str
    email: str
    display_name: str
    tenant_id: uuid.UUID
    expires_at: datetime
    nonce: str | None = None
    csrf_token: str | None = None
    jti: str | None = None


@dataclass(frozen=True)
class PKCEAuthorizationRequest:
    authorize_url: str
    state: str
    nonce: str
    code_challenge: str
    code_challenge_method: str = "S256"


def generate_pkce_pair() -> tuple[str, str]:
    """Generate an RFC 7636 PKCE (code_verifier, S256 code_challenge) pair."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def compute_pkce_challenge(code_verifier: str) -> str:
    """Compute S256 code_challenge for a given code_verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class OIDCVerifier:
    """Verify OIDC JWT tokens, PKCE authorization states, and BFF session cookies."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        if settings.oidc_jwks_url:
            safe_jwks_url = validate_outbound_https_url(settings.oidc_jwks_url)
            self._jwks_client: PyJWKClient | None = PyJWKClient(safe_jwks_url)
        else:
            self._jwks_client = None
        # Pending PKCE transactions keyed by state -> (nonce, code_challenge, redirect_uri, expires_at)
        self._pending_pkce: dict[str, tuple[str, str, str, datetime]] = {}
        # Consumed PKCE states and revoked session JTIs (replay & logout protection)
        self._consumed_states: set[str] = set()
        self._revoked_jtis: set[str] = set()

    def _signing_secret(self) -> str:
        if self._settings.dev_jwt_secret:
            return self._settings.dev_jwt_secret
        if self._settings.env == "production":
            raise AuthenticationError("Production session signing key is not configured.")
        return "ephemeral-non-prod-fallback-signing-key-32b!!"

    def create_pkce_authorization_request(
        self,
        *,
        redirect_uri: str,
        client_id: str = "cloudsentinel-console",
        code_challenge: str | None = None,
    ) -> PKCEAuthorizationRequest:
        """Create a state-bound, replay-protected OIDC Authorization Code + PKCE request."""
        allowed_prefixes = tuple(self._settings.cors_origins)
        if not any(redirect_uri.startswith(origin) for origin in allowed_prefixes):
            raise AuthenticationError("Redirect URI is not in the allowed origin list.")

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(24)
        if not code_challenge:
            _verifier, code_challenge = generate_pkce_pair()

        expires_at = datetime.now(UTC) + timedelta(minutes=10)
        self._pending_pkce[state] = (nonce, code_challenge, redirect_uri, expires_at)

        issuer = self._settings.oidc_issuer_url.rstrip("/")
        authorize_url = (
            f"{issuer}/authorize?response_type=code"
            f"&client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&scope=openid+profile+email"
            f"&state={state}"
            f"&nonce={nonce}"
            f"&code_challenge={code_challenge}"
            f"&code_challenge_method=S256"
        )
        return PKCEAuthorizationRequest(
            authorize_url=authorize_url,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
        )

    def consume_pkce_callback(
        self,
        *,
        state: str,
        code_verifier: str,
        redirect_uri: str,
        id_token: str,
    ) -> VerifiedTokenClaims:
        """Validate OIDC callback state, PKCE verifier, redirect URI, and ID token nonce (single-use)."""
        if not state or state in self._consumed_states:
            raise AuthenticationError("Invalid or replayed OIDC callback state.")
        record = self._pending_pkce.pop(state, None)
        if record is None:
            raise AuthenticationError("Unknown or expired OIDC state parameter.")

        expected_nonce, expected_challenge, expected_redirect, expires_at = record
        self._consumed_states.add(state)

        if datetime.now(UTC) > expires_at:
            raise AuthenticationError("OIDC authorization transaction expired.")
        if redirect_uri != expected_redirect:
            raise AuthenticationError("OIDC callback redirect_uri mismatch.")

        actual_challenge = compute_pkce_challenge(code_verifier)
        if not hmac.compare_digest(actual_challenge, expected_challenge):
            raise AuthenticationError("PKCE code_verifier validation failed.")

        claims = self.verify_token(id_token, expected_nonce=expected_nonce)
        return claims

    def issue_bff_session_cookie(
        self,
        claims: VerifiedTokenClaims,
        *,
        ttl_minutes: int = 30,
    ) -> tuple[str, str]:
        """Issue an HttpOnly BFF session JWT and its paired CSRF token."""
        now = datetime.now(UTC)
        jti = claims.jti or uuid.uuid4().hex
        csrf_token = secrets.token_urlsafe(24)
        payload: dict[str, Any] = {
            "iss": self._settings.oidc_issuer_url,
            "aud": self._settings.oidc_audience,
            "sub": claims.subject,
            "email": claims.email,
            "name": claims.display_name,
            "tenant_id": str(claims.tenant_id),
            "jti": jti,
            "csrf": csrf_token,
            "token_use": "bff_session",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp()),
        }
        cookie_val = jwt.encode(payload, self._signing_secret(), algorithm="HS256")
        return cookie_val, csrf_token

    def revoke_token(self, raw_token: str) -> None:
        """Revoke a session or access token by verifying its signature and recording its JTI and digest."""
        try:
            verified = self.verify_token(raw_token)
            if verified.jti:
                self._revoked_jtis.add(verified.jti)
        except Exception as exc:
            _ = exc
        digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        self._revoked_jtis.add(digest)

    def verify_token(
        self,
        raw_token: str,
        *,
        expected_nonce: str | None = None,
    ) -> VerifiedTokenClaims:
        if not raw_token or raw_token.count(".") != 2:
            raise AuthenticationError("Malformed bearer token.")

        digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        if digest in self._revoked_jtis:
            raise AuthenticationError("Token has been logged out or revoked.")

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

        jti = str(payload.get("jti", "")) if payload.get("jti") else None
        if jti and jti in self._revoked_jtis:
            raise AuthenticationError("Session token has been revoked.")

        if expected_nonce is not None:
            token_nonce = str(payload.get("nonce", ""))
            if not token_nonce or not hmac.compare_digest(token_nonce, expected_nonce):
                raise AuthenticationError("ID token nonce mismatch.")

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
            nonce=str(payload["nonce"]) if payload.get("nonce") else None,
            csrf_token=str(payload["csrf"]) if payload.get("csrf") else None,
            jti=str(payload["jti"]) if payload.get("jti") else None,
        )


def issue_dev_token(
    *,
    settings: Settings,
    subject: str,
    email: str,
    tenant_id: uuid.UUID,
    display_name: str = "Local Developer",
    expires_in_minutes: int = 30,
    nonce: str | None = None,
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
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_in_minutes)).timestamp()),
    }
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(claims, settings.dev_jwt_secret, algorithm="HS256")
