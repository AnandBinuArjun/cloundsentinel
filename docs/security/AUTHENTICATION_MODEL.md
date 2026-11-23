# CloudSentinel — Authentication & Session Security Model

**Phase**: Phase 4 (`P1`)  
**Implementation**:
- [packages/auth/oidc.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/auth/oidc.py)
- [packages/auth/dependencies.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/auth/dependencies.py)
- [apps/api/api/v1/system.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/api/api/v1/system.py)

---

## 1. Supported Authentication Modes

1. **OIDC Authorization Code Flow with PKCE + `HttpOnly` BFF Session Cookie (Primary Browser Flow)**:
   - `POST /api/v1/auth/oidc/authorize`: Validates `redirect_uri` against the strict `CLOUDSENTINEL_CORS_ORIGINS` allowlist, generates a cryptographic `state` (`32` bytes), `nonce` (`24` bytes), and RFC 7636 `S256` `code_challenge`, and stores a 10-minute single-use transaction record.
   - `POST /api/v1/auth/oidc/callback`: Consumes `state` once (preventing callback replay), verifies `code_verifier` against `code_challenge` via constant-time `hmac.compare_digest`, verifies the ID token's signature, `iss`, `aud`, `exp`, `tenant_id`, and `nonce`, verifies active PostgreSQL tenant membership, and sets an `HttpOnly; SameSite=Lax; Secure` (in production) session cookie (`cloudsentinel_session`) paired with a bound `csrf_token`.
   - **CSRF Protection**: State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) authenticated via the `cloudsentinel_session` cookie must provide an `X-CSRF-Token` header matching the session's `csrf` claim (`403 Forbidden` on mismatch).
   - **Logout & Revocation**: `POST /api/v1/auth/logout` adds the token's `jti` and SHA-256 digest to the verifier revocation set and deletes the `HttpOnly` cookie.
2. **Bearer Access Token (`Authorization: Bearer <jwt>`)**:
   - Supported for CLI/API clients and automated integration tests, verified against OIDC JWKS (`RS256`/`ES256`) or `CLOUDSENTINEL_DEV_JWT_SECRET` (strictly restricted to `CLOUDSENTINEL_ENV in ("development", "test")`).
3. **Synthetic Demo Sandbox**:
   - Strictly gated behind `VITE_ENABLE_DEMO_SANDBOX=true` (or non-production preview mode) and explicitly badged `SYNTHETIC FIXTURE`.
