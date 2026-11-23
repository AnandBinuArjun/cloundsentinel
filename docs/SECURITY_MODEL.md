# Security Model — CloudSentinel

**Status**: Implemented v1.0.0 (Verified by `tests/security/`)

---

## 1. Six-Layer Defense-in-Depth Architecture

1. **Identity & Authentication (`packages/auth/oidc.py`)**
   - OIDC JWT validation via RS256/ES256 JWKS (`PyJWKClient`), rejecting `alg: none`, malformed, forged, expired, or wrong-audience tokens.
   - Controlled HS256 dev token signing is restricted strictly to `CLOUDSENTINEL_ENV in ("development", "test")`.
2. **Dual-Layer RBAC (`packages/auth/rbac.py`, `dependencies.py`)**
   - Five least-privilege roles (`platform_admin`, `tenant_admin`, `security_analyst`, `auditor`, `read_only`) mapped to 16 explicit `Permission` grants.
   - Enforced at both FastAPI route dependencies (`require_permissions(...)`) and backend domain service methods (`auth.require_permission(...)`).
3. **Strict Multi-Tenant Isolation**
   - `tenant_id` is derived exclusively from the verified JWT claim cross-checked against active `memberships` in the database; client-supplied tenant IDs are never trusted.
   - Every ORM query filters by `auth.tenant_id`; cross-tenant ID access returns `404` or `403`.
4. **Application Security Controls**
   - Strict Pydantic v2 validation + parameterized SQLAlchemy 2 queries (SQL injection resistant).
   - Pure ASGI `SecurityHeadersMiddleware` (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cache-Control: no-store`).
   - Explicit CORS origin allowlist (wildcards stripped automatically).
   - `RateLimitMiddleware` returning HTTP `429` with `Retry-After`.
   - `validate_outbound_https_url()` (`packages/common/ssrf.py`) blocking cloud metadata (`169.254.169.254`, `metadata.azure.com`), loopback, and private IPs.
   - Sanitized `ErrorResponse` handlers and recursive log/evidence/report redaction (`packages/common/redaction.py`, `reporting_service.py`).
5. **Cloud Assessment Security**
   - AWS STS cross-account read-only `AssumeRole` + `ExternalId` (explicitly rejects `:root` ARNs).
   - Azure Managed Identity / Workload Identity Federation (never requires Global Administrator or raw secrets in DB columns).
6. **Safe Remediation Controls (`apps/api/services/remediation_service.py`)**
   - Read-only & dry-run verification by default.
   - Mandatory preview, impact analysis, rollback guidance, human approval, **separation of duties** (`approver != proposer`), separate remediation credentials gate, and immutable `audit_events`.
