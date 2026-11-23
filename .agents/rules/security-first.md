# Security-First Engineering Rules

Every change in CloudSentinel must uphold these implemented security invariants:

1. **Least Privilege & Read-Only Default**
   - Assessment connectors operate in **read-only mode** by default.
   - Remediation (`apps/api/services/remediation_service.py`) requires preview, impact analysis, rollback guidance, explicit human approval, **separation of duties** (`approver != proposer`), RBAC enforcement, and separate remediation credentials (`CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=true` + dedicated role) before any live cloud mutation.
   - Never require or accept AWS root credentials (`:root` ARNs are rejected) or Azure Global Administrator roles.

2. **Authentication, Authorization & Multi-Tenancy**
   - Enforce OIDC JWT/JWKS authentication (`packages/auth/oidc.py`) and 5-role RBAC (`platform_admin`, `tenant_admin`, `security_analyst`, `auditor`, `read_only`) at both FastAPI route dependencies and domain service layers.
   - Every tenant-owned entity must be scoped to `tenant_id` derived strictly from the verified token and active `memberships` row — never from client-supplied query/body parameters.
   - Enforce tenant boundaries in background workers as well as HTTP endpoints.

3. **Secrets & Data Protection**
   - Never hardcode credentials, API keys, JWT secrets, or cloud tokens in source files, tests, frontend code, or container images.
   - Never store raw cloud access keys or client secrets in standard database columns.
   - Redact sensitive fields via `packages/common/redaction.py` in structured logs, error responses, stored evidence, and external reports (`apps/api/services/reporting_service.py`).

4. **Application Security Baseline**
   - Validate all external inputs strictly via Pydantic v2 schemas.
   - Use parameterized SQLAlchemy 2 queries only; never construct raw SQL with string interpolation.
   - Enforce SSRF protections (`packages/common/ssrf.py`) on outbound URLs.
   - Return sanitized `ErrorResponse` payloads with `request_id`; never expose stack traces or raw cloud SDK exceptions to API clients.
   - Apply pure ASGI defensive HTTP headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control`), sliding-window rate limiting (`429`), and strict CORS allowlists.

5. **Supply Chain & Containers**
   - Pin dependencies and base image minor versions.
   - Run all containers as non-root users with `no-new-privileges:true`.
   - Pin third-party GitHub Actions to reviewed immutable commit SHAs prior to production release.
