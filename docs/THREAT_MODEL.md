# Threat Model — CloudSentinel

**Status**: Reviewed & Updated for v1.0.0 (Milestones 0–9 Implemented)  
**Methodology**: STRIDE + Cloud Security Trust-Boundary Analysis

---

## 1. Security Assets to Protect

1. **Tenant Isolation Boundaries**: Connections, assets, findings, evidence, detections, remediations, and audit logs belonging to Tenant A must never be accessible to Tenant B.
2. **Cloud Identities & Short-Lived Credentials**: AWS STS Role ARNs/External IDs, Azure Managed/Workload Identity bindings, and separate remediation credentials.
3. **Evidence & Audit Integrity**: Redacted evidence snapshots, finding lifecycle history, and immutable `audit_events`.
4. **Remediation Control Plane**: Prevents unauthorized, self-approved, or destructive cloud mutations.
5. **Control Plane Availability**: Protects FastAPI and workers from abuse, hanging backing services, or SSRF.

---

## 2. STRIDE Threat Matrix & Implemented Controls

| Category | Threat Scenario | Implemented Control | Verification Test |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Forged, `alg:none`, expired, or wrong-audience JWT; spoofed `tenant_id` | `OIDCVerifier` (`packages/auth/oidc.py`) enforces signature, `iss`, `aud`, `exp`; `get_auth_context` validates DB `memberships` strictly server-side | `test_invalid_forged_expired_and_wrong_audience_tokens_rejected` |
| **Tampering** | Unauthorized or self-approved cloud remediation | Preview-first lifecycle (`remediation_service.py`), RBAC gates, separation of duties (`approver != proposer`), `live_remediation_enabled=false` default | `test_rbac_privilege_escalation_and_separation_of_duties` |
| **Repudiation** | Actor denies changing findings, exporting reports, or approving remediations | Immutable `audit_events` recorded across connection, assessment, finding, detection, report, and remediation flows (`apps/api/services/audit.py`) | `test_full_cspm_detection_compliance_reporting_and_remediation_lifecycle` |
| **Information Disclosure** | Stack traces, DB passwords, or secrets leaked in HTTP errors, logs, or external reports | Sanitized `ErrorResponse` (`exceptions.py`), recursive `redact_data()` (`redaction.py`), external-sharing report redaction (`reporting_service.py`), defensive headers | `test_unhandled_exception_does_not_leak_stack_trace_or_secrets`, `test_ready_endpoint_with_unreachable_ports_never_fakes_ready` |
| **Information Disclosure** | Cross-tenant IDOR or unscoped queries | Every query filters by verified `auth.tenant_id`; cross-tenant direct ID lookups return `404` or `403` | `test_cross_tenant_isolation_denies_all_cross_tenant_reads_and_writes` |
| **Denial of Service** | Request flooding or hanging DB/Redis probes | `RateLimitMiddleware` (`429` + `Retry-After`), bounded `asyncio.wait_for` probe timeouts, Celery async worker isolation | `test_rate_limiter_enforces_http_429` |
| **Elevation of Privilege** | Read-only user mutating state; AWS root credentials submitted | Dual-layer RBAC (`require_permissions` + `auth.require_permission()`); Pydantic & connector rejection of `:root` ARNs | `test_rbac_privilege_escalation_and_separation_of_duties`, `test_aws_connector_rejects_root_arn_and_validates_fixture` |
| **Injection / SSRF** | SQL injection in search filters; SSRF to `169.254.169.254` or private IPs | Parameterized SQLAlchemy 2 ORM queries only; `validate_outbound_https_url()` (`packages/common/ssrf.py`) | `test_ssrf_validator_blocks_metadata_and_private_targets`, SQLi assertion in `test_authz_tenancy_and_hardening.py` |

---

## 3. Remaining Pre-Production Operational Actions (External / Deployment)

1. **GitHub Actions Commit-SHA Pinning**: Pin third-party action versions in `.github/workflows/ci.yml`, `release.yml`, and `cloud-lab-prowler.yml` to reviewed immutable commit SHAs prior to production release.
2. **Distributed Rate Limiting**: Replace the in-memory `RateLimitMiddleware` bucket with a shared Redis sliding-window counter when scaling beyond a single API replica.
3. **Production OIDC Provider**: Configure `OIDC_JWKS_URL` (SSRF-validated via `validate_outbound_https_url`), `OIDC_ISSUER_URL`, and `OIDC_AUDIENCE`, and run Alembic `0002_postgres_rls_policies` against PostgreSQL 16.
