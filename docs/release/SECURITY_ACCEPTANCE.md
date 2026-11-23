# Security Acceptance Criteria & Sign-Off Checklist (Phase 12)

## 1. P0/P1 Security Invariants Verified

- [x] **No Unverified Finding Resolution**: Dry-run remediation (`confirm_live=False`) stops at `stage="executed_unverified"` (`verification_status="dry_run_simulated"`) and never resolves open findings.
- [x] **Fail-Closed Live Remediation**: `CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED` defaults to `false`. Requesting `confirm_live=True` without a registered provider executor fails with `HTTP 501 Not Implemented`.
- [x] **Separation of Duties (SoD)**: A proposer cannot approve their own remediation request (`HTTP 403 Forbidden`), enforced both at `/approve` and re-verified at `/execute`.
- [x] **Defense-in-Depth Multi-Tenant Isolation**: Every tenant-scoped SQLAlchemy query filters by `tenant_id`, and PostgreSQL `0003_security_hardening_schema` enforces `FORCE ROW LEVEL SECURITY` with `USING (...) WITH CHECK (...)` policies under a `NOBYPASSRLS` application role (`cloudsentinel_app`).
- [x] **Pooled Connection Hygiene**: `get_db_session()` resets `app.current_tenant_id` on checkout and in `finally:` teardown.
- [x] **Zero Raw Cloud Credentials in Persistence**: AWS uses short-lived STS `AssumeRole` sessions; Azure uses Managed/Workload Identity or external secret manager references.
- [x] **Failed Cloud Calls Never Treated as PASS**: Both AWS and Azure connectors emit `CheckStatus.NOT_ASSESSED` (on HTTP 403 / `AccessDenied`) or `CheckStatus.ERROR` when provider API calls fail.
- [x] **Detection Provenance & Scope**: Detection ingestion verifies `account_ref` belongs to a tenant `CloudConnection`, prevents `synthetic_fixture` connections from spoofing `data_source="live"`, and deduplicates events.

---

## 2. Human Owner Sign-Off Required Before Production Deployment

1. Provision external PostgreSQL 16+ with separate `cloudsentinel_migrator` (schema migrations) and `cloudsentinel_app` (`NOBYPASSRLS` runtime) credentials.
2. Configure production OIDC IdP (`OIDC_ISSUER_URL`, `OIDC_JWKS_URL`, `OIDC_AUDIENCE`) and keep `CLOUDSENTINEL_ENV=production` (which disables HS256 dev tokens).
3. Execute controlled read-only sandbox validation against live AWS and Azure lab accounts (`tests/cloud_lab/`).
