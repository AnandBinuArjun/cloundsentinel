# CloudSentinel Rollback Runbook (Phase 12)

## 1. Application & Container Rollback

1. **Revert API, Worker, and Web Containers** to the previous known-good immutable image digest in GHCR (`ghcr.io/anandbinuarjun/cloundsentinel/{api,worker,web}:<PREVIOUS_VERSION>`).
2. **Disable Live Remediation Immediately** (if enabled):
   Set `CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=false` and restart `cloudsentinel-api`.

---

## 2. Database Migration Rollback (`0003_security_hardening_schema` -> `0002_postgres_rls_policies`)

Migration `0003_security_hardening_schema` includes a complete `downgrade()` routine that:
- Drops the `WITH CHECK` policies and restores the `0002` `USING` policies.
- Drops the additive columns (`job_id`, `idempotency_key`, `progress_pct`, `failure_reason`, `queued_at`, `cancelled_at` on `assessment_runs`; `provider_event_id` on `detection_events`; `idempotency_key`, `operation_id`, `verification_rule_id`, `verification_status`, `failure_reason`, `executed_at`, `verified_at` on `remediation_requests`).

To roll back the database schema:

```bash
DATABASE_URL=postgresql+asyncpg://cloudsentinel_migrator:<MIGRATOR_PASSWORD>@db.internal:5432/cloudsentinel \
  alembic -c database/migrations/alembic.ini downgrade 0002_postgres_rls_policies
```

---

## 3. Cloud Resource Remediation Rollback

If an authorized live remediation caused an operational disruption on a target cloud resource:
1. Open the `RemediationRequest` record in `/remediations` or query `SELECT proposal, verification_evidence, rollback_guidance FROM remediation_requests WHERE id = '<id>'`.
2. Inspect the pre-change configuration snapshot stored in `Finding` -> `Evidence.observed_config`.
3. Follow the action-specific `rollback_guidance` recorded on the remediation request.
