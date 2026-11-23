# Database Migrations (Alembic)

**Status**: Implemented v1.0.0 (`Milestone 1`)

- `alembic.ini` & `env.py` — Async SQLAlchemy 2 Alembic migration harness bound to `packages.db.base.Base.metadata`.
- `versions/0001_initial_schema.py` — Initial revision creating all 21 tenant-scoped CloudSentinel relational entities (`tenants`, `users`, `memberships`, `cloud_connections`, `cloud_accounts`, `assets`, `assessment_profiles`, `security_rules`, `assessment_runs`, `assessment_results`, `findings`, `finding_history`, `evidence`, `detection_rules`, `detection_events`, `compliance_frameworks`, `compliance_controls`, `compliance_mappings`, `remediation_requests`, `remediation_approvals`, `audit_events`).
- `versions/0002_postgres_rls_policies.py` — Enables PostgreSQL Row-Level Security (`ENABLE ROW LEVEL SECURITY`) and `cloudsentinel_tenant_isolation` policies bound to `app.current_tenant_id` across all 14 tenant-owned tables (automatically no-ops on SQLite test harnesses).

Run migrations against PostgreSQL 16+:
```bash
alembic -c database/migrations/alembic.ini upgrade head
```
