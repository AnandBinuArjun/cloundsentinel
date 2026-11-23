# Changelog — CloudSentinel

All notable milestone and release changes are documented here.

## [1.0.0] — Milestones 0–9 Complete (2026-11-23)

### Added
- **M0 (Foundation)**: Monorepo layout, `AGENTS.md`, `.agents/rules/*`, full `docs/` suite, FastAPI `/health` & real `/ready` probes, non-root Dockerfiles, `docker-compose.yml`, GitHub Actions CI & gated release workflows.
- **M1 (Identity & Multi-Tenancy)**: OIDC JWT/JWKS verifier, 5-role RBAC enforced at API & service layers, 21 SQLAlchemy 2 models, Alembic `0001_initial_schema` migration, server-derived tenant isolation, immutable `audit_events`.
- **M2 (AWS Integration)**: Read-only AWS STS `AssumeRole` + `ExternalId` connector, IAM permission manifest, 10 deterministic security rules, IAM privilege/MFA/trust analysis with explicit limitations.
- **M3 (Azure Integration)**: Read-only Azure Managed Identity / Workload Identity / controlled SP connector, minimal Reader manifest, 8 deterministic Azure rules, RBAC/SP analysis with explicit limitations.
- **M4 (Assessment Engine)**: Unified `CloudProviderConnector` interface, assessment runner persisting assets, results, deduplicated findings, lifecycle history, and redacted evidence.
- **M5 (Threat Detection)**: CloudTrail & Azure Activity Log normalization, 9 deterministic detection rules, 30-min actor correlation, MITRE ATT&CK mappings, false-positive disposition.
- **M6 (Compliance & Risk)**: Transparent 0–100 risk engine, version-controlled CIS AWS v3.0, CIS Azure v2.1, NIST CSF 2.0, and ISO/IEC 27001:2022 mappings with explicit limitations.
- **M7 (Frontend & Reporting)**: 16-page dark-enterprise React + TypeScript console wired to `/api/v1/*`, plus JSON, CSV, and PDF report exports with external-sharing redaction.
- **M8 (Safe Remediation)**: Preview-first remediation workflow with impact analysis, rollback guidance, human approval, separation-of-duties enforcement, and dry-run verification by default.
- **M9 (Hardening & IaC)**: OPA Rego policies + unit tests (`policies_test.rego`), isolated AWS/Azure Terraform sandbox labs with budget & cleanup docs, PostgreSQL Row-Level Security migration (`0002_postgres_rls_policies`), full live AWS boto3 & Azure ARM REST collectors, OIDC JWKS SSRF guard, expanded CI (`Bandit`, `Semgrep`, `pip-audit`, `OPA`, `Terraform validate`, `npm audit`, gated `Prowler`), sliding-window rate limiting, demo fixture seeder, and comprehensive unit/integration/security test suites.
