# CloudSentinel Implementation Plan & Milestone Checklist

This checklist is the source of truth for CloudSentinel engineering progress. Items are checked off only when backed by real code, tests, and executed verification output.

---

## Milestone 0 — Repository Foundation
- [x] Inspect workspace and audit local toolchain
- [x] Establish monorepo directory structure & `AGENTS.md` + `.agents/rules/`
- [x] Create complete documentation suite (`README.md`, `LICENSE`, `docs/*.md`)
- [x] Implement FastAPI control plane (`/health`, `/ready`, `/api/v1/system/info`, middleware, redaction)
- [x] Implement Celery worker configuration & `ping` task
- [x] Implement React + TypeScript dark-enterprise frontend shell
- [x] Create `docker-compose.yml`, multi-stage non-root Dockerfiles, and GitHub Actions CI/CD workflows

## Milestone 1 — Identity and Multi-Tenancy
- [x] OIDC JWT/JWKS validation (`packages/auth/oidc.py`)
- [x] Five-role RBAC enforced at both API and service layers (`packages/auth/rbac.py`, `dependencies.py`)
- [x] SQLAlchemy 2 async models for all 21 core entities (`packages/db/models.py`)
- [x] Alembic initial schema migration (`database/migrations/versions/0001_initial_schema.py`)
- [x] Strict server-derived `tenant_id` isolation & cross-tenant access denial security tests

## Milestone 2 — AWS Integration
- [x] AWS STS `AssumeRole` + `ExternalId` read-only connector & root ARN rejection (`cloud_connectors/aws/connector.py`)
- [x] Version-controlled read-only IAM permission manifest (`cloud_connectors/aws/permissions.json`)
- [x] 10 deterministic AWS security rules (`AWS-S3-001..003`, `AWS-EC2-001..002`, `AWS-CT-001`, `AWS-IAM-001..002`, `AWS-EBS-001`, `AWS-MON-001`)
- [x] AWS IAM identity posture analysis with explicit limitations & synthetic fixture tests

## Milestone 3 — Azure Integration
- [x] Azure Managed Identity / Workload Identity / controlled SP connector (`cloud_connectors/azure/connector.py`)
- [x] Version-controlled least-privilege Reader role manifest (`cloud_connectors/azure/permissions.json`)
- [x] 8 deterministic Azure security rules (`AZ-STG-001..003`, `AZ-NET-001`, `AZ-IAM-001`, `AZ-KV-001`, `AZ-MON-001..002`)
- [x] Azure RBAC/Service Principal analysis with explicit limitations & synthetic fixture tests

## Milestone 4 — Assessment Engine
- [x] Common `CloudProviderConnector` interface (`packages/assessment/interface.py`)
- [x] Unified assessment orchestration persisting runs, assets, results, deduplicated findings, history, and redacted evidence (`apps/api/services/assessment_service.py`)
- [x] Tenant-scoped Celery dispatch task (`apps/worker/celery_app.py`)
- [x] REST API endpoints for connections, validation, assets, assessments, findings, and identity analysis

## Milestone 5 — Detection Engine
- [x] AWS CloudTrail & Azure Activity Log normalization (`detections/engine.py`)
- [x] 9 deterministic detection rules mapped to MITRE ATT&CK with 30-minute actor correlation
- [x] Replayable synthetic threat fixtures (`detections/fixtures.py`) and disposition API

## Milestone 6 — Compliance and Risk
- [x] Transparent, documented 0–100 risk scoring algorithm (`packages/assessment/risk.py`)
- [x] Version-controlled CIS AWS v3.0, CIS Azure v2.1, NIST CSF 2.0, and ISO/IEC 27001:2022 mappings (`compliance/frameworks.json`)
- [x] Compliance posture evaluation never coercing unassessed/errored controls to PASS (`compliance/loader.py`)

## Milestone 7 — Enterprise Frontend & Reporting
- [x] All 16 required dark-enterprise console views wired to `/api/v1/*` (`apps/web/src/pages/`)
- [x] Evidence viewer, filters, search, synthetic-fixture provenance banners, loading/empty/error states
- [x] JSON, CSV, and PDF report exports with external-sharing redaction (`apps/api/services/reporting_service.py`)

## Milestone 8 — Safe Remediation Engine
- [x] Dry-run remediation preview, blast-radius impact analysis, and rollback guidance
- [x] Human approval workflow enforcing **separation of duties** (`approver != proposer`)
- [x] Live mutations disabled by default; verification evidence & immutable audit logging

## Milestone 9 — Production Hardening & Infrastructure Security
- [x] OPA Rego policies (`policies/opa/*.rego`)
- [x] Isolated AWS & Azure Terraform security lab templates with explicit budget & cleanup guides (`infrastructure/terraform/`)
- [x] Sliding-window rate limiting (`429`), SSRF URL guardrails, SQLi/JWT/RBAC/tenant-isolation security test suite
- [ ] Live cloud-lab execution against user-provisioned sandbox AWS account & Azure subscription *(requires human-owned sandbox accounts & explicit approval)*
- [ ] Pin third-party GitHub Actions to immutable commit SHAs & run live Docker Compose build *(requires Git & Docker Desktop installed on host / GitHub repo)*
