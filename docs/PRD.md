# Product Requirements Document (PRD) — CloudSentinel

**Document Status**: Implemented v1.0.0 (Milestones 0–9 Complete)  
**Product Category**: Multi-Cloud Security Posture Management (CSPM) & Threat Detection Platform  
**Primary Cloud Providers**: Amazon Web Services (AWS), Microsoft Azure  

---

## 1. Product Vision & Objective

CloudSentinel provides security engineering teams with a unified, evidence-driven control plane to:
1. Discover and inventory authorized AWS and Azure cloud assets.
2. Assess cloud configurations against deterministic security rules (`PASS`, `FAIL`, `NOT_ASSESSED`, `ERROR`).
3. Identify excessive IAM/RBAC privileges and risky identity configurations with explicit analysis limitations.
4. Ingest and correlate cloud audit logs (AWS CloudTrail, Azure Activity Logs) to detect suspicious activity mapped to MITRE ATT&CK.
5. Prioritize findings through a transparent, documented internal risk scoring engine (0–100).
6. Map technical findings to compliance frameworks (CIS AWS v3.0, CIS Azure v2.1, NIST CSF 2.0, ISO/IEC 27001:2022) with explicit coverage limitations.
7. Execute safe, human-approved, auditable remediation workflows enforcing separation of duties and post-change verification.

## 2. Core Product Principles

- **Proof Before Action**: Every finding cites its rule ID, rule version, provider/account/resource reference, expected vs. observed configuration, collection timestamp, and redacted evidence.
- **No Fabricated Security Claims**: Failed API calls or missing permissions are recorded as `ERROR` / `NOT_ASSESSED` (never `PASS`); synthetic demonstration fixtures are explicitly tagged `data_source="synthetic_fixture"`.
- **Read-Only by Default**: Assessment identities require read-only permissions only. Remediation is preview-first, approval-gated, and separated from assessment credentials.
- **Hybrid & Self-Hostable**: Runs locally via Python/Node or Docker Compose and supports private or cloud-hosted control plane deployments.

## 3. Target Personas & RBAC Roles (Implemented in `packages/auth/rbac.py`)

| Role | Enum Value | Primary Responsibilities | Scope |
| :--- | :--- | :--- | :--- |
| **Platform Administrator** | `platform_admin` | Full platform & tenant administration, all permissions | Multi-tenant / Platform |
| **Tenant Administrator** | `tenant_admin` | Cloud connector onboarding, remediation approval & execution, audit log oversight | Single Tenant |
| **Security Analyst** | `security_analyst` | Run assessments, investigate findings/detections, preview remediations, export reports | Single Tenant |
| **Auditor** | `auditor` | Read-only access to findings, evidence, compliance mappings, reports, and audit logs | Single Tenant |
| **Read-only User** | `read_only` | View dashboards, connections, assets, assessments, findings, detections, compliance | Single Tenant |

## 4. Product Modules & Delivery Status

| Module | Scope | Milestone | Status |
| :--- | :--- | :--- | :--- |
| **Platform Foundation** | Monorepo, FastAPI `/health` & `/ready`, Celery worker, React dark console, Docker Compose, GitHub Actions CI/CD | Milestone 0 | **Implemented** |
| **Identity & Multi-Tenancy** | OIDC JWT/JWKS verifier, 5-role RBAC, 21 SQLAlchemy 2 models, Alembic `0001_initial_schema`, tenant isolation | Milestone 1 | **Implemented** |
| **Module 02 — Cloud Connectors (AWS)** | AWS STS `AssumeRole` + `ExternalId`, root ARN rejection, read-only IAM manifest, 10 checks | Milestone 2 | **Implemented** |
| **Module 02 — Cloud Connectors (Azure)** | Managed/Workload Identity & controlled SP, subscription validation, Reader manifest, 8 checks | Milestone 3 | **Implemented** |
| **Module 03 & 04 — Inventory & Posture Engine** | `CloudProviderConnector` ABC, assessment orchestration, deduplicated findings & evidence | Milestone 4 | **Implemented** |
| **Module 05 — Identity & Access Security** | AWS IAM & Azure RBAC privilege/MFA/trust/SP analysis with explicit limitations | Milestones 2–4 | **Implemented** |
| **Module 06 — Cloud Threat Detection** | CloudTrail & Azure Activity Log normalization, 9 deterministic rules, 30m correlation, MITRE ATT&CK | Milestone 5 | **Implemented** |
| **Module 07 & 08 — Risk & Compliance** | Transparent 0–100 risk engine, CIS AWS/Azure, NIST CSF 2.0, ISO/IEC 27001:2022 mappings | Milestone 6 | **Implemented** |
| **Module 01 & 11 — Enterprise Console & Reporting** | 16-page dark-enterprise React console, evidence viewer, JSON/CSV/PDF redacted exports | Milestone 7 | **Implemented** |
| **Module 10 — Remediation Engine** | Dry-run preview, impact analysis, rollback guidance, human approval + separation of duties, verification | Milestone 8 | **Implemented** |
| **Module 09 — IaC Security & Hardening** | OPA Rego policies, isolated AWS/Azure Terraform labs + budget/cleanup docs, rate limiting, SSRF guardrails | Milestone 9 | **Implemented** |

> **Live Cloud Lab Boundary**: Automated CI and local test suites validate all modules using deterministic synthetic provider fixtures (`data_source="synthetic_fixture"`). Live cloud-lab execution requires user-owned isolated AWS/Azure sandbox accounts and explicit human approval.

## 5. Non-Functional Requirements

- **Security**: Multi-tenant isolation enforced via server-derived `tenant_id` across API, service, and worker layers; zero raw cloud secrets in source, frontend, logs, or standard DB columns; rate limiting (`429`), SSRF guardrails, defensive headers, and strict CORS.
- **Reliability**: Bounded timeouts on DB/Redis probes and cloud SDK clients, retries with backoff, pagination, and partial-failure tracking.
- **Observability**: Structured single-line JSON logs with `X-Request-ID` correlation, sensitive-key redaction, `/health`, and real `/ready` probes.
- **Maintainability**: Strict typing (`mypy --strict`, TypeScript `strict`), `ruff` formatting/linting, pinned dependencies, and living documentation.
