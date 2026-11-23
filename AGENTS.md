# AGENTS.md — CloudSentinel Engineering Operating Contract

This repository implements **CloudSentinel (v1.0.0)**, a Multi-Cloud Security Posture Management (CSPM) and Threat Detection Platform targeting **Amazon Web Services (AWS)** and **Microsoft Azure**.

All AI agents and human contributors working in this workspace MUST follow this document and the specialized rules in `.agents/rules/`.

---

## 1. Core Engineering Principle: PROOF BEFORE ACTION

- Every security finding must have a traceable detection source, reproducible evidence, a clear explanation, and recommended remediation.
- **Never fabricate security findings**, telemetry, compliance scores, or health checks.
- **Never claim an assessment or test passed without executing it and reporting real output.**
- Explicitly distinguish **implemented capabilities** from **planned work**, and **synthetic test/demo fixtures** (`data_source="synthetic_fixture"`) from **live cloud assessments**.
- Never interpret a failed cloud API call or unreachable dependency as a `PASS`.

---

## 2. Authority & Safety Boundaries

The **human project owner** is the final authority for:
- Architecture changes and schema migrations
- Cloud resource creation (AWS or Azure)
- External deployments and container registry pushes
- Security-sensitive actions (auth, RBAC, remediation execution, secret management)
- Production releases

Agents MUST NOT:
- Deploy infrastructure or execute destructive cloud/local commands without explicit human approval
- Store raw cloud credentials, tokens, or secrets in source code, git history, logs, frontend bundles, or ordinary database columns
- Bypass authentication, tenant isolation, separation of duties, or least-privilege constraints
- Overwrite existing user work without approval

---

## 3. Repository Architecture & Conventions

```text
CloudSentinel/
├── apps/
│   ├── api/                 # FastAPI REST API (/api/v1/*, /health, /ready, domain services)
│   ├── worker/              # Celery async worker (Redis broker/backend, tenant-scoped tasks)
│   └── web/                 # 16-page React 19 + TypeScript + Vite + Tailwind v4 enterprise console
├── cloud_connectors/
│   ├── aws/                 # AWS STS read-only connector, permissions manifest & 10 rules
│   └── azure/               # Azure Managed/Workload Identity connector, Reader manifest & 8 rules
├── packages/
│   ├── auth/                # OIDC JWT/JWKS verifier, 5-role RBAC & FastAPI dependencies
│   ├── common/              # Typed settings, structured JSON logging, redaction, SSRF validator
│   ├── contracts/           # Shared Pydantic v2 operational & domain schemas
│   ├── db/                  # SQLAlchemy 2 async engine & all 21 tenant-scoped models
│   └── assessment/          # Common CloudProviderConnector interface & transparent risk engine
├── policies/opa/            # OPA Rego policies for S3, Azure Storage, and Terraform guardrails
├── detections/              # CloudTrail & Azure Activity Log normalization, 9 rules, ATT&CK mappings
├── compliance/              # Version-controlled CIS AWS/Azure, NIST CSF 2.0, ISO 27001:2022 mappings
├── infrastructure/
│   ├── docker/              # Multi-stage non-root Dockerfiles (api, worker, web)
│   └── terraform/           # Isolated AWS & Azure sandbox lab templates + budget/cleanup guides
├── database/
│   ├── migrations/          # Alembic PostgreSQL 16+ migrations (0001_initial_schema .. 0003_security_hardening_schema)
│   └── seeds/               # Explicitly labeled synthetic demo fixture seeder (non-prod only)
├── tests/
│   ├── unit/                # Fast deterministic unit & config tests
│   ├── integration/         # Health/readiness & full M1–M8 async API/DB lifecycle tests
│   ├── security/            # Tenant isolation, RBAC, JWT/PKCE, SoD, remediation state machine, rate limiting
│   └── cloud_lab/           # Controlled AWS/Azure sandbox validation policy (manual only)
├── scripts/                 # Local YAML/config verification scripts
├── docs/                    # Living architecture, security, audits, validation, devsecops & release docs
└── .agents/rules/           # Domain-specific agent engineering standards
```

---

## 4. Hardened Security & Operational Invariants (Phases 1–12)

1. **Remediation Execution Safety (Phase 1)**:
   - Strict state machine: `DRAFT/PREVIEWED/PENDING_APPROVAL -> APPROVED -> EXECUTING -> EXECUTED_UNVERIFIED -> VERIFYING -> VERIFIED` (with `FAILED`, `REJECTED`, `CANCELLED`, `ROLLBACK_REQUIRED`).
   - Dry-run (`confirm_live=False`) stops at `executed_unverified` (`verification_status="dry_run_simulated"`) and NEVER resolves any finding.
   - Live execution (`confirm_live=True`) defaults to disabled (`CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=false`), requires a separate remediation role ARN, returns `HTTP 501` if no live provider executor is registered, and only resolves a finding after a post-remediation reassessment returns `CheckStatus.PASS`.
2. **PostgreSQL Row-Level Security & Tenant Context (Phase 2)**:
   - Migration `0003_security_hardening_schema` enforces `FORCE ROW LEVEL SECURITY` with `USING (...) WITH CHECK (...)` policies across all 14 tenant-scoped tables and creates a dedicated `NOBYPASSRLS` application role (`cloudsentinel_app`).
   - `get_db_session()` resets `app.current_tenant_id` on checkout and teardown (`finally:`) so pooled connections never leak tenant context.
3. **Asynchronous Assessment Orchestration (Phase 3)**:
   - `POST /api/v1/assessments` returns `202 Accepted`, enforces per-connection concurrency locks (`409 Conflict`) and idempotency keys, runs synchronous SDK/HTTP collectors via `asyncio.to_thread()`, exposes `/results` and `/cancel`, and reconciles stale findings on complete runs.
4. **OIDC PKCE, BFF Cookies, CSRF & Revocation (Phase 4)**:
   - Supports RFC 7636 PKCE (`S256`), single-use `state`/`nonce` validation, `HttpOnly; SameSite=Lax` BFF session cookies paired with `X-CSRF-Token` validation on state-changing requests, and token revocation via `POST /api/v1/auth/logout`.
5. **Cloud Connector & Detection Evidence Integrity (Phases 5–7)**:
   - AWS and Azure connectors emit explicit `NOT_ASSESSED` / `ERROR` `CheckEvaluation` records when service/provider API calls fail.
   - Detection ingestion validates ISO-8601 event timestamps, verifies `account_ref` belongs to a registered tenant `CloudConnection`, locks synthetic provenance, and deduplicates by `(tenant_id, provider, provider_event_id, rule_id)`.

---

## 5. Change & Release Discipline

For every subsequent feature or security fix:
1. Inspect existing code, `AGENTS.md`, and relevant `docs/` first.
2. State the objective, affected files, trust boundaries, and acceptance criteria.
3. Implement backend functionality and contracts before connecting frontend controls.
4. Add unit, integration, and security tests for every security-sensitive capability.
5. Run `ruff`, `mypy --strict`, `pytest`, and frontend `typecheck`/`test`/`build`; fix all failures.
6. Update `docs/` and `docs/IMPLEMENTATION_PLAN.md` to accurately reflect implemented state.
7. Deliver an evidence-backed engineering report and wait for human review before deploying or provisioning external cloud resources.

---

## 6. Workspace Rule Index

Read and comply with all rules under `.agents/rules/`:
- `.agents/rules/security-first.md` — Least privilege, multi-tenancy, secrets, error handling, safe remediation
- `.agents/rules/backend-standards.md` — Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2, Celery conventions
- `.agents/rules/frontend-standards.md` — Dark enterprise UI direction, real backend data only, state handling
- `.agents/rules/testing-standards.md` — Evidence requirements, test layers, CI fixture policy
- `.agents/rules/cloud-integration.md` — AWS STS & Azure Identity read-only assessment rules
