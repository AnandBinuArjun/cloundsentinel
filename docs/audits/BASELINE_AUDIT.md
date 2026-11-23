# CloudSentinel — Phase 0 Baseline Architecture & Security Audit

**Repository**: `https://github.com/AnandBinuArjun/cloundsentinel`  
**Audit Branch**: `hardening/cloudsentinel-security-validation`  
**Baseline Commit SHA**: `82596087a067589e1bf719e330534e0f7cdc3d40` (`main`)  
**Audit Date (UTC)**: `2026-11-23`  
**Operating Principle**: **PROOF BEFORE ACTION** — every finding below was verified directly against the current source tree at `HEAD`.

---

## 1. Baseline Repository Snapshot

### 1.1 Existing Architecture & Pinned Dependencies

| Layer | Implementation Path | Pinned Runtime / Toolchain |
| :--- | :--- | :--- |
| **Control Plane API** | `apps/api/` (`main.py`, `api/v1/{system,dashboard,cspm,operations}.py`, `services/`, `core/`) | Python `3.12+`, FastAPI `0.165.0` (Starlette `>=1.3.1`), Uvicorn `0.34.0`, Pydantic `2.10.6` |
| **Async Worker** | `apps/worker/celery_app.py` | Celery `5.4.0`, Redis `5.2.1` |
| **Web Console** | `apps/web/` (`src/pages/`, `src/components/`, `src/lib/`) | React `19.0.0`, TypeScript `5.7.3`, Vite `6.4.6`, Tailwind CSS `4.1.11`, TanStack Query `5.66.0`, React Router `7.18.6` |
| **Authentication & RBAC** | `packages/auth/` (`oidc.py`, `rbac.py`, `dependencies.py`) | `PyJWT[crypto]==2.15.1` (`RS256`/`ES256` JWKS + dev/test `HS256`), 5-role RBAC (`16` permissions) |
| **Persistence & Migrations** | `packages/db/` (`models.py`, `session.py`), `database/migrations/` | SQLAlchemy `2.0.38` (`asyncpg==0.30.0`, `aiosqlite==0.21.0`), Alembic `1.14.1` (`0001_initial_schema`, `0002_postgres_rls_policies`) |
| **Cloud Connectors** | `cloud_connectors/aws/`, `cloud_connectors/azure/`, `packages/assessment/` | `boto3==1.36.26` (`10` AWS rules), `azure-identity==1.20.0` + `httpx==0.28.1` (`8` Azure ARM rules) |
| **Threat Detection & Compliance** | `detections/`, `compliance/`, `policies/opa/` | `9` CloudTrail / Azure Activity Log rules (MITRE ATT&CK), CIS AWS v3.0 / CIS Azure v2.1 / NIST CSF 2.0 / ISO 27001 YAML mappings, `3` OPA Rego v1 policies |
| **Reporting** | `apps/api/services/reporting_service.py` | JSON, CSV, and `fpdf2==2.9.0` PDF exports with regex redaction |

### 1.2 Baseline Test & CI/CD Inventory

- **Backend Automated Tests (`pytest`)**: `41 passed` (`tests/unit/`, `tests/integration/`, `tests/security/`).
- **Frontend Automated Tests (`vitest`)**: `8 passed` (`apps/web/src/App.test.tsx`).
- **Static Analysis & Vulnerability Checks**:
  - `ruff format --check` & `ruff check`: `0` issues across `64` Python files.
  - `mypy --strict`: `0` issues across `54` source files.
  - `bandit -r ... -ll`: `0` Medium/High issues.
  - `pip-audit --skip-editable`: `0` known vulnerabilities.
  - `npm audit --audit-level=high`: `0` vulnerabilities.
  - `opa test policies/opa -v` (OPA `1.0.1`): `4/4` passing.
  - `Trivy` (`aquasec/trivy:0.58.2` on `cloudsentinel-api:ci`): `0` fixable `HIGH`/`CRITICAL` findings.
- **Live Cloud Validation Status**: **`NOT_RUN`** — all automated tests execute against synthetic fixtures (`data_source="synthetic_fixture"`) or mocked `boto3`/`httpx` transports.

---

## 2. Functional Implementation vs. Stub Matrix

| Subsystem | Current State | Verification Category | Gap Summary |
| :--- | :--- | :--- | :--- |
| **Remediation Execution (`remediation_service.py`)** | **Stub / Simulated** | Synthetic / Local DB only | Marks requests `verified` and auto-resolves findings without executing any cloud API mutation or post-remediation reassessment. |
| **PostgreSQL Row-Level Security (`0002_postgres_rls_policies.py`)** | **Partial Defense-in-Depth** | Migration tested on table owner | Lacks `FORCE ROW LEVEL SECURITY`, lacks `WITH CHECK` on `INSERT`/`UPDATE`, runs app as table owner (which bypasses RLS), and sets `app.current_tenant_id` *after* querying `memberships`. |
| **Celery Assessment Worker (`apps/worker/celery_app.py`)** | **Stub** | Unit test on stub return dict | `dispatch_assessment` returns `{"status": "accepted"}` and does no work; `POST /api/v1/assessments` runs synchronous cloud collection inside the FastAPI event loop. |
| **OIDC Authentication (`packages/auth/oidc.py`, `LoginPage.tsx`)** | **Bearer Token Verifier Only** | Unit & integration tested | Backend verifies JWTs, but primary UI requires manual JWT copy-paste into `sessionStorage` and has an unguarded remote-host synthetic demo fallback. No OIDC Authorization Code + PKCE flow or `HttpOnly` session cookies. |
| **AWS Connector (`cloud_connectors/aws/connector.py`)** | **Functional Read-Only Collector** | Fixture + unit tested (`NOT_RUN` on live AWS) | Uses STS `AssumeRole`, paginators, and 10 rules, but hardcodes bucket region to `self.regions[0]`, swallows exceptions in `analyze_identities()`, and does not emit `ERROR`/`NOT_ASSESSED` result rows when a top-level service call fails. |
| **Azure Connector (`cloud_connectors/azure/connector.py`)** | **Functional Read-Only Collector** | Fixture + `httpx.MockTransport` (`NOT_RUN` on live Azure) | Uses `azure-identity` and paginated ARM calls, but `validate_connection()` only checks token acquisition (not subscription `Reader` access), lacks `429`/`5xx` retry backoff, and swallows exceptions in `analyze_identities()`. |
| **Detection Ingestion (`operations.py`, `detections/engine.py`)** | **Functional Rule Engine** | Fixture + integration tested | Trusts client-supplied `data_source="live"`, does not verify `account_ref` ownership in tenant, and lacks event-ID deduplication constraint. |
| **API Rate Limiting (`apps/api/core/middleware.py`)** | **Process-Local In-Memory** | Integration tested (single process) | Uses process-local `defaultdict(deque)` with unbounded key retention and flat route limits instead of shared Redis-backed rate limiting. |
| **CI/CD & Supply Chain (`.github/workflows/*.yml`)** | **Functional Pipeline** | Verified on GitHub Actions | Third-party actions use mutable major tags (`@v4`), Checkov uses `soft_fail: true`, `release.yml` only scans/SBOMs the `api` image, and `release_version` is not regex-validated. |

---

## 3. Verified Security & Engineering Findings

### Finding F-01 (P0 — CRITICAL): Unverified Remediation Execution & Premature Finding Resolution

- **Evidence Paths**:
  - [remediation_service.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/api/services/remediation_service.py#L165-L231)
  - [operations.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/api/api/v1/operations.py#L508-L554)
  - [models.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/db/models.py#L443-L477)
- **Verified Defect**:
  1. In `execute_remediation()` (`remediation_service.py:181-205`), when `confirm_live=True` and `settings.live_remediation_enabled=True`, the code sets `mode = "live_authorized"`, immediately sets `remediation.stage = "verified"`, and writes `"Executed using separate remediation credentials and verified"` **without calling any AWS or Azure API or re-evaluating the security rule**.
  2. On line 207 (`if mode == "live_authorized" or finding.data_source == "synthetic_fixture":`), the service automatically marks `finding.status = "resolved"`—meaning a dry-run (`confirm_live=False`) resolves synthetic findings, and a `confirm_live=True` flag resolves live findings with zero cloud mutation or read-back verification.
  3. There is no state machine separating `APPROVED`, `EXECUTING`, `EXECUTED_UNVERIFIED`, `VERIFYING`, `VERIFIED`, `FAILED`, `REJECTED`, `CANCELLED`, and `ROLLBACK_REQUIRED`, and no idempotency key or row lock (`SELECT ... FOR UPDATE`) to prevent concurrent duplicate execution.
- **Impact**: Violates the core **Proof Before Action** principle by fabricating remediation verification and resolving active security findings without proof that the cloud resource configuration changed.
- **Proposed Fix**:
  - Implement a strict remediation state machine (`DRAFT`, `PENDING_APPROVAL`, `APPROVED`, `EXECUTING`, `EXECUTED_UNVERIFIED`, `VERIFYING`, `VERIFIED`, `FAILED`, `REJECTED`, `CANCELLED`, `ROLLBACK_REQUIRED`).
  - Ensure dry-run simulation (`DRY_RUN_SIMULATED`) **never** resolves any finding (live or synthetic) and is never labeled `VERIFIED`.
  - Reject live execution (`confirm_live=True`) with an explicit `501 Not Implemented` / unsupported-action error until an allowlisted, action-specific provider executor and read-back reassessment verifier both succeed.
  - Require an idempotency key and row-level locking (`with_for_update()`) on state transitions.
- **Test Strategy**: Unit, integration, and negative security tests covering dry-run non-resolution, approval without execution, self-approval rejection, duplicate/concurrent execution, cross-tenant execution, failed mutation, and failed verification.
- **Owner Approval Required**: Schema migration adding state-machine, idempotency, and execution-evidence columns on `remediation_requests`.

---

### Finding F-02 (P0 — CRITICAL): Incomplete PostgreSQL RLS Enforcement & Bootstrap Lookup Ordering Bug

- **Evidence Paths**:
  - [0002_postgres_rls_policies.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/database/migrations/versions/0002_postgres_rls_policies.py#L40-L49)
  - [session.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/db/session.py#L36-L50)
  - [dependencies.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/auth/dependencies.py#L47-L76)
  - [docker-compose.yml](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/docker-compose.yml#L50)
- **Verified Defect**:
  1. `0002_postgres_rls_policies.py` runs `ALTER TABLE {table} ENABLE ROW LEVEL SECURITY` without `FORCE ROW LEVEL SECURITY` and defines `CREATE POLICY ... USING (...)` without an explicit `WITH CHECK (...)` clause for `INSERT`/`UPDATE`.
  2. The application connects as the `cloudsentinel` table owner/superuser in `docker-compose.yml` and CI. In PostgreSQL, table owners bypass RLS unless `FORCE ROW LEVEL SECURITY` is enabled and the runtime role lacks `BYPASSRLS` / `SUPERUSER`.
  3. In `packages/auth/dependencies.py:47-75`, `get_auth_context()` queries `select(User, Membership, Tenant)` on line 59 **before** calling `await set_postgres_tenant_context(session, tenant.id)` on line 75. Once `FORCE ROW LEVEL SECURITY` is enabled on `memberships`, line 59 will fail closed (returning 0 rows and `HTTP 403` for all users) unless `set_postgres_tenant_context(session, claims.tenant_id)` is called **prior** to querying `memberships`.
- **Impact**: If an application query ever omits a `.where(Model.tenant_id == auth.tenant_id)` filter, PostgreSQL RLS will not currently block cross-tenant reads/writes when running as the table owner.
- **Proposed Fix**:
  - Create migration `0003_hardened_rls_and_roles.py` enabling `FORCE ROW LEVEL SECURITY`, adding explicit `USING (...) WITH CHECK (...)` policies on all tenant-scoped tables, and provisioning a dedicated non-owner `cloudsentinel_app` role (`NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`).
  - Update `get_auth_context()` to bind transaction-local `app.current_tenant_id = str(claims.tenant_id)` **before** querying `memberships`, and clear/reset context on session checkout/return so pooled connections never leak tenant context.
- **Test Strategy**: Real PostgreSQL integration tests running under the non-owner `cloudsentinel_app` role verifying that unscoped `SELECT`, `INSERT`, `UPDATE`, and `DELETE` fail closed across tenants and that pooled sessions do not leak `app.current_tenant_id`.
- **Owner Approval Required**: Alembic migration `0003` and runtime DB role separation.

---

### Finding F-03 (P1 — HIGH): Synchronous Cloud Collection Inside Async API & Stub Celery Worker

- **Evidence Paths**:
  - [cspm.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/api/api/v1/cspm.py#L209-L226)
  - [assessment_service.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/api/services/assessment_service.py#L119-L143)
  - [celery_app.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/worker/celery_app.py#L46-L57)
- **Verified Defect**:
  1. `POST /api/v1/assessments` (`cspm.py:212`) synchronously invokes `execute_assessment_run()`, which runs synchronous `boto3` and `httpx.Client` calls inside the FastAPI event loop and returns `201 Created` only after the entire scan finishes.
  2. `apps/worker/celery_app.py:46-57` (`dispatch_assessment`) is a stub that returns `{"status": "accepted"}` without touching the database or running any connector.
  3. `GET /api/v1/identity/analysis` (`cspm.py:483`) also runs live connector collection synchronously on every GET request instead of reading persisted assessment/identity telemetry or running via a bounded worker thread/task.
- **Impact**: Live multi-region cloud assessments block the FastAPI event loop, risk HTTP gateway timeouts, and lack queue persistence, retry/backoff, concurrency guards, and crash recovery.
- **Proposed Fix**:
  - Implement persistent job orchestration (`QUEUED -> RUNNING -> COMPLETED | PARTIAL | FAILED | CANCELLED`) with `POST /api/v1/assessments` returning `202 Accepted` (plus optional synchronous/eager execution in `test` mode or via worker task execution).
  - Add `GET /api/v1/assessments/{id}/results` and `POST /api/v1/assessments/{id}/cancel`, per-connection concurrency locking (preventing overlapping runs on the same connection), bounded retries with backoff/jitter, and outbox/dispatch tracking.
- **Test Strategy**: Worker task execution tests, duplicate/concurrent dispatch tests, broker failure handling, timeout/crash recovery, and tenant isolation tests.
- **Owner Approval Required**: API status code change on `POST /api/v1/assessments` (`202 Accepted`) and assessment run lifecycle columns.

---

### Finding F-04 (P1 — HIGH): Manual JWT Paste Login UX, `sessionStorage` Token Exposure & Unguarded Preview Fallback

- **Evidence Paths**:
  - [LoginPage.tsx](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/web/src/pages/LoginPage.tsx#L34-L120)
  - [api.ts](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/web/src/lib/api.ts#L314-L347)
  - [oidc.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/auth/oidc.py#L31-L133)
- **Verified Defect**:
  1. The production login page has no OIDC Authorization Code + PKCE flow (`/api/v1/auth/oidc/authorize`, `/api/v1/auth/oidc/callback`, `/api/v1/auth/logout`), forcing users to paste raw JWT strings into `sessionStorage`.
  2. `apps/web/src/lib/api.ts:314-331` (`isRemoteStaticPreviewHost`) automatically returns `DEMO_ADMIN_TOKEN` on any non-localhost hostname when `VITE_API_BASE_URL` is unset, rather than requiring an explicit `VITE_ENABLE_DEMO_SANDBOX=true` environment flag.
- **Impact**: Storing bearer tokens in `sessionStorage` exposes them to XSS if a script injection occurs; unguarded remote demo fallback could mask a misconfigured deployment.
- **Proposed Fix**:
  - Implement OIDC Authorization Code Flow with PKCE (`state`, `nonce`, `code_challenge`/`code_verifier`), strict redirect URI allowlisting, and `HttpOnly; Secure; SameSite=Lax` BFF session cookie support (with CSRF header validation on state-changing requests) while retaining Bearer token support for API clients and gating synthetic demo mode strictly behind `VITE_ENABLE_DEMO_SANDBOX=true` / `development`/`test`.
- **Test Strategy**: Negative OIDC tests for invalid `state`, `nonce`, `PKCE`, expired session, callback replay, CSRF rejection, and production disabling of dev/demo login.

---

### Finding F-05 (P1 — HIGH): AWS Connector S3 Region Hardcoding, Silent Identity Failure & Unrecorded Service-Level `ERROR` Results

- **Evidence Paths**:
  - [cloud_connectors/aws/connector.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/cloud_connectors/aws/connector.py#L189-L240)
  - [cloud_connectors/aws/connector.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/cloud_connectors/aws/connector.py#L581-L590)
  - [operations.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/api/api/v1/operations.py#L241-L254)
- **Verified Defect**:
  1. `connector.py:231` assigns `"region": self.regions[0]` to every S3 bucket instead of resolving actual bucket location via `s3.get_bucket_location(Bucket=bname)`.
  2. When a top-level service call (`s3.list_buckets`, `ec2.describe_*`, `iam.list_*`) raises `ClientError` (`AccessDenied`), `connector.py:239,295,372` records `partial_failures` but emits **zero** `CheckEvaluation(status=CheckStatus.ERROR / NOT_ASSESSED)` items for the affected rules.
  3. `connector.py:587` (`analyze_identities`) catches `except Exception:` and returns an empty snapshot (`findings=[]`), disguising a failed IAM collection as a clean identity report.
  4. `operations.py:244` (`get_compliance_posture`) aggregates **all** `AssessmentResult` rows in the database across all historical runs rather than scoping to the latest completed run per connection.
  5. Deleted cloud assets leave previously opened `Finding` rows in `"open"` status indefinitely without stale-finding reconciliation.
- **Impact**: Partial permission failures can hide unassessed rules from the results table, and `analyze_identities()` violates Proof Before Action on collection error.
- **Proposed Fix**:
  - Resolve S3 bucket region via `get_bucket_location`.
  - Emit explicit `CheckStatus.NOT_ASSESSED` (on `AccessDenied`) or `CheckStatus.ERROR` (on transport/throttling error) `CheckEvaluation` records whenever a service collector fails.
  - Propagate collection errors and status in `IdentityAnalysisReport` (`collection_status="error"`, `errors=[...]`) instead of returning an empty pass-like report.
  - Scope compliance posture aggregation to the latest completed/partial assessment run per connection, and reconcile stale findings not seen in a full (non-partial) collection run.

---

### Finding F-06 (P1 — HIGH): Azure Connector Preflight Subscription Check, Retry Backoff & Identity Error Handling

- **Evidence Paths**:
  - [cloud_connectors/azure/connector.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/cloud_connectors/azure/connector.py#L105-L135)
  - [cloud_connectors/azure/connector.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/cloud_connectors/azure/connector.py#L394-L417)
  - [cloud_connectors/azure/connector.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/cloud_connectors/azure/connector.py#L563-L572)
- **Verified Defect**:
  1. `AzureConnector.validate_connection()` (`connector.py:394-405`) acquires an ARM token and immediately returns `valid=True` without querying `GET /subscriptions/{subscription_id}?api-version=2022-12-01` to verify the principal actually has `Reader` access on that subscription.
  2. `_arm_get_paginated()` (`connector.py:119-134`) lacks bounded retry/backoff for HTTP `429` (`Retry-After`) and `502/503/504`, and does not guard against duplicate/looping `nextLink` URLs.
  3. Service-level exceptions (`connector.py:185,209,243,296,319,333,351`) do not emit `NOT_ASSESSED` / `ERROR` `CheckEvaluation` rows, and `analyze_identities()` (`connector.py:569`) silently swallows exceptions.
- **Impact**: An Azure credential valid in Entra ID but lacking `Reader` role on the target subscription passes preflight validation (`healthy`), and transient ARM `429` throttling aborts collection immediately.
- **Proposed Fix**:
  - Verify subscription accessibility via `GET /subscriptions/{sub}?api-version=2022-12-01` during preflight validation.
  - Add bounded exponential backoff with `Retry-After` support and visited-URL cycle detection in `_arm_get_paginated()`.
  - Emit `NOT_ASSESSED` (HTTP 403) or `ERROR` (HTTP 5xx/timeout) `CheckEvaluation` rows when an ARM provider call fails, and surface errors explicitly in `analyze_identities()`.

---

### Finding F-07 (P1 — HIGH): Detection Ingestion Trusts Client `data_source`, Lacks Account Ownership Check & Event Deduplication

- **Evidence Paths**:
  - [operations.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/api/api/v1/operations.py#L56-L139)
  - [domain.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/contracts/domain.py#L115-L119)
  - [detections/engine.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/detections/engine.py#L158-L210)
  - [models.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/packages/db/models.py#L376-L408)
- **Verified Defect**:
  1. `POST /api/v1/detections/ingest` trusts client-supplied `payload.data_source` (`"live"` by default) without verifying provenance or requiring that the event's `account_ref` matches an active `CloudConnection` registered to the authenticated tenant.
  2. `DetectionEvent` has no `provider_event_id` column or unique constraint `(tenant_id, provider, provider_event_id, rule_id)`, allowing unlimited duplicate detections on replayed batches.
  3. `normalize_aws_cloudtrail_event` (`engine.py:162`) and `normalize_azure_activity_event` (`engine.py:192`) fall back to `datetime.now(UTC)` if `eventTime`/`eventTimestamp` is missing instead of rejecting malformed event schemas.
- **Impact**: Replay of an identical CloudTrail log batch duplicates detection alerts and inflates dashboard metrics; unverified manual API submissions can masquerade as `"live"` cloud telemetry.
- **Proposed Fix**:
  - Validate that each ingested event's `account_ref` belongs to a registered `CloudConnection` in the tenant (or tag manual API uploads without a verified connector signature as `api_ingested` / `synthetic_fixture`).
  - Require valid provider event IDs and timestamps, add `provider_event_id` + unique deduplication index on `detection_events`, and enforce idempotent skip-on-duplicate ingestion.

---

### Finding F-08 (P2 — MEDIUM): Process-Local Rate Limiting & Untrusted Proxy Header Handling

- **Evidence Paths**:
  - [middleware.py](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/apps/api/core/middleware.py#L81-L131)
- **Verified Defect**:
  - `RateLimitMiddleware` stores timestamps in an in-memory `defaultdict(deque)` per process, never evicts inactive keys, uses a single flat RPM limit across all routes, and lacks a shared Redis sliding-window implementation, request body size cap middleware, and explicit trusted-proxy CIDR configuration.
- **Proposed Fix**:
  - Implement a Redis-backed sliding-window / fixed-window atomic rate limiter with route-class tiers (`auth`, `ingest`, `mutations`, `read`), bounded local fallback cache with LRU eviction when Redis is unreachable, and a request body size limit middleware (`1 MB` default).

---

### Finding F-09 (P2 — MEDIUM): CI/CD Mutable Action Tags, Advisory Checkov Step & Partial Release Scanning

- **Evidence Paths**:
  - [ci.yml](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/.github/workflows/ci.yml#L44-L195)
  - [release.yml](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/.github/workflows/release.yml#L10-L83)
  - [cloud-lab-prowler.yml](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/.github/workflows/cloud-lab-prowler.yml#L18-L52)
- **Verified Defect**:
  1. Third-party actions in `.github/workflows/*.yml` use mutable version tags (`@v4`, `@v5`, `@v2`, `@v12`) instead of full 40-char commit SHAs.
  2. `semgrep/semgrep-action@v1` in `ci.yml:136` references an upstream archived repository.
  3. `ci.yml:166` sets `soft_fail: true` on Checkov instead of making Checkov blocking with explicit, documented `#checkov:skip=` annotations on intentional sandbox-cost trade-offs (such as cross-region replication on ephemeral lab buckets).
  4. `release.yml` only scans and generates an SBOM for the `api` image (omitting `worker` and `web`), grants workflow-wide `id-token: write`, and does not validate `inputs.release_version` against a strict SemVer regex.
  5. `cloud-lab-prowler.yml:45` ends with `|| true`, masking non-zero Prowler error codes.

---

### Finding F-10 (P2 — MEDIUM): Documentation Claims vs. Implementation Reality

- **Evidence Paths**:
  - [README.md](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/README.md)
  - [AGENTS.md](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/AGENTS.md)
  - [docs/SECURITY_MODEL.md](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/docs/SECURITY_MODEL.md)
- **Verified Defect**:
  - Documentation describes Celery worker assessment execution, PostgreSQL RLS isolation, and post-remediation verification as active production guarantees without documenting the gaps identified in `F-01`, `F-02`, and `F-03`, and without a formal `VALIDATION_MATRIX.md` distinguishing `PASS` (unit/mock/local integration) from `NOT_RUN` (live AWS/Azure cloud lab).

---

## 4. Owner Approval Gate (Phase 0 Stop Point)

Per **Operating Rule 7** and **Phase 0 Mandate**, no production code, database migrations, or external cloud resources have been modified during Phase 0.

Please review this audit and the accompanying [HARDENING_ROADMAP.md](file:///c:/Users/Arun%20G/Downloads/CLOUDSENTINEL/docs/implementation/HARDENING_ROADMAP.md) and confirm approval to proceed through **Phases 1–12** on branch `hardening/cloudsentinel-security-validation`.
