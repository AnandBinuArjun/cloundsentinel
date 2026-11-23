# API Contracts — CloudSentinel

**Status**: Implemented v1.0.0 (All Endpoints Live in FastAPI OpenAPI `/openapi.json`)  
**API Prefix**: `/api/v1` (operational probes at `/health` and `/ready`)  
**Authentication**: `Authorization: Bearer <OIDC_JWT>` on all `/api/v1/*` business endpoints (server resolves verified `tenant_id` and RBAC `role` from `memberships`).  
**Request Correlation**: Every response echoes a validated or generated `X-Request-ID`.

---

## 1. Operational & System Endpoints

| Endpoint | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/health` | `GET` | None | Process liveness probe (`200 OK`) |
| `/ready` | `GET` | None | Real bounded-timeout PostgreSQL + Redis probes (`200 ready` or `503 not_ready`) |
| `/api/v1/system/info` | `GET` | None | Non-sensitive product metadata, `default_mode: "read_only"`, active capability flags |
| `/api/v1/auth/me` | `GET` | Bearer JWT | Returns verified `user_id`, `tenant_id`, `email`, `role`, and granted `permissions` |

---

## 2. Dashboard, Connectors, Assets & Assessments

| Endpoint | Method | Required Permission | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/dashboard/summary` | `GET` | `findings:read` | Tenant-scoped multi-cloud posture summary (`?provider=aws\|azure`), includes `data_sources` and `contains_synthetic_fixtures` |
| `/api/v1/connections` | `GET` | `connections:read` | List tenant AWS & Azure cloud connectors (`?provider=`) |
| `/api/v1/connections` | `POST` | `connections:write` | Register AWS STS or Azure Managed/Workload Identity connector (rejects `:root` ARNs) |
| `/api/v1/connections/{id}/validate` | `POST` | `connections:write` | Execute read-only identity & permission preflight check |
| `/api/v1/assets` | `GET` | `assets:read` | Paginated, filtered cloud asset inventory (`provider`, `resource_type`, `region`, `search`, `limit`, `offset`) |
| `/api/v1/assets/{id}` | `GET` | `assets:read` | Detailed metadata for a single tenant-owned asset |
| `/api/v1/assessments` | `POST` | `assessments:run` | Run asset discovery + deterministic rules for a connection |
| `/api/v1/assessments` | `GET` | `assessments:read` | Paginated assessment run history with PASS/FAIL/NOT_ASSESSED/ERROR & partial failure counts |
| `/api/v1/assessments/{id}` | `GET` | `assessments:read` | Detailed status for a single assessment run |

---

## 3. Findings, Identity Analysis & Threat Detection

| Endpoint | Method | Required Permission | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/findings` | `GET` | `findings:read` | Risk-ranked paginated findings (`provider`, `severity`, `status`, `region`, `search`) |
| `/api/v1/findings/{id}` | `GET` | `findings:read` | Full finding detail, expected vs. observed redacted evidence snapshots, and lifecycle history |
| `/api/v1/findings/{id}` | `PATCH` | `findings:write` | Update status (`open`, `resolved`, `risk_accepted`, `false_positive`) with mandatory justification |
| `/api/v1/identity/analysis` | `GET` | `findings:read` | IAM & Azure RBAC risk analysis across tenant connections with explicit `limitations` |
| `/api/v1/detections/ingest` | `POST` | `detections:write` | Normalize & evaluate AWS CloudTrail or Azure Activity Log events with 30m actor correlation |
| `/api/v1/detections` | `GET` | `detections:read` | List MITRE ATT&CK-mapped detections (`provider`, `severity`, `disposition`) |
| `/api/v1/detections/{id}` | `GET` | `detections:read` | Single detection detail with correlated event IDs and evidence |
| `/api/v1/detections/{id}` | `PATCH` | `detections:write` | Record disposition (`open`, `true_positive`, `false_positive`, `resolved`) and reason |

---

## 4. Compliance, Reports, Remediation & Audit Logs

| Endpoint | Method | Required Permission | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/compliance` | `GET` | `compliance:read` | CIS AWS v3.0, CIS Azure v2.1, NIST CSF 2.0, ISO/IEC 27001:2022 posture & mandatory limitations (`?framework_id=`) |
| `/api/v1/reports` | `GET` | `reports:export` | Export `posture`, `assessment`, `vulnerability`, `identity`, `compliance`, `remediation`, or `threat_detection` reports as `json`, `csv`, or `pdf` (`?redact=true\|false`) |
| `/api/v1/remediations` | `GET` | `findings:read` | List remediation requests and stages |
| `/api/v1/remediations/preview` | `POST` | `remediations:preview` | Generate dry-run remediation proposal, blast-radius impact analysis, and rollback guidance |
| `/api/v1/remediations/{id}/approve` | `POST` | `remediations:approve` | Approve or reject previewed remediation; **blocks self-approval** (`403`) |
| `/api/v1/remediations/{id}/execute` | `POST` | `remediations:execute` | Execute approved remediation in `dry_run_verified` mode by default (`confirm_live=true` blocked unless live remediation + separate role enabled) |
| `/api/v1/audit-events` | `GET` | `audit:read` | Paginated immutable tenant audit trail (`?action=`, `limit`, `offset`) |

---

## 5. Standard Error Contract (`ErrorResponse`)

All `4xx`/`5xx` responses (including `429` rate limit and unhandled `500`) return sanitized JSON without stack traces or credentials:

```json
{
  "error": {
    "code": "http_403",
    "message": "Separation of duties violation: the proposer cannot approve their own remediation.",
    "request_id": "2c8b28d4-9e76-48e4-9b7a-58e91068a14c"
  }
}
```
