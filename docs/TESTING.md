# Testing Strategy & Verification Evidence — CloudSentinel

**Status**: Implemented v1.0.0 — Full Automated Suite Active (`41` Python tests + `4` Vitest UI tests)

---

## 1. Test Pyramid & Suites

| Directory | Marker | Coverage | CI Execution |
| :--- | :--- | :--- | :--- |
| `tests/unit/` | `@pytest.mark.unit` | Settings, redaction, `CheckStatus`, worker `ping`, AWS/Azure rules & error handling, live Azure ARM pagination (`httpx.MockTransport`), OIDC JWKS SSRF guard, Postgres RLS migration & OPA/Prowler workflow checks, risk scoring, threat correlation, compliance evaluator, Compose/Dockerfile/workflow checks (`26` tests) | Every PR |
| `tests/integration/` | `@pytest.mark.integration` | `/health`, `/ready` (`200` & `503`), `/api/v1/system/info`, OpenAPI, and complete M1–M8 async SQLAlchemy lifecycle across connectors, assessments, findings, detections, compliance, JSON/CSV/PDF reports, remediation, and audit logs (`7` tests) | Every PR |
| `tests/security/` | `@pytest.mark.security` | Security headers, malformed `X-Request-ID` rejection, CORS enforcement, sanitized `500` errors, forged/expired/wrong-audience JWT rejection, cross-tenant access denial, RBAC privilege escalation denial, separation of duties, SQLi resilience, HTTP `429` rate limiting (`8` tests) | Every PR |
| `tests/cloud_lab/` | `@pytest.mark.cloud_lab` | Controlled AWS/Azure sandbox lab validation with cleanup verification | Manual / Isolated Sandbox Only |
| `apps/web/src/App.test.tsx` | Vitest | Live `/system` health + degraded `503`, dashboard summary & synthetic-fixture warning banner, `401` error state, OIDC `/login` form (`4` tests) | Every PR |

---

## 2. Synthetic Fixtures vs. Live Cloud Validation

- Public GitHub Actions CI runs strictly against **deterministic synthetic provider response fixtures** (`data_source="synthetic_fixture"`) and local service containers — **never** requiring live AWS or Azure credentials.
- Live cloud-lab validation must be executed manually against isolated sandbox accounts provisioned with `infrastructure/terraform/{aws,azure}/` and destroyed afterward per `CLEANUP_AND_BUDGET.md`.

---

## 3. Running Verification Locally

### Backend
```bash
ruff format --check apps packages cloud_connectors detections compliance tests database/seeds
ruff check apps packages cloud_connectors detections compliance tests database/seeds
mypy apps packages cloud_connectors detections compliance
pytest -v
python scripts/verify_local.py
```

### Frontend
```bash
cd apps/web
npm run typecheck
npm test
npm run build
```
