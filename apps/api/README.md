# CloudSentinel Control Plane API (`apps/api`)

FastAPI async control plane exposing operational probes and versioned `/api/v1/*` REST endpoints.

## Structure
- `main.py` — Application factory (`create_app`), CORS, pure ASGI middleware, `/health`, `/ready`, and router wiring.
- `core/` — Bounded PostgreSQL/Redis readiness probes (`probes.py`), `RequestIdMiddleware`, `SecurityHeadersMiddleware`, `RateLimitMiddleware` (`middleware.py`), and sanitized global exception handlers (`exceptions.py`).
- `api/v1/` — Thin REST route modules (`system.py`, `dashboard.py`, `cspm.py`, `operations.py`) enforcing OIDC + RBAC dependencies.
- `services/` — Domain business logic enforcing service-layer RBAC and tenant isolation (`assessment_service.py`, `remediation_service.py`, `reporting_service.py`, `audit.py`).

## Run Locally
```bash
uvicorn apps.api.main:app --reload --port 8000
```

See [`docs/API_CONTRACTS.md`](../../docs/API_CONTRACTS.md) for full endpoint documentation.
