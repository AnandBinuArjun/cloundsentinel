# Backend Engineering Standards

1. **Runtime & Stack**
   - Target Python 3.12+ with strict type annotations (`mypy` clean) and `ruff` formatting/linting.
   - Use FastAPI, Pydantic v2 (`pydantic-settings` for environment config), SQLAlchemy 2 (async), Alembic, Celery, and Redis.

2. **API Design**
   - Version business endpoints under `/api/v1`.
   - Expose operational probes at `GET /health` (liveness) and `GET /ready` (real dependency readiness).
   - Include `X-Request-ID` on every response and bind it to structured JSON logs.
   - Implement pagination, deterministic filtering, consistent error payloads (`ErrorResponse`), and accurate OpenAPI schemas.

3. **Layered Architecture**
   - `apps/api/core/` — Configuration, logging, middleware, dependency probes, exception handlers.
   - `apps/api/api/v1/` — Thin route handlers delegating business logic to services.
   - `packages/contracts/` — Shared Pydantic request/response and domain event schemas.
   - `packages/common/` — Shared utilities (logging, redaction, time, IDs).
   - `apps/worker/` — Idempotent, tenant-scoped Celery background tasks with explicit timeouts and retries.

4. **Error & Dependency Handling**
   - Readiness probes and cloud connectors must use explicit timeouts and never swallow exceptions as healthy/pass states.
   - Avoid global mutable state; use FastAPI dependency injection so components are cleanly testable.
