# CloudSentinel Production Deployment Runbook (Phase 12)

## 1. Prerequisites

- **PostgreSQL 16+** with two database roles:
  - `cloudsentinel_migrator`: privileged schema migration role used exclusively by `alembic upgrade head`.
  - `cloudsentinel_app`: runtime role created by migration `0003_security_hardening_schema` (`NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`).
- **Redis 7+** for Celery task brokering, result backend, and distributed rate limiting.
- **Enterprise OIDC Identity Provider** (Entra ID, Okta, Auth0, Keycloak) with HTTPS JWKS endpoint.

---

## 2. Mandatory Production Environment Variables

```bash
CLOUDSENTINEL_ENV=production
CLOUDSENTINEL_API_HOST=0.0.0.0
CLOUDSENTINEL_API_PORT=8000
CLOUDSENTINEL_CORS_ORIGINS=https://console.cloudsentinel.example.com
CLOUDSENTINEL_TRUSTED_PROXY_HOSTS=10.0.0.10
CLOUDSENTINEL_MAX_REQUEST_BODY_BYTES=1048576
CLOUDSENTINEL_RATE_LIMIT_RPM=120
CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=false

# Database & Redis
DATABASE_URL=postgresql+asyncpg://cloudsentinel_app:<RUNTIME_PASSWORD>@db.internal:5432/cloudsentinel
REDIS_URL=redis://redis.internal:6379/0
CELERY_BROKER_URL=redis://redis.internal:6379/1
CELERY_RESULT_BACKEND=redis://redis.internal:6379/2

# OIDC Authentication (HS256 dev secret MUST be empty in production)
OIDC_ISSUER_URL=https://idp.example.com/oauth2/default
OIDC_JWKS_URL=https://idp.example.com/oauth2/default/v1/keys
OIDC_AUDIENCE=cloudsentinel-api
CLOUDSENTINEL_DEV_JWT_SECRET=
```

---

## 3. Deployment Sequence

1. **Apply Database Migrations (using `cloudsentinel_migrator`)**:
   ```bash
   DATABASE_URL=postgresql+asyncpg://cloudsentinel_migrator:<MIGRATOR_PASSWORD>@db.internal:5432/cloudsentinel \
     alembic -c database/migrations/alembic.ini upgrade head
   ```
2. **Start Celery Worker**:
   ```bash
   celery -A apps.worker.celery_app:celery_app worker --loglevel=INFO --concurrency=4
   ```
3. **Start FastAPI Control Plane**:
   ```bash
   uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --workers 4
   ```
4. **Verify Health & Readiness Probes**:
   ```bash
   curl -fsS http://localhost:8000/health
   curl -fsS http://localhost:8000/ready
   ```
