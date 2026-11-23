# Deployment Guide — CloudSentinel

**Status**: v1.0.0 Ready for Local Dev & Self-Hosted Containerized Deployment  
**Architecture**: Hybrid (Local Python/Node or Docker Compose, private self-hosted deployments, optional cloud-hosted control plane)

---

## 1. Local Development (Without Docker)

### Backend API
1. Copy `.env.example` to `.env` and configure `DATABASE_URL` (e.g., `sqlite+aiosqlite:///./cloudsentinel_local.db` for dockerless local testing, or PostgreSQL 16) and `CLOUDSENTINEL_DEV_JWT_SECRET`.
2. Create virtual environment and install pinned dependencies:
   ```bash
   python -m venv .venv
   pip install -e ".[dev]"
   ```
3. *(Optional, non-production only)* Seed explicitly labeled synthetic demonstration fixtures and print dev JWT tokens:
   ```bash
   python database/seeds/seed_demo_fixtures.py
   ```
4. Launch FastAPI:
   ```bash
   uvicorn apps.api.main:app --reload --port 8000
   ```
   - `GET /health` returns `200 OK`
   - `GET /ready` probes PostgreSQL and Redis honestly (returns `503 not_ready` if backing services are offline)

### Frontend Console
```bash
cd apps/web
npm install
npm run dev
```
Open `http://localhost:5173`, navigate to `/login`, and paste the JWT printed by the seed script (or issued by your OIDC provider).

---

## 2. Local Containerized Stack (Docker Compose)

Requires Docker Engine / Docker Desktop with Compose v2:

```bash
cp .env.example .env
docker compose config -q
docker compose up --build
```

Services defined in `docker-compose.yml` (all with `no-new-privileges:true` and non-root containers):
- `postgres` (`postgres:16-alpine`, `pg_isready` healthcheck, persistent volume)
- `redis` (`redis:7-alpine`, `redis-cli ping` healthcheck, persistent volume)
- `api` (`infrastructure/docker/Dockerfile.api`, non-root user `cloudsentinel`, port `127.0.0.1:8000`)
- `worker` (`infrastructure/docker/Dockerfile.worker`, non-root Celery worker)
- `web` (`infrastructure/docker/Dockerfile.web`, unprivileged `nginxinc/nginx-unprivileged:1.27-alpine`, port `127.0.0.1:5173`)

Apply PostgreSQL migrations after `postgres` is healthy:
```bash
alembic -c database/migrations/alembic.ini upgrade head
```

---

## 3. Production & Self-Hosted Hardening Checklist

1. **TLS & Reverse Proxy**: Terminate HTTPS with TLS 1.2+, HSTS, and strict `CLOUDSENTINEL_CORS_ORIGINS`.
2. **OIDC Configuration**: Set `CLOUDSENTINEL_ENV=production`, configure `OIDC_ISSUER_URL`, `OIDC_JWKS_URL`, and `OIDC_AUDIENCE`, and leave `CLOUDSENTINEL_DEV_JWT_SECRET` unset (HS256 dev tokens are automatically rejected in production).
3. **Secrets & Backups**: Inject `DATABASE_URL` and cloud secret references from AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault; enable encrypted PostgreSQL storage, automated daily snapshots + WAL archiving, and quarterly restore drills.
4. **Remediation Safety**: Keep `CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=false` unless an organization explicitly approves live remediation with a dedicated, isolated remediation IAM role (`CLOUDSENTINEL_REMEDIATION_AWS_ROLE_ARN`).
5. **Release Governance**: Use `.github/workflows/release.yml` (manual approval via `production-release` environment, Trivy scan, CycloneDX SBOM) after pinning third-party GitHub Actions to reviewed immutable commit SHAs.
