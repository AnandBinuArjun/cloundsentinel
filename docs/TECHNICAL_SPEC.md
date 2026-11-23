# Technical Specification — CloudSentinel

**Status**: Implemented v1.0.0 (Milestones 0–9 Complete)

---

## 1. Pinned Technology Stack

### Backend (`pyproject.toml`, Python 3.12+)
- **API Framework**: `fastapi==0.115.12`, `uvicorn[standard]==0.34.0`
- **Validation & Settings**: `pydantic==2.10.6`, `pydantic-settings==2.8.1`
- **Persistence & Migrations**: `sqlalchemy[asyncio]==2.0.38`, `asyncpg==0.30.0`, `aiosqlite==0.21.0`, `alembic==1.14.1`
- **Authentication & Crypto**: `PyJWT[crypto]==2.10.1`
- **Cloud SDKs**: `boto3==1.36.26`, `azure-identity==1.20.0`
- **Async Queue & Cache**: `celery==5.4.0`, `redis==5.2.1`
- **Reporting & HTTP**: `fpdf2==2.8.2`, `httpx==0.28.1`
- **Quality & Testing**: `pytest==8.3.5`, `pytest-asyncio==0.25.3`, `ruff==0.9.9`, `mypy==1.15.0`, `PyYAML==6.0.2`

### Frontend (`apps/web/package.json`)
- **Framework**: `react@19.0.0`, `react-dom@19.0.0`, `typescript@5.7.3` (`strict: true`), `vite@6.1.0`
- **Styling & Icons**: `tailwindcss@4.1.11`, `@tailwindcss/vite@4.1.11`, `lucide-react@0.475.0`
- **Data & Routing**: `@tanstack/react-query@5.66.0`, `react-router-dom@7.1.5`, `recharts@2.15.1`
- **Testing**: `vitest@3.0.5`, `@testing-library/react@16.2.0`, `@testing-library/jest-dom@6.6.3`, `jsdom@26.0.0`

### Infrastructure & Policy Tooling
- **Datastores**: PostgreSQL `16-alpine`, Redis `7-alpine`
- **Containers**: Multi-stage non-root Dockerfiles (`infrastructure/docker/`), `docker-compose.yml`
- **Policy & IaC**: OPA Rego (`policies/opa/*.rego`), isolated AWS & Azure Terraform labs (`infrastructure/terraform/{aws,azure}/`)
- **CI/CD**: GitHub Actions (`ci.yml`, `release.yml`) with Ruff, Mypy, Pytest, Vitest, Docker Compose validation, Gitleaks, Checkov, and Trivy + CycloneDX SBOM.

---

## 2. Configuration & Environment Variables (`packages/common/config.py`)

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `CLOUDSENTINEL_ENV` | `development` | `development`, `test`, `staging`, or `production` |
| `CLOUDSENTINEL_VERSION` | `1.0.0` | Build/release version surfaced in `/health` & `/api/v1/system/info` |
| `CLOUDSENTINEL_LOG_LEVEL` | `INFO` | Structured JSON log threshold (`DEBUG..CRITICAL`) |
| `CLOUDSENTINEL_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Explicit CORS allowlist (wildcards `*` stripped automatically) |
| `CLOUDSENTINEL_READINESS_TIMEOUT_SECONDS` | `2.0` | Bounded timeout per probe in `GET /ready` |
| `CLOUDSENTINEL_RATE_LIMIT_RPM` | `120` | Per-client sliding-window request limit per minute |
| `DATABASE_URL` | `postgresql+asyncpg://cloudsentinel@localhost:5432/cloudsentinel` | Async SQLAlchemy database URL |
| `REDIS_URL` / `CELERY_*` | `redis://localhost:6379/{0,1,2}` | Redis cache, Celery broker, and result backend |
| `OIDC_ISSUER_URL` / `OIDC_JWKS_URL` / `OIDC_AUDIENCE` | `https://auth.cloudsentinel.local` / `""` / `cloudsentinel-api` | OIDC JWT/JWKS validation parameters |
| `CLOUDSENTINEL_DEV_JWT_SECRET` | `""` | Local HS256 dev/test key (strictly disabled in `production`) |
| `CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED` | `false` | Master safety gate; must be `true` with separate role ARN for live remediation |
| `CLOUDSENTINEL_REMEDIATION_AWS_ROLE_ARN` | `""` | Separate remediation IAM role ARN (isolated from assessment role) |

---

## 3. Deterministic Assessment & Transparent Risk Scoring

### Canonical Check Outcomes (`packages/assessment/interface.py`)
- `PASS`: Verified against evidence and satisfies control.
- `FAIL`: Verified against evidence and violates control; upserts deduplicated `Finding` + redacted `Evidence`.
- `NOT_ASSESSED`: Control could not be evaluated (e.g., optional permission absent).
- `ERROR`: API call or evaluation failed; **never coerced to `PASS`**.

### Internal Risk Scoring Formula (`packages/assessment/risk.py`)
$$\text{score} = \min\Big(100,\; \max\big(0,\; (\text{severity\_base} + \text{exposure} + \text{criticality} + \text{privilege} + \text{exploitability} + \text{impact}) \times \text{confidence\_mult}\big)\Big)$$

- `severity_base`: Critical `45`, High `34`, Medium `22`, Low `10`
- `internet_exposure`: `+15` if publicly reachable, else `0`
- `asset_criticality`: High `+12`, Standard `+6`, Low `+2`
- `identity_privilege`: Admin `+16`, Elevated `+10`, Standard `+4`, None `0`
- `exploitability`: High `+7`, Moderate `+4`, Low `+1`
- `business_impact`: High `+5`, Moderate `+3`, Low `+1`
- `confidence_multiplier`: High `1.0`, Medium `0.9`, Low `0.75`
- Priority tiers: `P0 - Immediate` ($\ge 80$), `P1 - Urgent` ($\ge 60$), `P2 - Scheduled` ($\ge 35$), `P3 - Monitor` ($< 35$).
- **Disclaimer**: Returned inside every finding's `risk_explanation` stating this is an internally calculated prioritization score and not an externally certified industry standard.

---

## 4. Logging, Redaction & SSRF Guardrails

- **Structured JSON Logging (`packages/common/logging.py`)**: Single-line UTC JSON logs bound to `request_id_ctx`.
- **Recursive Redaction (`packages/common/redaction.py`)**: Masks sensitive dictionary keys (`password`, `secret`, `token`, `authorization`, `cookie`, `api_key`, `access_key`, `private_key`, `credential`, etc.) and inline credentials in URLs.
- **SSRF Validation (`packages/common/ssrf.py`)**: Enforces `https://` and blocks loopback (`127.0.0.1`, `::1`), link-local/cloud metadata (`169.254.169.254`, `metadata.azure.com`, `metadata.google.internal`), RFC1918 private ranges, and internal domain suffixes (`.local`, `.internal`, `.localhost`).
