# CloudSentinel Async Worker (`apps/worker`)

Celery background worker connected to Redis for asynchronous, tenant-scoped assessment dispatching and health verification.

## Tasks (`celery_app.py`)
- `cloudsentinel.system.ping` — Worker liveness/health verification task.
- `cloudsentinel.assessments.dispatch` — Tenant-scoped assessment dispatch entry point validating mandatory `tenant_id` and `connection_id` context before execution.

## Run Locally
```bash
celery -A apps.worker.celery_app:celery_app worker --loglevel=info
```
