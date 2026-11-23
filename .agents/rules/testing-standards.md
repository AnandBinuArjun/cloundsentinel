# Testing & Verification Standards

1. **Definition of Done**
   - No feature or milestone is complete until its unit, integration, and security tests are written, executed, and passing.
   - Always report the exact commands executed and observed results.

2. **Test Layers**
   - `tests/unit/` — Pure logic: config validation, security rules, provider normalization, risk scoring, evidence formatting, YAML/schema checks.
   - `tests/integration/` — API endpoints, database migrations, Redis/Celery lifecycle, dependency readiness/degraded behavior.
   - `tests/security/` — Cross-tenant access denial, RBAC/privilege escalation, invalid auth rejection, security headers, CORS enforcement, error/secret redaction, SSRF/injection defenses.
   - `tests/cloud_lab/` — Isolated AWS/Azure sandbox validation with documented cleanup. Never required for public CI.

3. **CI & Fixtures Policy**
   - Public GitHub Actions workflows MUST run using synthetic, deterministic provider response fixtures and never require production cloud credentials.
   - Live cloud validation must be clearly separated from fixture-based validation in both tests and documentation.
