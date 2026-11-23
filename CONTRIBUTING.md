# Contributing to CloudSentinel

Thank you for contributing to CloudSentinel. All contributors (human and AI agents) must follow [`AGENTS.md`](AGENTS.md) and the workspace standards under [`.agents/rules/`](.agents/rules/).

---

## Core Engineering Principles

1. **Proof Before Action**: Every security check must produce traceable, reproducible evidence and never coerce an API error or missing permission into `PASS`.
2. **Real Functionality Over Placeholders**: Implement backend logic, contracts, and tests before connecting UI controls. Explicitly label synthetic test/demo fixtures (`data_source="synthetic_fixture"`).
3. **Security-First**: Enforce RBAC at both route and service layers, derive `tenant_id` strictly from verified server-side authentication context, and add automated security tests for every security-sensitive change.

---

## Local Development Setup

```bash
cp .env.example .env
python -m venv .venv
# Activate .venv, then:
pip install -e ".[dev]"

cd apps/web
npm install
```

---

## Pull Request Checklist

Before opening a pull request, run and verify all checks pass locally:

- [ ] `ruff format --check apps packages cloud_connectors detections compliance tests database/seeds`
- [ ] `ruff check apps packages cloud_connectors detections compliance tests database/seeds`
- [ ] `mypy apps packages cloud_connectors detections compliance`
- [ ] `pytest -v` (unit, integration, and security suites)
- [ ] `python scripts/verify_local.py` (Docker Compose & GitHub Actions YAML validation)
- [ ] `npm --prefix apps/web run typecheck && npm --prefix apps/web test && npm --prefix apps/web run build`
- [ ] Updated relevant documentation in [`docs/`](docs/) and [`docs/CHANGELOG.md`](docs/CHANGELOG.md)
- [ ] Confirmed zero secrets, `.env` files, or `.db` artifacts are staged
