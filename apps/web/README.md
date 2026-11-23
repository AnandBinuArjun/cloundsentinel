# CloudSentinel Enterprise Web Console (`apps/web`)

16-page dark-enterprise React 19 + TypeScript + Vite + Tailwind CSS v4 security operations console wired exclusively to the FastAPI `/api/v1/*` control plane.

## Implemented Views (`src/pages/`)
- `/login` — OIDC Bearer token sign-in
- `/` — Overview Dashboard (real KPIs, Recharts severity chart, synthetic-fixture banner)
- `/connections` — AWS STS & Azure Managed/Workload Identity onboarding & preflight validation
- `/aws` & `/azure` — Provider-scoped posture views
- `/assets` — Searchable, filterable multi-cloud asset inventory
- `/findings` & `/findings/:id` — Risk-ranked findings list, expected vs. observed evidence viewer, risk acceptance workflow
- `/identity` — IAM & Azure RBAC risk review with explicit limitations
- `/detections` — CloudTrail & Azure Activity Log alerts mapped to MITRE ATT&CK
- `/compliance` — CIS AWS v3.0, CIS Azure v2.1, NIST CSF 2.0, ISO/IEC 27001:2022 coverage & limitations
- `/assessments` — Assessment history with PASS/FAIL/NOT_ASSESSED/ERROR counts
- `/remediations` — Preview-first remediation approval (separation of duties) & dry-run verification
- `/reports` — JSON, CSV, and PDF report exports with external-sharing redaction
- `/audit` & `/settings` — Immutable audit trail & verified OIDC/RBAC session view
- `/system` — Live `/health`, `/ready` (`200`/`503`), and `/api/v1/system/info` telemetry

## Commands
```bash
npm install
npm run dev
npm run typecheck
npm test
npm run build
```
