# CloudSentinel — UI/UX Modernisation Implementation Plan

**Design Identity**: `CloudSentinel — Security Intelligence Workspace`  
**Constraint**: UI/UX modernisation only — zero backend rewrites, preserving all existing `/api/v1/*` contracts, OIDC auth, RBAC, tenant isolation, and provenance integrity.

---

## Phased Delivery Tracker

### Phase 1 — Frontend Inspection & UI Audit *(Completed)*
- [x] Inspect routes, API client (`apps/web/src/lib/api.ts`), state management (TanStack Query), components, and Tailwind v4 config
- [x] Audit baseline UI gaps and document redesigned Information Architecture in `docs/UX_ARCHITECTURE.md`
- [x] Author `docs/UI_DESIGN_SYSTEM.md`, `docs/COMPONENT_LIBRARY.md`, `docs/ACCESSIBILITY.md`, and `docs/UI_IMPLEMENTATION_PLAN.md`

### Phase 2 — Design Tokens, Typography & Shared Components *(Completed)*
- [x] Implement semantic CSS variables (`#080D14`, `#0C121B`, `#111925`, `#172131`, `#1C293A`, `#243142`, `#00D6A0`)
- [x] Load `Manrope` (primary) and `JetBrains Mono` (monospace) fonts with `prefers-reduced-motion` support
- [x] Build modular component primitives (`MetricCard`, `Badges`, `ComplianceProgress`, `CommandPalette`, `FindingDetailsDrawer`)

### Phase 3 — Application Shell Redesign *(Completed)*
- [x] Collapsible `Sidebar` (256px ↔ 72px) with tooltips in collapsed mode, 5 navigation groups, read-only status, live connector health, and user profile footer
- [x] Persistent `Topbar` with breadcrumbs, global search / `Ctrl+K` shortcut, honest notifications popover, data freshness indicator, tenant ID badge, and profile menu
- [x] Mobile drawer, skip-to-content link, and keyboard accessibility

### Phase 4 — Security Overview Dashboard Redesign *(Completed)*
- [x] Page header with environment selector, date range filter, Refresh, and RBAC-gated **Run Assessment** control
- [x] 6-card KPI summary grid (Cloud Environments, Discovered Assets, Open Findings, Critical Risks, Active Detections, Compliance Coverage)
- [x] Cloud Security Posture comparison cards (AWS vs. Azure)
- [x] Risk Intelligence panels (Severity chart, Top affected asset categories, Highest-priority findings)
- [x] Interactive Security Findings table (search, filter, sort, pagination, row selection) + slide-over `FindingDetailsDrawer`
- [x] Threat Detection activity panel & Compliance technical control coverage panel

### Phase 5 — Dedicated AWS & Azure Workspaces & Cloud Connections *(Completed)*
- [x] Purpose-built **AWS Security Workspace** (`/aws`, `CloudEnvironmentPage.tsx`): account overview, active regions, IAM/S3/EC2-VPC/CloudTrail/RDS service security posture breakdown, interactive findings table + `FindingDetailsDrawer`, recent AWS assessment runs, and CloudTrail detections
- [x] Purpose-built **Azure Security Workspace** (`/azure`, `CloudEnvironmentPage.tsx`): subscription overview, regions, Entra-RBAC/Storage/NSG/KeyVault-Diagnostics/Compute service posture breakdown, interactive findings table + `FindingDetailsDrawer`, recent Azure assessment runs, and Activity Log detections
- [x] Redesigned **Cloud Connections** (`/connections`, `ConnectionsPage.tsx`): connector KPIs, AWS STS vs. Azure Managed Identity provider switcher, least-privilege permission manifest notice, RBAC-gated registration/validation/assessment actions

### Phase 6 — Investigation & Security Posture Pages *(Completed)*
- [x] Redesigned **Asset Inventory** (`/assets`, `AssetsPage.tsx`): KPI summary, provider/type filters, and slide-over `AssetDetailDrawer` with canonical IDs and tags
- [x] Redesigned **Security Findings** (`/findings`, `FindingsPage.tsx`): severity filter chips, sortable/paginated table, and click-to-open `FindingDetailsDrawer` + full-page link
- [x] Redesigned **Finding Detail** (`/findings/:id`, `FindingDetailPage.tsx`): risk factor breakdown, side-by-side Expected vs. Observed JSON evidence, RBAC-gated remediation preview, immutable disposition form, and lifecycle history
- [x] Redesigned **Identity & Access Security** (`/identity`, `IdentityPage.tsx`): KPI summary, provider filter, explicit effective-permission limitations callout, and expandable evidence payloads
- [x] Redesigned **Threat Detection** (`/detections`, `DetectionsPage.tsx`): SOC triage KPIs, search/provider/disposition filters, MITRE ATT&CK chips, 30-minute actor correlation metadata, and analyst disposition actions

### Phase 7 — Governance, Response & Platform Pages *(Completed)*
- [x] Redesigned **Compliance Centre** (`/compliance`, `CompliancePage.tsx`): non-certification notice, KPI summary, framework tabs, status filter, segmented `ComplianceProgress` bars
- [x] Redesigned **Assessment History** (`/assessments`, `AssessmentsPage.tsx`): run KPIs, provider filter, PASS/FAIL/NA/ERR telemetry, expandable partial failure warnings
- [x] Redesigned **Remediation Centre** (`/remediations`, `RemediationPage.tsx`): KPIs, Separation of Duties banner, stage filter, expandable Proposal & Impact Analysis diffs, RBAC-gated Approve/Reject/Execute controls
- [x] Redesigned **Reports & Evidence** (`/reports`, `ReportsPage.tsx`): interactive report package selector cards, PDF/CSV/JSON export, external-sharing redaction toggle, provenance checklist
- [x] Redesigned **Audit Logs**, **Settings**, **Login**, and **Control Plane Status** (`/audit`, `/settings`, `/login`, `/system`)

### Phase 8 — Accessibility Audit, Responsive Polish & Full Verification *(Completed)*
- [x] Verified semantic tokens across all 16 routes (zero legacy `#090C10`/`#0F141A`/`#1E2733` hex mismatches remaining)
- [x] Verified WCAG 2.2 AA landmarks, `role="dialog"`, `role="alert"`, `role="status"`, `Escape` modal dismissal, focus-visible `#00D6A0` outlines, and `prefers-reduced-motion` support
- [x] Expanded Vitest integration/UI test suite (`apps/web/src/App.test.tsx`) covering System Status, Overview + Command Palette, AWS & Azure Workspaces, Findings & Assets drawers, Compliance & Remediation workflows, 401 handling, Login, and collapsible Sidebar
- [x] Verified TypeScript strict check (`tsc --noEmit`), Vitest suite, and production bundle build (`tsc -b && vite build`)
