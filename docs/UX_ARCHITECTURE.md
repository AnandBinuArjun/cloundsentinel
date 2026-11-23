# CloudSentinel — UX & Information Architecture

## 1. Baseline UI Audit (Pre-Redesign Findings)

Inspecting the initial v1.0 functional frontend identified the following UX gaps:
1. **Navigation Ergonomics**: The left sidebar was fixed at `256px` with no collapse toggle, no collapsed tooltips, and no quick keyboard command interface (`Ctrl/Cmd+K`) for SOC analysts switching between investigations.
2. **Topbar Operational Context**: The header lacked route breadcrumbs, tenant ID display, data freshness timestamp, global search trigger, and an honest operational notification popover.
3. **Overview Dashboard Depth**: The Overview screen had 4 KPI cards and a single severity chart, missing:
   - Environment selector, date-range filter, refresh action, and RBAC-gated **Run Assessment** button in the page header.
   - 6-metric executive KPI grid (adding Critical Risks and Compliance Coverage).
   - Dedicated AWS vs. Azure cloud posture comparison cards.
   - Risk intelligence breakdown (risk by provider, top affected asset categories, highest-priority findings).
   - Embedded interactive Security Findings table with search/filter/sort/pagination and a slide-over **FindingDetailsDrawer** for rapid evidence triage without leaving the dashboard.
   - Threat Detection activity panel alongside Compliance coverage.
4. **Design System Consistency**: Palette values were hardcoded across pages instead of centralized semantic CSS variables (`#080D14` canvas, `#0C121B` sidebar, `#111925` surface, `#00D6A0` accent, `Manrope` typography).

---

## 2. Redesigned Information Architecture

```text
CloudSentinel — Security Intelligence Workspace
├── WORKSPACE
│   ├── Overview                  (/)              [Phase 4 — Active]
│   ├── AWS Environment           (/aws)           [Phase 5]
│   ├── Azure Environment         (/azure)         [Phase 5]
│   └── Cloud Connections         (/connections)   [Phase 5]
├── SECURITY POSTURE
│   ├── Asset Inventory           (/assets)        [Phase 6]
│   ├── Security Findings         (/findings)      [Phase 6]
│   └── Identity & Access         (/identity)      [Phase 6]
├── DETECTION & GOVERNANCE
│   ├── Threat Detection          (/detections)    [Phase 6]
│   ├── Compliance Centre         (/compliance)    [Phase 6]
│   └── Assessment History        (/assessments)   [Phase 6]
├── RESPONSE
│   ├── Remediation Centre        (/remediations)  [Phase 6]
│   └── Reports & Evidence        (/reports)       [Phase 6]
└── PLATFORM
    ├── Settings                  (/settings)      [Phase 6]
    ├── Audit Logs                (/audit)         [Phase 6]
    └── System Health             (/system)        [Phase 6]
```

> **Honesty Rule**: `Attack Paths` and `On-Prem Posture` are intentionally omitted from primary navigation and posture grids because no backend attack-path graph or on-prem collector API currently exists.

---

## 3. Analyst Investigation Flow

1. **Triage on Overview (`/`)**: Filter by environment (`All` / `AWS` / `Azure`), inspect 6 KPIs, compare AWS vs. Azure posture, and scan highest-priority findings.
2. **In-Place Evidence Drawer**: Click any row in the Security Findings table to open the right-side `FindingDetailsDrawer` showing expected vs. observed evidence, risk factors, compliance mappings, and remediation preview without losing dashboard scroll position.
3. **Keyboard-First Switching**: Press `Ctrl+K` / `Cmd+K` from anywhere to jump directly to any module or search findings/pages.
