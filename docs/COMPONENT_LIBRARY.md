# CloudSentinel — Reusable Component Library

Location: `apps/web/src/components/`

| Component | File | Purpose & Key States |
| :--- | :--- | :--- |
| `AppShell` | `layout/AppShell.tsx` | Responsive shell orchestrating collapsible `Sidebar`, sticky `Topbar`, `CommandPalette`, mobile drawer, and skip-to-content landmark |
| `Sidebar` | `layout/Sidebar.tsx` | 256px expanded / 72px collapsed rail, 5 navigation groups, collapsed hover tooltips, read-only status, live connector health indicator, and user profile footer |
| `Topbar` | `layout/Topbar.tsx` | Dynamic breadcrumbs, workspace pill, global search / `Ctrl+K` trigger, honest operational notifications popover, data freshness status, current tenant ID, and user profile menu |
| `CommandPalette` | `ui/CommandPalette.tsx` | Keyboard-accessible (`Ctrl/Cmd+K`, Arrow keys, Enter, Escape) quick navigation & action launcher |
| `PageHeader` | `ui/Primitives.tsx` | Consistent heading, subtitle, eyebrow, and right-aligned operational controls |
| `MetricCard` | `ui/MetricCard.tsx` | Compact KPI tile with tabular primary figure, explanatory label, semantic icon, optional last-updated timestamp, and click-through route |
| `SeverityBadge` | `ui/Badges.tsx` | Semantic dot + uppercase label (`critical`, `high`, `medium`, `low`) |
| `ProviderBadge` | `ui/Badges.tsx` | Compact `AWS` / `Azure` indicator respecting global dark design language |
| `DataSourceBadge` | `ui/Badges.tsx` | Distinct `LIVE`, `SYNTHETIC`, `PARTIAL`, `STALE`, `NOT ASSESSED`, and `ERROR` provenance badges |
| `ConnectorStatus` | `ui/Badges.tsx` | Healthy / Degraded / Pending connector indicator dot + label |
| `RiskIndicator` | `ui/Badges.tsx` | Numeric 0–100 score + colour-coded compact progress gauge |
| `ChartPanel` | `ui/Primitives.tsx` | Standard 12px-radius `#111925` panel with crisp header, subtitle, and optional header action |
| `FilterToolbar` | `ui/Primitives.tsx` | Unified search + select filter bar with clear/reset action |
| `FindingDetailsDrawer` | `features/findings/FindingDetailsDrawer.tsx` | Accessible right-side slide-over drawer fetching `/api/v1/findings/{id}` with executive summary, observed vs. expected evidence viewer, risk factors, compliance controls, remediation guidance, and lifecycle history |
| `EvidenceViewer` | `features/findings/EvidenceViewer.tsx` | Side-by-side redacted JSON diff block (Expected Secure Config vs. Observed Config) |
| `ComplianceProgress` | `ui/ComplianceProgress.tsx` | Segmented horizontal progress bar distinguishing Passed, Failed, Not Assessed, and Error counts |
| `EmptyState`, `ErrorState`, `SkeletonLoader` | `ui/Primitives.tsx` | Explicit non-blocking loading skeletons, actionable empty states, and accessible `role="alert"` error banners |
| `Toast` | `ui/Toast.tsx` | Non-intrusive bottom-right status notifications with dismiss button |
