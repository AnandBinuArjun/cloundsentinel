# CloudSentinel — UI Design System (`Security Intelligence Workspace`)

**Version**: 2.0 (Enterprise UI/UX Modernisation)  
**Design Direction**: Precise, technical, restrained dark cybersecurity operations workspace inspired by Linear, Microsoft Defender, Wiz, Grafana, and Vercel.

---

## 1. Semantic Colour Tokens (`apps/web/src/styles/tokens.css`)

### Surfaces & Borders
| Token | Hex | Usage |
| :--- | :--- | :--- |
| `--cs-bg-canvas` | `#080D14` | Root application viewport background |
| `--cs-bg-sidebar` | `#0C121B` | Left navigation rail & mobile drawer |
| `--cs-bg-surface` | `#111925` | Primary cards, panels, tables, popovers |
| `--cs-bg-elevated` | `#172131` | Table headers, nested evidence blocks, active pills |
| `--cs-bg-hover` | `#1C293A` | Interactive row hover, menu item hover |
| `--cs-border` | `#243142` | Crisp 1px structural dividers & card outlines |

### Typography & Brand Accent
| Token | Hex | Usage |
| :--- | :--- | :--- |
| `--cs-text-primary` | `#F1F5F9` | Headings, KPI figures, table primary cells |
| `--cs-text-secondary` | `#A0AEC0` | Descriptions, labels, secondary metadata |
| `--cs-text-muted` | `#64748B` | Group headings, timestamps, helper hints |
| `--cs-accent` | `#00D6A0` | Primary active indicator, interactive CTA focus |

### Semantic Security Status Colours
Severity colours are strictly reserved for communicating real security posture and operational health:

| Semantic Role | Token | Hex |
| :--- | :--- | :--- |
| Success / Pass / Healthy / Live | `--cs-success` | `#10B981` |
| Information / Low / Azure cue | `--cs-info` | `#38BDF8` |
| Warning / Medium / Synthetic / Partial | `--cs-warning` | `#F59E0B` |
| High Severity | `--cs-high` | `#F97316` |
| Critical Severity / Fail / Error | `--cs-critical` | `#F43F5E` |
| Neutral / Not Assessed | `--cs-neutral` | `#94A3B8` |

---

## 2. Typography & Geometry

- **Primary Sans**: `Manrope` (weights 400, 500, 600, 700)
- **Technical Monospace**: `JetBrains Mono` (weights 400, 500, 600) for ARNs, subscription UUIDs, rule IDs, timestamps, JSON diffs, and tabular KPI numerals (`font-variant-numeric: tabular-nums`).
- **Spacing Rhythm**: 8px grid (`4px`, `8px`, `12px`, `16px`, `24px`, `32px`).
- **Corner Radii**: Cards `12px` (`--cs-radius-card`), Inputs & Buttons `8px` (`--cs-radius-control`).
- **Borders & Elevation**: Subtle `1px solid var(--cs-border)` with restrained shadows (`0 1px 2px rgba(0, 0, 0, 0.35)`). Large neon glows and decorative gradients are prohibited.

---

## 3. Data Provenance Badges

Every data surface communicates trustworthiness using distinct badges:
- `LIVE` — Verified live cloud provider assessment
- `SYNTHETIC` — Explicitly labeled synthetic test/demonstration fixture (`data_source="synthetic_fixture"`)
- `PARTIAL` — Assessment completed with one or more partial collection warnings
- `STALE` — Data refreshed beyond freshness threshold
- `NOT ASSESSED` — Control skipped or optional permissions unavailable
- `ERROR` — Provider API failure (never coerced to `PASS`)
