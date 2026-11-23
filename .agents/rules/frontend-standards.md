# Frontend Engineering Standards

1. **Visual Direction: Dark Enterprise**
   - Dark graphite background (`#0B0E11`), near-black elevated surfaces (`#11161C` / `#161D26`), subtle structural borders (`#242E3B`), restrained emerald accent (`#10B981`), neutral grey secondary text (`#94A3B8`).
   - Clear, consistent severity indicators (`apps/web/src/components/Badges.tsx`): Critical (red), High (orange), Medium (amber), Low (sky), Healthy/Pass/Verified (emerald).
   - Avoid excessive neon, decorative gradients, busy animations, glassmorphism clutter, or fake alert banners.

2. **Data Integrity & State Handling**
   - **Never render fabricated security findings, fake posture scores, or decorative charts disconnected from backend APIs.**
   - Every API-backed view in `apps/web/src/pages/` must explicitly handle **loading**, **empty**, **error**, **partial/degraded**, and **populated** states.
   - Clearly distinguish `synthetic_fixture` data from `live` cloud assessments using `DataSourceBadge` and dashboard warning banners.

3. **Architecture & Accessibility**
   - React 19 + TypeScript (strict mode) + Vite 6 + Tailwind CSS 4 + TanStack Query 5 + React Router 7 + Lucide icons + Recharts.
   - Keep cloud credentials completely out of frontend state, storage, and source code (session Bearer OIDC JWT only).
   - Ensure accessible contrast ratios, semantic HTML landmarks, and keyboard navigation on all interactive controls.
   - Every button must perform a real action or be visibly disabled with an explicit reason.
