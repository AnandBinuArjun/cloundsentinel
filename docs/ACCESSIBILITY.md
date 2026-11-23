# CloudSentinel — Accessibility Specification (WCAG 2.2 AA Target)

## 1. Colour & Contrast
- Primary text `#F1F5F9` on `#080D14` canvas (**17.4:1** contrast) and `#111925` surface (**14.8:1** contrast) exceeds WCAG AAA.
- Secondary text `#A0AEC0` on `#111925` surface (**7.3:1** contrast) exceeds WCAG AA.
- Semantic status badges pair colour with explicit text labels and indicator dots — colour is never the sole carrier of meaning.

## 2. Keyboard Navigation & Focus Management
- **Skip Link**: First focusable element jumps directly to `#main-content`.
- **Command Palette (`Ctrl+K` / `Cmd+K`)**: Traps keyboard navigation (`ArrowUp`, `ArrowDown`, `Enter`, `Escape`) and restores focus on close.
- **Finding Details Drawer**: Supports `Escape` to dismiss, explicit close button with `aria-label`, and `role="dialog"` + `aria-modal="true"`.
- **Focus Rings**: Consistent `2px solid #00D6A0` `focus-visible` outlines on all interactive controls, table rows, and sidebar links.

## 3. Motion & Responsiveness
- All transitions honour `@media (prefers-reduced-motion: reduce)` by disabling smooth animations and pulse effects.
- Responsive breakpoints verified across Desktop (`>=1440px`), Laptop (`1024–1439px`), Tablet (`768–1023px`), and Mobile (`<768px`) with zero horizontal overflow in the application shell.

## 4. Semantic Landmarks & ARIA
- Explicit `<aside>`, `<nav aria-label="...">`, `<header>`, `<main id="main-content">`, and `<section aria-label="...">` landmarks.
- Error feedback uses `role="alert"`; loading feedback uses `aria-live="polite"`.
