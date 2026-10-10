# Aegis Console — Design System & Component Guide ("Meridian")

> **Anchor doc for AI-assisted UI work.** Reference this file in every UI prompt
> (e.g. "Follow `web/Components.md`"). Never hand-write raw hex colors, ad-hoc
> spacing, or new one-off components. Reuse the tokens and primitives below.

**Principles:** neutral canvas, white surfaces, one blue accent. Status colour appears only where state is
communicated. Hierarchy comes from size, weight and space, not colour. Use hairlines instead of boxes, quiet
elevation, and no gradients. Every widget answers *what happened, why it matters, what to do*.

---

## 1. Stack

- **React 19** + **TypeScript** (strict) + **Vite 7**
- **Tailwind CSS v4**, configured in `src/index.css` via `@theme` (there is no `tailwind.config.js`)
- **React Router 7** (`react-router`), **TanStack Query v5** for all server state (`src/lib/queries.ts`)
- **Radix** via shadcn wrappers in `src/components/shadcn/`: `dialog`, `dropdown-menu`, `tooltip`. The search
  palette uses **cmdk**.
- **lucide-react** for every icon (global stroke 1.75)
- Fonts are self-hosted with Fontsource, imported in `main.tsx`: **Inter Variable** for UI and
  **JetBrains Mono Variable** for IDs, hashes and JSON. There is no third-party font CDN.
- Entry: `src/main.tsx` → `components/Layout.tsx` → a page under `src/pages/*`. The landing page is
  `/overview` for staff and `/assistant` for customers.

---

## 2. Colour tokens (semantic roles, never raw hex)

Light values sit on `:root, [data-theme="light"]`, dark values on `[data-theme="dark"]`.
`index.html` applies the saved theme before first paint, and `src/lib/theme.ts` provides `useTheme()`.

| Class | Role |
|---|---|
| `bg-page` / `bg-panel` | Canvas. The sidebar and header sit on the canvas. |
| `bg-card` | Cards, menus, dialogs |
| `bg-inset` | Wells, code/JSON, segmented-control track |
| `bg-hover` / `bg-selected` | Hover wash / active nav item, neutral badge |
| `bg-overlay` | Dialog scrim |
| `text-fg` | Primary text |
| `text-muted` | Secondary text, and **all information-bearing meta** (timestamps, captions, hints) |
| `text-faint` | Icons, placeholders, separators, disabled only. **Never information-bearing text** (fails AA). |
| `border-line` / `border-line-strong` | Hairline / input border |
| `bg-accent` `text-accent` `bg-accent-soft` `text-on-accent` | The one brand accent (blue). Primary action, links, focus. |
| `bg-series` | Chart slot 1 / info |
| `bg-chart-muted` | De-emphasised chart marks (routine volume) |

**Status scale** (fixed meaning, never decoration): `good` → `warning` → `serious` → `critical`. Each has a fill
(`bg-good`, …) and an ink for text (`text-good-ink`, …); `text-info-ink` covers info. `serious` (orange) is only
for **High** severity and rate-limited.

> **Accessibility rule:** status always carries a **text label**. Colour (a dot or tint) only reinforces it.

---

## 3. Type, spacing, radius, elevation

- **Type:**
  - Page title: 24/32 semibold, tracking −0.02em (`PageHeader`).
  - Card title: 14 semibold.
  - Body: 14.
  - Meta: `text-caption` (13/18) in `text-muted`.
  - Table header: 12 medium muted, **sentence case**.
  - Sidebar section label: `text-2xs` uppercase.
  - Stat value: `text-3xl` semibold.
- **Numbers:** proportional figures for big stand-alone values. Use `tabular` only for table columns and axis
  ticks.
- **Radius:** controls `rounded-lg`, cards `rounded-xl`, dialogs `rounded-2xl`. Never `rounded-3xl`.
- **Elevation:** `shadow-card` (default), `shadow-pop` (hover/raised), `shadow-overlay` (menus, dialogs,
  toasts). Never Tailwind's `shadow-lg/xl/2xl`.
- **Spacing:**
  - Page gutter: `px-4 sm:px-6 lg:px-10`.
  - Section gap: `gap-6` / `mb-6`.
  - Card padding: `p-5`.
  - Header-to-content: `mb-8`.
- **Layering:** dialogs `z-40`, menus and tooltips `z-50`, toasts `z-[60]`.
- **Motion:** 150ms colour/opacity. Overlays use `animate-overlay`, `animate-content` and
  `animate-sheet-*`. `prefers-reduced-motion` is honoured globally.

---

## 4. Primitives (`src/components/ui.tsx`)

**Reuse these. Do not re-create.**

### Layout and content
- `PageHeader({ title, subtitle?, meta?, eyebrow?, actions? })`
  - Every page starts with this. `icon` is accepted but not drawn.
  - Use `eyebrow` for a back link and `meta` for a live/updated line.
- `Card({ title?, description?, action?, footer?, className })`
  - A title adds a hairline header.
  - Put `p-5` inside `children`, or render a `Table` flush.
- `CardLink({ to })` — the "View all ›" link in card headers.
- `StatGroup({ columns? })` + `Stat({ label, value, caption?, tone?, to?, onClick?, trend? })`
  - Metrics in one hairline-divided card.
  - `caption` states the scope ("Last 30 min", "All time", "Right now").
  - `tone` adds a dot. The value turns to the tone's ink only when a bad-state count is above 0.
- `Kpi` — a single Stat card, kept for older pages.
- `Callout({ tone, title, children, action? })` — inline banner. Use it instead of hand-built tinted boxes.
- `DescriptionList` + `DLRow({ label })` — key/value detail.
- States:
  - `EmptyState({ icon?, title, children?, action? })`
  - `ErrorState({ title, error, onRetry })` — every query's `isError` renders this.
  - `Skeleton`, `SkeletonRows` — first load only. A refetch keeps the old frame.
  - `Loading`, `Spinner`

### Controls
- `Button({ variant, size, loading?, icon?, roles? })`
  - Variants: `primary` | `secondary` (default) | `ghost` | `danger` (soft) | `destructive` (solid, for
    confirm dialogs) | `link`.
  - Sizes: `md` (36) | `sm` (32).
  - `roles` disables the button and explains why in a tooltip.
- `buttonClass(variant, size)` — styles a `<Link>` as a button.
- `IconButton({ label, icon })` — icon-only; `label` is both the aria-label and the tooltip.
- Inputs:
  - `TextInput`, `Textarea`, `SearchInput({ label })`, `Select({ label })`
  - `FilterSelect({ label, value, options })` for table toolbars
  - `Field({ label, hint?, error? })`
- `Tabs({ value, onChange, tabs, variant })`
  - `segmented` (default) is for view toggles such as Chart/Table or a time range.
  - `underline` is for page sections.
  - Arrow keys move between tabs; tabs take an optional `count`.
- `CopyButton`, `Kbd`.

### Tables
- `Table`, `THead`, `TBody`, `Tr({ onClick? })`, `Th({ numeric? })`, `Td({ numeric? })`
- `RowLink({ to | onClick })` — **required in the primary cell of every clickable row**. It is the keyboard path;
  a clickable `<tr>` alone is not accessible.
- `TableToolbar({ end })` sits above the table card; `Pagination({ page, pageSize, total, onPage })`.

### Overlays (Radix: focus trap, Esc, focus return)
- `Modal({ open, onClose, title, description?, wide? })`, `Drawer({ open, onClose, title })`
- Menus: `DropdownMenu*` from `shadcn/dropdown-menu`. Tooltips: `Tooltip*` from `shadcn/tooltip` (the provider
  is mounted in `main.tsx`).

### Badges
- `Badge({ tone, icon?, dot? })` (alias `Pill`): a dot or icon plus a label.
- Domain badges map values → tone: `StatusPill`, `SeverityPill`, `DecisionPill`, `DataClassPill`, `RiskPill`.
- `Chip({ mono? })` — a neutral tag.

### Misc
- `Avatar`, `Meter`, `Countdown`, `TimeAgo` (relative time; the absolute time is in its tooltip), `JsonBlock`.
- `cx(...)` joins classes in page code; `cn(...)` (`lib/utils.ts`) merges them inside shadcn components.
- `focusRing` is the shared outline focus ring. Add it to any custom interactive element.

---

## 5. Charts (`src/components/charts.tsx`, hand-built SVG)

- **Components:**
  - `StackedBars({ data, series, xLabel, ariaLabel })`
  - `AreaChart({ data, series, xLabel, ariaLabel })`
  - `Sparkline({ data, label })`
  - `BarList({ items })`
  - `CategoryBar({ segments })`
  - `Legend({ series, line? })`
- **Marks:** bars ≤24px, 4px rounded data end, 2px surface gap between segments, hairline solid gridlines, 2px
  lines, 10% area wash.
- **Text:** labels and values use text tokens, never the series colour.
- **Colour encodes a job:**
  - Outcomes and states use status tokens, and **routine volume stays `--chart-muted`**. Only the exceptions are
    coloured.
  - A single nominal series uses `--series`.
- **Interaction:** every time-series chart is focusable, with an arrow-key and hover tooltip. Every chart has a
  table-view twin (a Chart/Table segmented toggle).

---

## 6. Page pattern

```tsx
export function MyPage() {
  const q = useMyQuery();
  return (
    <>
      <PageHeader title="My page" subtitle="One-line purpose" actions={<Button variant="primary">Do it</Button>} />
      <StatGroup className="mb-8">
        <Stat label="Things" value={q.data?.count ?? "—"} caption="Right now" />
      </StatGroup>
      <TableToolbar end={<span>{n} items</span>}>
        <SearchInput label="Search things" />
      </TableToolbar>
      <Card className="overflow-hidden">
        {q.isLoading ? <SkeletonRows /> : q.isError ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : !q.data?.items.length ? <EmptyState title="No things" /> : (
          <Table>{/* THead / TBody / Tr with RowLink in the primary cell */}</Table>
        )}
      </Card>
    </>
  );
}
```

Register the route in `main.tsx` and add the nav entry in `components/Layout.tsx` (`useNav`).

---

## 7. Hard rules for AI edits

1. No raw hex/rgb, Tailwind palette colours (`emerald-*`, `gray-*` …) or `text-white`/`bg-white/x` in components.
   Use tokens only (`destructive` is the one place white text sits on red).
2. lucide-react only. No gradients, no glass, no heavy shadows.
3. Status = tone + **text label**, never colour alone. Information-bearing text uses `text-muted`, never
   `text-faint`.
4. Reuse the primitives; extend `ui.tsx` when a variant is missing.
5. Server state goes through TanStack Query. **Gate role-restricted queries with `enabled: can(...)`.**
   `/v1/approvals` is only readable by `APPROVAL_READERS`.
6. Every query renders loading, error and empty states.
7. Both themes must work, so check light *and* dark. Keep it responsive: the sidebar becomes a sheet below `lg`.
8. Keyboard: every interactive element is a real `button`/`a`, gets `focusRing`, and clickable rows have a
   `RowLink`.
