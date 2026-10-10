import {
  useEffect,
  type ComponentProps,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type KeyboardEvent,
  type ReactNode,
  type TextareaHTMLAttributes,
} from "react";
import { Link } from "react-router";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Copy,
  Info,
  Loader2,
  OctagonAlert,
  RefreshCw,
  Search,
  type LucideIcon,
} from "lucide-react";
import { useSession } from "../lib/session";
import { clock, duration, initials, secondsUntil, timeAgo, titleCase, toDate } from "../lib/format";
import { Dialog, DialogCloseButton, DialogContent, DialogDescription, DialogTitle } from "./shadcn/dialog";
import { Tooltip, TooltipContent, TooltipTrigger } from "./shadcn/tooltip";

export const cx = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(" ");

/** Shared, visible keyboard-focus ring (outline: follows the radius and needs no offset colour). */
export const focusRing = "focus-visible:outline-2 focus-visible:outline-solid focus-visible:outline-offset-2 focus-visible:outline-accent";

// =====================================================================================================
// Layout
// =====================================================================================================

export function PageHeader({
  title,
  subtitle,
  actions,
  meta,
  eyebrow,
}: {
  /** Accepted for compatibility; page headers no longer draw an icon tile. */
  icon?: LucideIcon;
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  /** A quiet status line under the subtitle, e.g. "Live · updated 3s ago". */
  meta?: ReactNode;
  /** Small link or label above the title, e.g. a back link to the parent list. */
  eyebrow?: ReactNode;
}) {
  return (
    <header className="mb-8 flex flex-wrap items-end gap-x-6 gap-y-4">
      <div className="min-w-0 flex-1">
        {eyebrow && <div className="mb-2 text-caption text-muted">{eyebrow}</div>}
        <h1 className="text-2xl font-semibold tracking-[-0.02em] text-fg">{title}</h1>
        {subtitle && <p className="mt-1 max-w-2xl text-sm text-muted">{subtitle}</p>}
        {meta && <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-muted">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Card({
  className,
  children,
  title,
  description,
  action,
  footer,
}: {
  className?: string;
  children: ReactNode;
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <section className={cx("rounded-xl border border-line bg-card shadow-card", className)}>
      {title && (
        <header className="flex items-start gap-3 border-b border-line px-5 py-3.5">
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-fg">{title}</h2>
            {description && <p className="mt-0.5 text-caption text-muted">{description}</p>}
          </div>
          {action && <div className="flex shrink-0 items-center gap-2">{action}</div>}
        </header>
      )}
      {children}
      {footer && <footer className="border-t border-line px-5 py-3 text-caption">{footer}</footer>}
    </section>
  );
}

/** "View all →" style link for card footers and headers. */
export function CardLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className={cx("inline-flex items-center gap-1 rounded text-caption font-medium text-accent hover:text-accent-strong", focusRing)}>
      {children}
      <ChevronRight className="size-3.5" />
    </Link>
  );
}

// ---------- metrics ----------

export type StatTone = "neutral" | "good" | "warning" | "serious" | "critical" | "accent";
const statDot: Record<StatTone, string> = {
  neutral: "bg-chart-muted",
  good: "bg-good",
  warning: "bg-warning",
  serious: "bg-serious",
  critical: "bg-critical",
  accent: "bg-accent",
};
const statInk: Record<StatTone, string> = {
  neutral: "text-fg",
  good: "text-good-ink",
  warning: "text-warning-ink",
  serious: "text-serious-ink",
  critical: "text-critical-ink",
  accent: "text-fg",
};

/** A group of metrics in one card, divided by hairlines (fewer boxes than one card per number). */
export function StatGroup({ children, className, columns = 4 }: { children: ReactNode; className?: string; columns?: 2 | 3 | 4 | 5 }) {
  const cols = { 2: "sm:grid-cols-2", 3: "sm:grid-cols-3", 4: "sm:grid-cols-2 xl:grid-cols-4", 5: "sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5" }[columns];
  return (
    <section className={cx("grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-line bg-line shadow-card", cols, className)}>
      {children}
    </section>
  );
}

/**
 * One metric: label, value, scope caption. Tone shows as a small dot; the value only takes the tone's colour
 * when a bad-state count is non-zero, so colour guides attention instead of decorating.
 */
export function Stat({
  label,
  value,
  caption,
  tone = "neutral",
  to,
  onClick,
  trend,
  className,
}: {
  label: string;
  value: ReactNode;
  caption?: ReactNode;
  tone?: StatTone;
  to?: string;
  onClick?: () => void;
  trend?: ReactNode;
  className?: string;
}) {
  const emphasis = tone !== "neutral" && tone !== "accent" && typeof value === "number" && value > 0;
  const body = (
    <>
      <div className="flex items-center gap-2 text-caption font-medium text-muted">
        {tone !== "neutral" && <span className={cx("size-1.5 shrink-0 rounded-full", statDot[tone])} aria-hidden />}
        <span className="truncate">{label}</span>
        {(to || onClick) && <ChevronRight className="ml-auto size-3.5 shrink-0 text-faint transition group-hover:translate-x-0.5 group-hover:text-muted" />}
      </div>
      <div className="mt-2 flex items-end justify-between gap-3">
        <div className={cx("text-3xl font-semibold tracking-tight", emphasis ? statInk[tone] : "text-fg")}>{value}</div>
        {trend && <div className="mb-1 w-24 shrink-0">{trend}</div>}
      </div>
      {caption && <div className="mt-1 truncate text-caption text-muted">{caption}</div>}
    </>
  );
  const base = cx("group block min-w-0 bg-card p-5 text-left", className);
  const interactive = cx(base, "transition-colors hover:bg-[color-mix(in_srgb,var(--card),var(--fg)_3%)]", focusRing, "focus-visible:-outline-offset-2");
  if (to)
    return (
      <Link to={to} className={interactive}>
        {body}
      </Link>
    );
  if (onClick)
    return (
      <button type="button" onClick={onClick} className={cx(interactive, "w-full")}>
        {body}
      </button>
    );
  return <div className={base}>{body}</div>;
}

/** Single metric card. Kept for pages that predate StatGroup. */
export function Kpi({
  label,
  value,
  hint,
  tone = "accent",
  onClick,
}: {
  icon?: LucideIcon;
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "accent" | "warning" | "critical" | "series" | "serious";
  onClick?: () => void;
}) {
  const map: Record<string, StatTone> = { accent: "neutral", series: "neutral", warning: "warning", critical: "critical", serious: "serious" };
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-card shadow-card">
      <Stat label={label} value={value} caption={hint} tone={map[tone]} onClick={onClick} />
    </div>
  );
}

// ---------- states ----------

export function EmptyState({ icon: Icon = Info, title, children, action }: { icon?: LucideIcon; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="mb-1 grid size-10 place-items-center rounded-full bg-inset text-muted">
        <Icon className="size-5" />
      </div>
      <div className="text-sm font-medium text-fg">{title}</div>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

/** Shown when a query fails, so an error never masquerades as an empty or loading state. */
export function ErrorState({ title = "Couldn't load this", error, onRetry }: { title?: string; error?: unknown; onRetry?: () => void }) {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : undefined;
  return (
    <div role="alert" className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="mb-1 grid size-10 place-items-center rounded-full bg-critical/10 text-critical-ink">
        <AlertTriangle className="size-5" />
      </div>
      <div className="text-sm font-medium text-fg">{title}</div>
      {message && <div className="max-w-md text-sm break-words text-muted">{message}</div>}
      {onRetry && (
        <Button size="sm" icon={RefreshCw} onClick={onRetry} className="mt-2">
          Try again
        </Button>
      )}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cx("size-4 animate-spin", className)} />;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted" role="status">
      <Spinner /> {label}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("animate-pulse rounded-md bg-selected", className)} aria-hidden />;
}

/** Placeholder table rows for the first load of a list. */
export function SkeletonRows({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="divide-y divide-line" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex items-center gap-6 px-4 py-3.5">
          {Array.from({ length: cols }, (_, c) => (
            <Skeleton key={c} className={cx("h-3.5", c === 0 ? "w-48" : "flex-1")} />
          ))}
        </div>
      ))}
    </div>
  );
}

type CalloutTone = "info" | "good" | "warning" | "critical";
const calloutStyles: Record<CalloutTone, { box: string; icon: LucideIcon; ink: string }> = {
  info: { box: "bg-accent-soft border-accent/20", icon: Info, ink: "text-info-ink" },
  good: { box: "bg-good/8 border-good/25", icon: CheckCircle2, ink: "text-good-ink" },
  warning: { box: "bg-warning/10 border-warning/30", icon: AlertTriangle, ink: "text-warning-ink" },
  critical: { box: "bg-critical/8 border-critical/25", icon: OctagonAlert, ink: "text-critical-ink" },
};

/** Inline banner: what happened, why it matters, and (optionally) what to do. */
export function Callout({
  tone = "info",
  title,
  children,
  action,
  icon,
  className,
}: {
  tone?: CalloutTone;
  title?: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  icon?: LucideIcon;
  className?: string;
}) {
  const s = calloutStyles[tone];
  const Icon = icon ?? s.icon;
  return (
    <div role={tone === "critical" ? "alert" : undefined} className={cx("flex gap-3 rounded-lg border p-3.5", s.box, className)}>
      <Icon className={cx("mt-0.5 size-4 shrink-0", s.ink)} />
      <div className="min-w-0 flex-1 text-sm">
        {title && <div className={cx("font-medium", s.ink)}>{title}</div>}
        {children && <div className={cx("text-muted", !!title && "mt-0.5")}>{children}</div>}
      </div>
      {action && <div className="shrink-0 self-center">{action}</div>}
    </div>
  );
}

export function DescriptionList({ children, className }: { children: ReactNode; className?: string }) {
  return <dl className={cx("divide-y divide-line", className)}>{children}</dl>;
}

export function DLRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1 py-3 text-sm sm:grid-cols-[160px_1fr] sm:gap-4">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 text-fg">{children}</dd>
    </div>
  );
}

// =====================================================================================================
// Controls
// =====================================================================================================

type Variant = "primary" | "secondary" | "danger" | "destructive" | "ghost" | "link";
const buttonStyles: Record<Variant, string> = {
  primary: "bg-accent text-on-accent font-medium hover:bg-accent-strong shadow-card",
  secondary: "border border-line-strong bg-card text-fg font-medium hover:bg-hover shadow-card",
  danger: "border border-critical/30 bg-critical/8 text-critical-ink font-medium hover:bg-critical/14",
  destructive: "bg-critical text-white font-medium hover:bg-critical/90 shadow-card",
  ghost: "text-muted hover:bg-hover hover:text-fg",
  link: "text-accent hover:text-accent-strong underline-offset-4 hover:underline",
};

/** Button styling for links that act as buttons (e.g. "Review" in a list row). */
export const buttonClass = (variant: Variant = "secondary", size: "sm" | "md" = "md") =>
  cx(
    "inline-flex items-center justify-center gap-2 rounded-lg text-sm whitespace-nowrap transition-colors",
    variant !== "link" && (size === "sm" ? "h-8 px-3" : "h-9 px-3.5"),
    focusRing,
    buttonStyles[variant],
  );

export function Button({
  variant = "secondary",
  size = "md",
  loading,
  icon: Icon,
  className,
  children,
  roles,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: "sm" | "md"; loading?: boolean; icon?: LucideIcon; roles?: string[] }) {
  const { can } = useSession();
  const missingRole = roles && !can(...roles);
  const button = (
    <button
      type="button"
      {...props}
      disabled={props.disabled || loading || missingRole}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-lg text-sm whitespace-nowrap transition-colors disabled:pointer-events-none disabled:opacity-45",
        variant !== "link" && (size === "sm" ? "h-8 px-3" : "h-9 px-3.5"),
        focusRing,
        buttonStyles[variant] ?? buttonStyles.secondary,
        className,
      )}
    >
      {loading ? <Spinner /> : Icon && <Icon className="size-4" />}
      {children}
    </button>
  );
  if (!missingRole) return button;
  // Disabled buttons can't take focus, so the reason lives on a focusable wrapper.
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className={cx("inline-flex rounded-lg", focusRing)}>
          {button}
        </span>
      </TooltipTrigger>
      <TooltipContent>Requires the role: {roles!.join(" or ")}</TooltipContent>
    </Tooltip>
  );
}

/** Icon-only button; the label is both the accessible name and the tooltip. */
export function IconButton({ label, icon: Icon, className, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; icon: LucideIcon }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={label}
          {...props}
          className={cx("grid size-9 shrink-0 place-items-center rounded-lg text-muted transition-colors hover:bg-hover hover:text-fg", focusRing, className)}
        >
          <Icon className="size-[18px]" />
        </button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

const inputBase =
  "h-9 w-full rounded-lg border border-line-strong bg-card px-3 text-sm text-fg outline-none transition placeholder:text-faint focus:border-accent focus:ring-3 focus:ring-accent/15";

export function Select({
  value,
  onChange,
  options,
  label,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  label: string;
  className?: string;
}) {
  return (
    <div className={cx("relative", className)}>
      <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)} className={cx(inputBase, "appearance-none pr-9")}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-faint" />
    </div>
  );
}

/** Compact toolbar filter: "Status · All ⌄". A native select, so keyboard and screen readers just work. */
export function FilterSelect({
  label,
  value,
  onChange,
  options,
  allLabel = "All",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  allLabel?: string;
}) {
  const active = value !== "";
  const current = options.find((o) => o.value === value)?.label ?? allLabel;
  return (
    <label
      className={cx(
        "relative inline-flex h-9 cursor-pointer items-center gap-1.5 rounded-lg border px-3 text-sm whitespace-nowrap transition focus-within:outline-2 focus-within:outline-solid focus-within:outline-offset-2 focus-within:outline-accent",
        active ? "border-accent/30 bg-accent-soft" : "border-line-strong bg-card hover:bg-hover",
      )}
    >
      <span className="text-muted">{label}</span>
      <span className={cx("font-medium", active ? "text-accent" : "text-fg")}>{current}</span>
      <ChevronDown className="size-3.5 text-faint" />
      <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)} className="absolute inset-0 cursor-pointer appearance-none opacity-0">
        <option value="">{allLabel}</option>
        {options
          .filter((o) => o.value !== "")
          .map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
      </select>
    </label>
  );
}

export function TextInput(props: ComponentProps<"input">) {
  return <input {...props} className={cx(inputBase, props.className)} />;
}

export function SearchInput({ className, label, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  return (
    <div className={cx("relative", className)}>
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-faint" />
      <input type="search" aria-label={label} {...props} className={cx(inputBase, "pl-9")} />
    </div>
  );
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx(inputBase, "h-auto min-h-24 py-2 leading-relaxed", props.className)} />;
}

export function Field({ label, children, hint, error }: { label: string; children: ReactNode; hint?: string; error?: string }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-caption font-medium text-fg">{label}</span>
      {children}
      {hint && !error && <span className="mt-1.5 block text-caption text-muted">{hint}</span>}
      {error && <span className="mt-1.5 block text-caption text-critical-ink">{error}</span>}
    </label>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded border border-line-strong bg-card px-1.5 font-sans text-2xs font-medium text-muted">{children}</kbd>;
}

export function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className={cx("relative rounded p-0.5 text-faint transition hover:text-fg", focusRing)}
          aria-label={copied ? "Copied" : "Copy"}
          onClick={(e) => {
            e.stopPropagation();
            navigator.clipboard?.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          }}
        >
          {copied ? <Check className="size-3.5 text-good-ink" /> : <Copy className="size-3.5" />}
        </button>
      </TooltipTrigger>
      <TooltipContent>{copied ? "Copied" : "Copy"}</TooltipContent>
    </Tooltip>
  );
}

/**
 * Tabs. `segmented` (default) for small view toggles such as Chart/Table; `underline` for page sections.
 * Arrow keys move between tabs (roving tab index).
 */
export function Tabs<T extends string>({
  value,
  onChange,
  tabs,
  variant = "segmented",
  label,
  className,
}: {
  value: T;
  onChange: (v: T) => void;
  tabs: { value: T; label: ReactNode; count?: number }[];
  variant?: "segmented" | "underline";
  label?: string;
  className?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: KeyboardEvent, i: number) => {
    const delta = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!delta) return;
    e.preventDefault();
    const next = (i + delta + tabs.length) % tabs.length;
    refs.current[next]?.focus();
    onChange(tabs[next].value);
  };
  const underline = variant === "underline";
  return (
    <div role="tablist" aria-label={label} className={cx(underline ? "flex gap-6 overflow-x-auto border-b border-line" : "inline-flex rounded-lg border border-line bg-inset p-0.5", className)}>
      {tabs.map((t, i) => {
        const selected = value === t.value;
        return (
          <button
            key={t.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            role="tab"
            type="button"
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(t.value)}
            onKeyDown={(e) => onKey(e, i)}
            className={cx(
              "inline-flex items-center gap-1.5 text-sm whitespace-nowrap transition-colors",
              focusRing,
              underline
                ? cx("-mb-px border-b-2 pt-1 pb-2.5 font-medium", selected ? "border-fg text-fg" : "border-transparent text-muted hover:text-fg")
                : cx("rounded-md px-3 py-1", selected ? "bg-card font-medium text-fg shadow-card" : "text-muted hover:text-fg"),
            )}
          >
            {t.label}
            {t.count !== undefined && <span className={cx("tabular rounded px-1.5 text-2xs font-medium", selected ? "bg-selected text-fg" : "bg-selected text-muted")}>{t.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

// =====================================================================================================
// Overlays (Radix Dialog: focus trap, Esc, scroll lock, focus return)
// =====================================================================================================

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className={wide ? "max-w-3xl" : "max-w-lg"}>
        <header className="flex items-start gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0 flex-1">
            <DialogTitle className="text-base font-semibold text-fg">{title}</DialogTitle>
            <DialogDescription className={description ? "mt-1 text-sm text-muted" : "sr-only"}>{description ?? (typeof title === "string" ? title : "Dialog")}</DialogDescription>
          </div>
          <DialogCloseButton className="-mt-1 -mr-1" />
        </header>
        <div className="overflow-y-auto p-5">{children}</div>
      </DialogContent>
    </Dialog>
  );
}

export function Drawer({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode }) {
  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent side="right">
        <header className="flex items-start gap-3 border-b border-line px-5 py-4">
          <DialogTitle className="min-w-0 flex-1 text-base font-semibold text-fg">{title}</DialogTitle>
          <DialogDescription className="sr-only">{typeof title === "string" ? title : "Details"}</DialogDescription>
          <DialogCloseButton className="-mt-1 -mr-1" />
        </header>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </DialogContent>
    </Dialog>
  );
}

// =====================================================================================================
// Badges (status always carries a text label; colour only reinforces it)
// =====================================================================================================

export type Tone = "good" | "warning" | "serious" | "critical" | "neutral" | "info" | "accent";
const toneStyles: Record<Tone, { badge: string; dot: string }> = {
  good: { badge: "bg-good/10 text-good-ink", dot: "bg-good" },
  warning: { badge: "bg-warning/12 text-warning-ink", dot: "bg-warning" },
  serious: { badge: "bg-serious/10 text-serious-ink", dot: "bg-serious" },
  critical: { badge: "bg-critical/10 text-critical-ink", dot: "bg-critical" },
  neutral: { badge: "bg-selected text-muted", dot: "bg-faint" },
  info: { badge: "bg-accent-soft text-info-ink", dot: "bg-accent" },
  accent: { badge: "bg-accent-soft text-accent", dot: "bg-accent" },
};

export function Badge({
  tone = "neutral",
  icon: Icon,
  dot,
  children,
  className,
}: {
  tone?: Tone;
  icon?: LucideIcon;
  dot?: boolean;
  children: ReactNode;
  className?: string;
}) {
  const s = toneStyles[tone];
  const showDot = dot ?? !Icon;
  return (
    <span className={cx("inline-flex h-[22px] items-center gap-1.5 rounded-md px-2 text-xs font-medium whitespace-nowrap", s.badge, className)}>
      {Icon ? <Icon className="size-3.5" /> : showDot && <span className={cx("size-1.5 rounded-full", s.dot)} aria-hidden />}
      {children}
    </span>
  );
}

/** Kept for compatibility: same as Badge. */
export const Pill = Badge;

export const DECISIONS: Record<string, { tone: Tone; icon: LucideIcon; label: string }> = {
  allow: { tone: "good", icon: CheckCircle2, label: "Allowed" },
  require_approval: { tone: "warning", icon: Info, label: "Needs approval" },
  deny: { tone: "critical", icon: OctagonAlert, label: "Denied" },
  rate_limited: { tone: "serious", icon: AlertTriangle, label: "Rate-limited" },
};

export function DecisionPill({ decision }: { decision: string }) {
  const d = DECISIONS[decision];
  return <Badge tone={d?.tone ?? "neutral"}>{d?.label ?? titleCase(decision)}</Badge>;
}

const STATUS_TONE: Record<string, Tone> = {
  active: "good",
  suspended: "critical",
  pending_approval: "warning",
  draft: "neutral",
  discovered: "serious",
  quarantined: "critical",
  retired: "neutral",
  approved: "good",
  pending: "warning",
  completed: "good",
  revoked: "critical",
  consumed: "good",
  rejected: "critical",
  expired: "neutral",
  cancelled: "neutral",
  open: "serious",
  claimed: "good",
  dismissed: "neutral",
  new: "serious",
  triage: "warning",
  investigating: "info",
  resolved: "good",
  false_positive: "neutral",
  submitted: "warning",
  superseded: "neutral",
};

export function StatusPill({ status }: { status: string }) {
  return <Badge tone={STATUS_TONE[status] ?? "neutral"}>{titleCase(status)}</Badge>;
}

const SEVERITY_TONE: Record<string, Tone> = { critical: "critical", high: "serious", medium: "warning", low: "neutral" };
export function SeverityPill({ severity }: { severity: string }) {
  return (
    <Badge tone={SEVERITY_TONE[severity] ?? "neutral"} className={severity === "critical" ? "bg-critical/15" : undefined}>
      {titleCase(severity)}
    </Badge>
  );
}

export function DataClassPill({ value }: { value: string }) {
  const tone: Record<string, Tone> = { public: "neutral", internal: "info", confidential: "warning", restricted: "critical" };
  return <Badge tone={tone[value] ?? "neutral"}>{titleCase(value)}</Badge>;
}

export function RiskPill({ tier }: { tier: string }) {
  const tone: Record<string, Tone> = { low: "good", medium: "warning", high: "serious", critical: "critical" };
  return <Badge tone={tone[tier] ?? "neutral"}>{titleCase(tier)} risk</Badge>;
}

export function Chip({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return <span className={cx("inline-flex h-[22px] items-center rounded-md bg-selected px-2 text-xs text-muted", mono && "font-mono")}>{children}</span>;
}

// =====================================================================================================
// Misc
// =====================================================================================================

export function Avatar({ name, size = "md" }: { name: string; size?: "sm" | "md" }) {
  return (
    <span className={cx("grid shrink-0 place-items-center rounded-full bg-selected font-semibold text-fg", size === "sm" ? "size-7 text-2xs" : "size-8 text-xs")} aria-hidden>
      {initials(name)}
    </span>
  );
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="max-h-96 overflow-auto rounded-lg border border-line bg-inset p-3 font-mono text-xs leading-relaxed text-muted">{JSON.stringify(value, null, 2)}</pre>;
}

/** A 0-max meter whose fill carries severity; the track is a lighter step of the same hue. */
export function Meter({ value, max, label }: { value: number; max: number; label: string }) {
  const ratio = Math.max(0, Math.min(1, value / max));
  const color = ratio >= 0.8 ? "var(--critical)" : ratio >= 0.5 ? "var(--warning)" : "var(--series)";
  return (
    <div>
      <div className="mb-1.5 flex justify-between text-sm">
        <span className="text-muted">{label}</span>
        <span className="tabular font-medium text-fg">
          {value}
          <span className="text-muted"> / {max}</span>
        </span>
      </div>
      <div
        className="h-1.5 rounded-full"
        style={{ background: `color-mix(in srgb, ${color} 16%, transparent)` }}
        role="meter"
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-label={label}
      >
        <div className="h-1.5 rounded-full transition-all" style={{ width: `${ratio * 100}%`, background: color }} />
      </div>
    </div>
  );
}

export function useNow(intervalMs = 1000) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

export function Countdown({ until }: { until: string }) {
  useNow();
  const left = secondsUntil(until);
  return <span className={cx("tabular", left <= 60 && left > 0 && "text-warning-ink", left <= 0 && "text-muted")}>{duration(left)}</span>;
}

/** Relative time with the absolute timestamp on hover/focus. */
export function TimeAgo({ value }: { value: string | null | undefined }) {
  useNow(15000);
  if (!value) return <span className="text-muted">—</span>;
  const date = toDate(value);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <time dateTime={date.toISOString()} className="whitespace-nowrap">
          {timeAgo(value)}
        </time>
      </TooltipTrigger>
      <TooltipContent>
        {date.toLocaleDateString()} {clock(value)}
      </TooltipContent>
    </Tooltip>
  );
}

// =====================================================================================================
// Tables
// =====================================================================================================

export function Table({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className="overflow-x-auto">
      <table className={cx("w-full text-sm", className)}>{children}</table>
    </div>
  );
}

export function THead({ children }: { children: ReactNode }) {
  return (
    <thead className="border-b border-line">
      <tr>{children}</tr>
    </thead>
  );
}

export function TBody({ children }: { children: ReactNode }) {
  return <tbody className="divide-y divide-line">{children}</tbody>;
}

/** Row. Mouse users can click anywhere; keyboard users reach the row through the RowLink in its main cell. */
export function Tr({ children, onClick, className }: { children: ReactNode; onClick?: () => void; className?: string }) {
  return (
    <tr onClick={onClick} className={cx(onClick && "cursor-pointer", "transition-colors hover:bg-hover", className)}>
      {children}
    </tr>
  );
}

export function Th({ children, className, numeric }: { children?: ReactNode; className?: string; numeric?: boolean }) {
  return <th className={cx("px-4 py-2.5 text-xs font-medium whitespace-nowrap text-muted", numeric ? "text-right" : "text-left", className)}>{children}</th>;
}

export function Td({ children, className, numeric }: { children?: ReactNode; className?: string; numeric?: boolean }) {
  return <td className={cx("px-4 py-3 align-middle text-sm", numeric && "tabular text-right", className)}>{children}</td>;
}

/** The focusable primary cell content of a row: a link (navigates) or a button (opens a panel). */
export function RowLink({ to, onClick, children, className }: { to?: string; onClick?: () => void; children: ReactNode; className?: string }) {
  const cls = cx("rounded text-left font-medium text-fg hover:text-accent", focusRing, className);
  if (to)
    return (
      <Link to={to} className={cls} onClick={(e) => e.stopPropagation()}>
        {children}
      </Link>
    );
  return (
    <button
      type="button"
      className={cls}
      onClick={(e) => {
        e.stopPropagation();
        onClick?.();
      }}
    >
      {children}
    </button>
  );
}

export function TableToolbar({ children, end }: { children: ReactNode; end?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2">
      {children}
      {end && <div className="ml-auto flex items-center gap-2 text-caption text-muted">{end}</div>}
    </div>
  );
}

export function Pagination({ page, pageSize, total, onPage, noun = "results" }: { page: number; pageSize: number; total: number; onPage: (p: number) => void; noun?: string }) {
  const from = total ? page * pageSize + 1 : 0;
  const to = Math.min(total, (page + 1) * pageSize);
  return (
    <div className="flex items-center justify-between border-t border-line px-4 py-2.5 text-caption text-muted">
      <span className="tabular">
        {total ? (
          <>
            Showing{" "}
            <span className="font-medium text-fg">
              {from}–{to}
            </span>{" "}
            of <span className="font-medium text-fg">{total.toLocaleString()}</span>
          </>
        ) : (
          `0 ${noun}`
        )}
      </span>
      <div className="flex gap-1">
        <Button variant="ghost" size="sm" icon={ChevronLeft} disabled={page === 0} onClick={() => onPage(page - 1)}>
          Previous
        </Button>
        <Button variant="ghost" size="sm" disabled={(page + 1) * pageSize >= total} onClick={() => onPage(page + 1)}>
          Next <ChevronRight className="size-4" />
        </Button>
      </div>
    </div>
  );
}
