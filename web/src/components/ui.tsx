import { useEffect, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  Ban,
  Check,
  CheckCircle2,
  Circle,
  Clock,
  Copy,
  Gauge,
  Hourglass,
  Info,
  Loader2,
  ShieldCheck,
  X,
  type LucideIcon,
} from "lucide-react";
import { useSession } from "../lib/session";
import { duration, initials, secondsUntil, titleCase } from "../lib/format";

export const cx = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(" ");

// ---------- layout ----------

export function PageHeader({
  icon: Icon,
  title,
  subtitle,
  actions,
}: {
  icon: LucideIcon;
  title: string;
  subtitle: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-center gap-4">
      <div className="grid size-12 place-items-center rounded-xl border border-line bg-accent-soft text-accent">
        <Icon className="size-6" />
      </div>
      <div className="min-w-0 flex-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="mt-0.5 text-sm text-muted">{subtitle}</p>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Card({ className, children, title, action }: { className?: string; children: ReactNode; title?: ReactNode; action?: ReactNode }) {
  return (
    <section className={cx("rounded-2xl border border-line bg-card", className)}>
      {title && (
        <header className="flex items-center gap-3 border-b border-line px-5 py-3.5">
          <h2 className="flex-1 text-sm font-semibold">{title}</h2>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function Kpi({
  icon: Icon,
  label,
  value,
  hint,
  tone = "accent",
  onClick,
}: {
  icon: LucideIcon;
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "accent" | "warning" | "critical" | "series" | "serious";
  onClick?: () => void;
}) {
  const toneClass = {
    accent: "text-accent",
    warning: "text-warning-ink",
    critical: "text-critical-ink",
    series: "text-info-ink",
    serious: "text-serious-ink",
  }[tone];
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!onClick}
      className={cx(
        "group flex flex-col items-start justify-start rounded-2xl border border-line bg-card p-5 text-left transition",
        onClick && "hover:border-line-strong hover:bg-hover",
      )}
    >
      <Icon className={cx("size-5", toneClass)} />
      <div className="mt-4 text-3xl font-semibold tracking-tight">{value}</div>
      <div className="mt-1 text-xs font-semibold tracking-wider text-muted uppercase">{label}</div>
      {hint && <div className={cx("mt-1.5 text-sm", onClick ? toneClass : "text-faint")}>{hint}</div>}
    </button>
  );
}

export function EmptyState({ icon: Icon = Info, title, children }: { icon?: LucideIcon; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="grid size-11 place-items-center rounded-full bg-inset text-faint">
        <Icon className="size-5" />
      </div>
      <div className="font-medium">{title}</div>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cx("size-4 animate-spin", className)} />;
}

export function Loading() {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted">
      <Spinner /> Loading…
    </div>
  );
}

// ---------- controls ----------

type Variant = "primary" | "secondary" | "danger" | "ghost";
export function Button({
  variant = "secondary",
  loading,
  icon: Icon,
  className,
  children,
  roles,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; loading?: boolean; icon?: LucideIcon; roles?: string[] }) {
  const { can } = useSession();
  const missingRole = roles && !can(...roles);
  const styles: Record<Variant, string> = {
    primary: "bg-accent text-on-accent hover:bg-accent-strong font-semibold",
    secondary: "border border-line-strong bg-inset hover:bg-hover",
    danger: "border border-critical/40 bg-critical/12 text-critical-ink hover:bg-critical/20",
    ghost: "text-muted hover:bg-hover hover:text-fg",
  };
  return (
    <button
      {...props}
      disabled={props.disabled || loading || missingRole}
      title={missingRole ? `Requires the role: ${roles!.join(" or ")}` : props.title}
      className={cx(
        "inline-flex h-9 items-center justify-center gap-2 rounded-lg px-3.5 text-sm whitespace-nowrap transition disabled:cursor-not-allowed disabled:opacity-45",
        styles[variant],
        className,
      )}
    >
      {loading ? <Spinner /> : Icon && <Icon className="size-4" />}
      {children}
    </button>
  );
}

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
    <select
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={cx("h-10 rounded-lg border border-line-strong bg-inset px-3 text-sm outline-none focus:border-accent", className)}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cx(
        "h-10 w-full rounded-lg border border-line-strong bg-inset px-3 text-sm outline-none placeholder:text-faint focus:border-accent",
        props.className,
      )}
    />
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-semibold tracking-wide text-muted uppercase">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-faint">{hint}</span>}
    </label>
  );
}

export function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="text-faint hover:text-fg"
      aria-label="Copy"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
    >
      {copied ? <Check className="size-3.5 text-good-ink" /> : <Copy className="size-3.5" />}
    </button>
  );
}

export function Tabs<T extends string>({ value, onChange, tabs }: { value: T; onChange: (v: T) => void; tabs: { value: T; label: ReactNode }[] }) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-inset p-1" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.value}
          role="tab"
          aria-selected={value === t.value}
          onClick={() => onChange(t.value)}
          className={cx(
            "rounded-md px-3 py-1.5 text-sm transition",
            value === t.value ? "bg-card font-medium shadow-sm" : "text-muted hover:text-fg",
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ---------- overlays ----------

export function Modal({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    if (open) window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 grid place-items-center bg-black/60 p-4 backdrop-blur-sm" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        className={cx("max-h-[90vh] w-full overflow-auto rounded-2xl border border-line-strong bg-card shadow-2xl", wide ? "max-w-3xl" : "max-w-lg")}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <header className="sticky top-0 flex items-center gap-3 border-b border-line bg-card px-5 py-4">
          <h2 className="flex-1 font-semibold">{title}</h2>
          <button onClick={onClose} className="text-faint hover:text-fg" aria-label="Close">
            <X className="size-5" />
          </button>
        </header>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function Drawer({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onMouseDown={onClose}>
      <aside className="h-full w-full max-w-xl overflow-auto border-l border-line-strong bg-card shadow-2xl" onMouseDown={(e) => e.stopPropagation()}>
        <header className="sticky top-0 flex items-center gap-3 border-b border-line bg-card px-5 py-4">
          <h2 className="flex-1 font-semibold">{title}</h2>
          <button onClick={onClose} className="text-faint hover:text-fg" aria-label="Close">
            <X className="size-5" />
          </button>
        </header>
        <div className="p-5">{children}</div>
      </aside>
    </div>
  );
}

// ---------- pills (status always carries an icon + label, never colour alone) ----------

type Tone = "good" | "warning" | "serious" | "critical" | "neutral" | "info" | "accent";
const toneStyles: Record<Tone, string> = {
  good: "bg-good/14 text-good-ink border-good/30",
  warning: "bg-warning/14 text-warning-ink border-warning/30",
  serious: "bg-serious/14 text-serious-ink border-serious/30",
  critical: "bg-critical/14 text-critical-ink border-critical/35",
  neutral: "bg-inset text-muted border-line-strong",
  info: "bg-series/14 text-info-ink border-series/30",
  accent: "bg-accent-soft text-accent border-accent/30",
};

export function Pill({ tone = "neutral", icon: Icon, children, className }: { tone?: Tone; icon?: LucideIcon; children: ReactNode; className?: string }) {
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium whitespace-nowrap", toneStyles[tone], className)}>
      {Icon && <Icon className="size-3.5" />}
      {children}
    </span>
  );
}

export const DECISIONS: Record<string, { tone: Tone; icon: LucideIcon; label: string }> = {
  allow: { tone: "good", icon: CheckCircle2, label: "Allowed" },
  require_approval: { tone: "warning", icon: Hourglass, label: "Needs approval" },
  deny: { tone: "critical", icon: Ban, label: "Denied" },
  rate_limited: { tone: "serious", icon: Gauge, label: "Rate-limited" },
};

export function DecisionPill({ decision }: { decision: string }) {
  const d = DECISIONS[decision] ?? { tone: "neutral" as Tone, icon: Circle, label: decision };
  return (
    <Pill tone={d.tone} icon={d.icon}>
      {d.label}
    </Pill>
  );
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, [Tone, LucideIcon]> = {
    active: ["good", CheckCircle2],
    suspended: ["critical", Ban],
    pending_approval: ["warning", Hourglass],
    draft: ["neutral", Circle],
    discovered: ["serious", AlertTriangle],
    quarantined: ["critical", AlertOctagon],
    retired: ["neutral", X],
    approved: ["good", ShieldCheck],
    pending: ["warning", Hourglass],
    completed: ["good", CheckCircle2],
    revoked: ["critical", Ban],
    consumed: ["good", CheckCircle2],
    rejected: ["critical", X],
    expired: ["neutral", Clock],
    cancelled: ["neutral", X],
    open: ["serious", AlertTriangle],
    claimed: ["good", CheckCircle2],
    dismissed: ["neutral", X],
    new: ["serious", AlertTriangle],
    triage: ["warning", Hourglass],
    investigating: ["info", Clock],
    resolved: ["good", CheckCircle2],
    false_positive: ["neutral", X],
  };
  const [tone, icon] = map[status] ?? ["neutral", Circle];
  return (
    <Pill tone={tone} icon={icon}>
      {titleCase(status)}
    </Pill>
  );
}

export function SeverityPill({ severity }: { severity: string }) {
  const map: Record<string, [Tone, LucideIcon]> = {
    critical: ["critical", AlertOctagon],
    high: ["serious", AlertTriangle],
    medium: ["warning", AlertTriangle],
    low: ["info", Info],
  };
  const [tone, icon] = map[severity] ?? ["neutral", Info];
  return (
    <Pill tone={tone} icon={icon}>
      {titleCase(severity)}
    </Pill>
  );
}

export function DataClassPill({ value }: { value: string }) {
  const tone: Record<string, Tone> = { public: "neutral", internal: "info", confidential: "warning", restricted: "critical" };
  return <Pill tone={tone[value] ?? "neutral"}>{titleCase(value)}</Pill>;
}

export function RiskPill({ tier }: { tier: string }) {
  const tone: Record<string, Tone> = { low: "good", medium: "warning", high: "serious", critical: "critical" };
  return (
    <Pill tone={tone[tier] ?? "neutral"} icon={Gauge}>
      {titleCase(tier)} risk
    </Pill>
  );
}

export function Chip({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return <span className={cx("inline-flex rounded-md border border-line bg-inset px-2 py-0.5 text-xs text-muted", mono && "font-mono")}>{children}</span>;
}

// ---------- misc ----------

export function Avatar({ name, size = "md" }: { name: string; size?: "sm" | "md" }) {
  return (
    <span className={cx("grid shrink-0 place-items-center rounded-full bg-accent-soft font-semibold text-accent", size === "sm" ? "size-7 text-[11px]" : "size-9 text-xs")}>
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
      <div className="mb-1 flex justify-between text-sm">
        <span className="text-muted">{label}</span>
        <span className="tabular font-medium">
          {value}
          <span className="text-faint"> / {max}</span>
        </span>
      </div>
      <div className="h-2 rounded-full" style={{ background: `color-mix(in srgb, ${color} 18%, transparent)` }} role="meter" aria-valuenow={value} aria-valuemax={max} aria-label={label}>
        <div className="h-2 rounded-full transition-all" style={{ width: `${ratio * 100}%`, background: color }} />
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
  return <span className={cx("tabular", left <= 60 && "text-warning-ink", left <= 0 && "text-faint")}>{duration(left)}</span>;
}

export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return <th className={cx("px-4 py-3 text-left text-xs font-semibold tracking-wider text-muted uppercase", className)}>{children}</th>;
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cx("px-4 py-3 align-middle text-sm", className)}>{children}</td>;
}
