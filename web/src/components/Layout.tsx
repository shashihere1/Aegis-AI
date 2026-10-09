import { useEffect, useMemo, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  BadgeCheck,
  Bell,
  BookLock,
  Bot,
  ChevronDown,
  ChevronLeft,
  ClipboardCheck,
  Coins,
  Ghost,
  GitFork,
  KeyRound,
  LayoutGrid,
  LogOut,
  MessageSquare,
  MonitorDot,
  Moon,
  Plug,
  Search,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sparkles,
  Sun,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { api } from "../lib/api";
import { useAlerts, useFindings, usePendingApprovals, useStats } from "../lib/queries";
import { useSession } from "../lib/session";
import type { AgentPage } from "../lib/types";
import { Avatar, cx } from "./ui";
import { StudioLauncher } from "./StudioLauncher";
import { CopilotLauncher } from "../pages/Copilot";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  badge?: number;
  tone?: "warning" | "critical";
}

function useNav(): { section: string; items: NavItem[] }[] {
  const { can } = useSession();
  const stats = useStats().data;
  const alerts = useAlerts().data ?? [];
  const findings = useFindings().data ?? [];
  const approvals = usePendingApprovals().data ?? [];
  const open = alerts.filter((a) => a.status === "new");
  const injections = open.filter((a) => a.rule_id === "DET-01").length;
  const shadow = findings.filter((f) => f.status === "open").length;
  return [
    {
      section: "Registry",
      items: [
        { to: "/agents", label: "Agent Registry", icon: LayoutGrid },
        { to: "/shadow", label: "Shadow Agents", icon: Ghost, badge: shadow, tone: "warning" },
        { to: "/attestation", label: "Re-attestation", icon: ClipboardCheck, badge: stats?.pending_attestation, tone: "warning" },
        { to: "/activity", label: "Activity", icon: Activity },
      ],
    },
    {
      section: "Observability",
      items: [
        { to: "/soc", label: "SOC Dashboard", icon: MonitorDot, badge: open.length, tone: "critical" },
        { to: "/alerts", label: "Alert Management", icon: TriangleAlert },
        { to: "/lineage", label: "Agent Lineage", icon: GitFork },
        { to: "/injection", label: "Prompt Injection", icon: ShieldAlert, badge: injections, tone: "critical" },
        { to: "/usage", label: "Usage & Cost", icon: Coins },
        ...(can("soc-analyst", "auditor") ? [{ to: "/copilot", label: "Investigation Copilot", icon: Bot }] : []),
      ],
    },
    {
      section: "Access Control",
      items: [
        { to: "/access", label: "Agent Access Control", icon: KeyRound },
        { to: "/approvals", label: "Approvals", icon: BadgeCheck, badge: approvals.length, tone: "warning" },
        { to: "/tools", label: "MCP Servers & Tools", icon: Plug },
        { to: "/policies", label: "Policy Governance", icon: BookLock },
      ],
    },
    {
      section: "Assurance",
      items: [
        { to: "/evidence", label: "Audit Ledger", icon: ShieldCheck },
        { to: "/studio", label: "Demo Studio", icon: Sparkles },
        { to: "/assistant", label: "Bank Assistant", icon: MessageSquare },
      ],
    },
  ];
}

function Sidebar() {
  const { can } = useSession();
  return can("customer") ? <CustomerSidebar /> : <StaffSidebar />;
}

function CustomerSidebar() {
  return <aside className="hidden w-64 shrink-0 flex-col border-r border-line bg-panel lg:flex">
    <div className="flex items-center gap-3 border-b border-line px-5 py-5">
      <div className="grid size-11 place-items-center rounded-xl bg-accent-soft text-accent"><ShieldCheck className="size-6" /></div>
      <div><div className="font-semibold">Aegis AI</div><div className="text-xs text-muted">Synthetic banking workspace</div></div>
    </div>
    <nav className="flex-1 p-3" aria-label="Customer navigation">
      <div className="mb-2 px-3 pt-2 text-[11px] font-semibold tracking-wider text-faint uppercase">Your workspace</div>
      <NavLink to="/assistant" className="flex items-center gap-3 rounded-xl border border-accent/20 bg-accent-soft px-3 py-3 text-sm font-medium text-accent">
        <MessageSquare className="size-[18px]" />Bank Assistant
      </NavLink>
    </nav>
    <div className="m-3 rounded-xl border border-line bg-inset p-4">
      <div className="flex items-center gap-2 text-xs font-medium"><ShieldCheck className="size-4 text-accent" />You're in the customer view</div>
      <p className="mt-2 text-xs leading-relaxed text-muted">You review your actions. Staff approvals and audit records use separate roles.</p>
    </div>
  </aside>;
}

function StaffSidebar() {
  const nav = useNav();
  const { persona } = useSession();
  return (
    <aside className="flex w-72 shrink-0 flex-col border-r border-line bg-panel">
      <div className="flex items-center gap-3 border-b border-line px-5 py-5">
        <div className="grid size-11 place-items-center rounded-xl bg-accent-strong text-white">
          <ShieldCheck className="size-6" />
        </div>
        <div>
          <div className="font-semibold">ABN AMRO</div>
          <div className="text-sm text-accent">Aegis AI · Agent Foundry</div>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        {nav.map((group) => (
          <div key={group.section} className="mb-5">
            <div className="mb-1.5 px-3 text-[11px] font-semibold tracking-[0.14em] text-faint uppercase">{group.section}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cx(
                    "flex items-center gap-3 rounded-lg px-3 py-2 text-[15px] transition",
                    isActive ? "bg-accent-soft font-medium text-accent" : "text-muted hover:bg-hover hover:text-fg",
                  )
                }
              >
                <item.icon className="size-[18px]" />
                <span className="flex-1">{item.label}</span>
                {!!item.badge && (
                  <span
                    className={cx(
                      "rounded-md px-1.5 py-0.5 text-xs font-semibold",
                      item.tone === "critical" ? "bg-critical/18 text-critical-ink" : "bg-warning/18 text-warning-ink",
                    )}
                  >
                    {item.badge}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      {persona && (
        <div className="m-3 flex items-center gap-3 rounded-xl border border-line bg-inset p-3">
          <Avatar name={persona.name} />
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold">{persona.name}</div>
            <div className="truncate text-xs text-muted">{persona.roles.join(", ")}</div>
          </div>
        </div>
      )}
    </aside>
  );
}

function PersonaSwitcher() {
  const { personas, persona, source, config, switchTo, signIn, signOut } = useSession();
  const [open, setOpen] = useState(false);
  const sso = source === "sso";
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex h-10 items-center gap-2 rounded-xl border border-accent/40 bg-accent-soft px-3 text-sm font-medium text-accent"
        aria-haspopup="menu"
      >
        {sso ? <KeyRound className="size-4" /> : <ShieldCheck className="size-4" />}
        {persona?.name ?? "Sign in"}
        <span className="hidden text-xs text-muted xl:inline">· {sso ? "SSO" : persona?.roles[0]}</span>
        <ChevronDown className="size-4" />
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-2 max-h-[80vh] w-80 max-w-[calc(100vw-1.5rem)] overflow-y-auto rounded-xl border border-line-strong bg-card p-1.5 shadow-2xl" role="menu" onMouseLeave={() => setOpen(false)}>
          {config?.oidc && !sso && (
            <>
              <button
                role="menuitem"
                onClick={() => void signIn(window.location.pathname.replace(/^\/ui/, "") || "/")}
                className="flex w-full items-center gap-3 rounded-lg bg-accent-soft px-3 py-2.5 text-left text-sm font-medium text-accent hover:bg-hover"
              >
                <KeyRound className="size-4" /> Sign in with SSO
              </button>
              {personas.length > 0 && <div className="my-1 border-t border-line" />}
            </>
          )}
          {sso && persona && (
            <div className="px-3 py-2">
              <div className="text-sm font-medium">{persona.name}</div>
              <div className="text-xs text-muted">Signed in with SSO · {persona.roles.join(", ") || "no Aegis roles"}</div>
            </div>
          )}
          {personas.length > 0 && (
            <div className="px-3 py-2 text-xs text-faint">Act as a demo persona (development IdP). Each role sees and can do different things.</div>
          )}
          {personas.map((p) => (
            <button
              key={p.username}
              role="menuitem"
              disabled={p.status !== "active"}
              onClick={() => {
                setOpen(false);
                switchTo(p.username);
              }}
              className={cx(
                "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left hover:bg-hover disabled:opacity-40",
                !sso && p.username === persona?.username && "bg-accent-soft",
              )}
            >
              <Avatar name={p.name} size="sm" />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium">{p.name}</div>
                <div className="truncate text-xs text-muted">{p.status === "active" ? p.roles.join(", ") : "left the bank"}</div>
              </div>
            </button>
          ))}
          {sso && <div className="my-1 border-t border-line" />}
          {sso && (
            <button role="menuitem" onClick={signOut} className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm hover:bg-hover">
              <LogOut className="size-4 text-muted" /> Sign out
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function Notifications() {
  const approvals = usePendingApprovals().data ?? [];
  const alerts = (useAlerts().data ?? []).filter((a) => a.status === "new").slice(0, 5);
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const count = approvals.length + alerts.length;
  return (
    <div className="relative">
      <button onClick={() => setOpen((v) => !v)} className="relative grid size-10 place-items-center rounded-xl text-muted hover:bg-hover hover:text-fg" aria-label="Notifications">
        <Bell className="size-5" />
        {count > 0 && <span className="absolute top-1 right-1 grid min-w-5 place-items-center rounded-full bg-critical px-1 text-[11px] font-bold text-white">{count}</span>}
      </button>
      {open && (
        <div className="absolute right-0 z-30 mt-2 w-96 rounded-xl border border-line-strong bg-card p-1.5 shadow-2xl" onMouseLeave={() => setOpen(false)}>
          {count === 0 && <div className="px-3 py-6 text-center text-sm text-muted">Nothing needs your attention.</div>}
          {approvals.map((a) => (
            <button key={a.id} onClick={() => (setOpen(false), navigate("/approvals"))} className="flex w-full gap-3 rounded-lg px-3 py-2.5 text-left hover:bg-hover">
              <BadgeCheck className="mt-0.5 size-4 shrink-0 text-warning-ink" />
              <div className="text-sm">
                <div className="font-medium">Approval needed: {a.tool}</div>
                <div className="text-muted">{a.reasons[0]?.message}</div>
              </div>
            </button>
          ))}
          {alerts.map((a) => (
            <button key={a.id} onClick={() => (setOpen(false), navigate("/alerts"))} className="flex w-full gap-3 rounded-lg px-3 py-2.5 text-left hover:bg-hover">
              <Siren className={cx("mt-0.5 size-4 shrink-0", a.severity === "critical" ? "text-critical-ink" : "text-serious-ink")} />
              <div className="text-sm">
                <div className="font-medium">
                  {a.rule_id} · {a.severity}
                </div>
                <div className="text-muted">{a.title}</div>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const nav = useNav().flatMap((g) => g.items);
  const [q, setQ] = useState("");
  const navigate = useNavigate();
  const input = useRef<HTMLInputElement>(null);
  const agents = useQuery({
    queryKey: ["palette", q],
    queryFn: () => api<AgentPage>("/v1/agents", { query: { q, limit: 6 } }),
    enabled: open && q.length >= 2,
  });
  useEffect(() => {
    if (open) {
      setQ("");
      setTimeout(() => input.current?.focus(), 0);
    }
  }, [open]);
  const pages = useMemo(() => nav.filter((n) => n.label.toLowerCase().includes(q.toLowerCase())), [nav, q]);
  if (!open) return null;
  const go = (to: string) => (onClose(), navigate(to));
  return (
    <div className="fixed inset-0 z-50 flex justify-center bg-black/60 pt-[12vh] backdrop-blur-sm" onMouseDown={onClose}>
      <div className="h-fit w-full max-w-xl overflow-hidden rounded-2xl border border-line-strong bg-card shadow-2xl" onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search className="size-5 text-faint" />
          <input
            ref={input}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === "Escape" && onClose()}
            placeholder="Search agents by name, ID or owner, or jump to a page…"
            className="h-14 flex-1 bg-transparent outline-none placeholder:text-faint"
          />
        </div>
        <div className="max-h-96 overflow-auto p-2">
          {(agents.data?.items ?? []).map((a) => (
            <button key={a.id} onClick={() => go(`/agents/${a.id}`)} className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left hover:bg-hover">
              <Bot className="size-4 text-accent" />
              <span className="flex-1 text-sm">{a.name}</span>
              <span className="font-mono text-xs text-faint">{a.id}</span>
            </button>
          ))}
          {pages.map((p) => (
            <button key={p.to} onClick={() => go(p.to)} className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left hover:bg-hover">
              <p.icon className="size-4 text-muted" />
              <span className="text-sm">{p.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

const TITLES: Record<string, string> = {
  agents: "Agent Registry",
  shadow: "Shadow Agents",
  attestation: "Re-attestation",
  activity: "Activity",
  soc: "SOC Dashboard",
  alerts: "Alert Management",
  lineage: "Agent Lineage",
  injection: "Prompt Injection",
  usage: "Usage & Cost",
  access: "Agent Access Control",
  approvals: "Approvals",
  tools: "MCP Servers & Tools",
  policies: "Policy Governance",
  evidence: "Audit Ledger",
  studio: "Demo Studio",
  assistant: "Bank Assistant",
};

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("aegis.theme") || "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("aegis.theme", theme);
    } catch {
      /* not persisted */
    }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

export function Layout() {
  const { can, persona } = useSession();
  const customer = can("customer");
  const location = useLocation();
  const navigate = useNavigate();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [theme, toggleTheme] = useTheme();
  const section = location.pathname.split("/")[1] || "agents";
  useEffect(() => {
    if (customer && section !== "assistant") navigate("/assistant", { replace: true });
  }, [customer, section, navigate]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <div className="flex h-full">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className={cx("flex h-16 shrink-0 items-center gap-3 border-b border-line bg-panel/80 backdrop-blur", customer ? "px-3 sm:px-6" : "px-6")}>
          <button onClick={() => navigate(-1)} className="text-faint hover:text-fg" aria-label="Back">
            <ChevronLeft className="size-5" />
          </button>
          <div className={cx("flex items-center gap-2 text-sm", customer && "min-w-0 flex-1")}>
            <span className={cx("text-muted", customer && "hidden xl:inline")}>ABN AMRO</span>
            <span className={cx("text-faint", customer && "hidden xl:inline")}>›</span>
            <span className={cx("text-muted", customer && "hidden sm:inline")}>Aegis AI</span>
            <span className={cx("text-faint", customer && "hidden sm:inline")}>›</span>
            <span className={cx("font-semibold", customer && "truncate")}>{TITLES[section] ?? "Agent"}</span>
          </div>
          {!customer && <button
            onClick={() => setPaletteOpen(true)}
            className="mx-auto flex h-10 w-full max-w-md items-center gap-2 rounded-xl border border-line-strong bg-inset px-3 text-sm text-faint hover:border-accent/50"
          >
            <Search className="size-4" />
            <span className="flex-1 text-left">Search agents, owners, IDs…</span>
            <kbd className="rounded border border-line-strong px-1.5 text-xs">Ctrl K</kbd>
          </button>}
          <PersonaSwitcher />
          {!customer && <Notifications />}
          <button onClick={toggleTheme} className="grid size-10 place-items-center rounded-xl text-muted hover:bg-hover hover:text-fg" aria-label="Toggle theme">
            {theme === "dark" ? <Sun className="size-5" /> : <Moon className="size-5" />}
          </button>
        </header>
        <main className={cx("min-h-0 flex-1 overflow-y-auto", section === "assistant" ? "px-3 py-5 sm:px-6 lg:px-8 lg:py-7" : "px-8 py-7")}>
          <div className="mx-auto max-w-[1500px]">
            <Outlet />
          </div>
        </main>
      </div>
      {!customer && <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />}
      {!customer && section !== "copilot" && (can("soc-analyst", "auditor") ? <CopilotLauncher key={persona?.username} /> : <StudioLauncher />)}
    </div>
  );
}
