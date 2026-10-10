import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Command } from "cmdk";
import {
  Activity,
  BadgeCheck,
  Bell,
  BookLock,
  Bot,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  Coins,
  Ghost,
  GitFork,
  KeyRound,
  LayoutDashboard,
  LayoutGrid,
  LogOut,
  Menu,
  MessageSquare,
  Moon,
  Plug,
  Repeat,
  Route,
  Search,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sun,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { api } from "../lib/api";
import { APPROVAL_READERS, isUnresolved, useAlerts, useFindings, useLedgerVerify, usePendingApprovals, useStats } from "../lib/queries";
import { useSession } from "../lib/session";
import { useTheme } from "../lib/theme";
import type { AgentPage } from "../lib/types";
import { Avatar, IconButton, Kbd, cx, focusRing } from "./ui";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "./shadcn/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./shadcn/dropdown-menu";
import { CopilotLauncher } from "../pages/Copilot";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  badge?: number;
  tone?: "warning" | "critical";
}

function useNav(): { section: string | null; items: NavItem[] }[] {
  const { can } = useSession();
  const stats = useStats().data;
  const alerts = useAlerts().data ?? [];
  const findings = useFindings().data ?? [];
  const approvals = usePendingApprovals(can(...APPROVAL_READERS)).data ?? [];
  const fresh = alerts.filter((a) => a.status === "new");
  const criticalOpen = alerts.filter((a) => isUnresolved(a) && a.severity === "critical").length;
  const injections = fresh.filter((a) => a.rule_id === "DET-01").length;
  const shadow = findings.filter((f) => f.status === "open").length;
  return [
    { section: null, items: [{ to: "/overview", label: "Overview", icon: LayoutDashboard, badge: criticalOpen, tone: "critical" }] },
    {
      section: "Agents",
      items: [
        { to: "/agents", label: "Agent registry", icon: LayoutGrid },
        { to: "/shadow", label: "Shadow agents", icon: Ghost, badge: shadow, tone: "warning" },
        { to: "/attestation", label: "Re-attestation", icon: ClipboardCheck, badge: stats?.pending_attestation, tone: "warning" },
        { to: "/activity", label: "Activity", icon: Activity },
      ],
    },
    {
      section: "Detect & respond",
      items: [
        { to: "/alerts", label: "Alerts", icon: TriangleAlert, badge: fresh.length, tone: "critical" },
        { to: "/injection", label: "Prompt injection", icon: ShieldAlert, badge: injections, tone: "critical" },
        { to: "/lineage", label: "Agent lineage", icon: GitFork },
        ...(can("soc-analyst", "auditor") ? [{ to: "/copilot", label: "Investigation copilot", icon: Bot }] : []),
      ],
    },
    {
      section: "Access",
      items: [
        { to: "/access", label: "Access control", icon: KeyRound },
        { to: "/approvals", label: "Approvals", icon: BadgeCheck, badge: approvals.length, tone: "warning" },
        { to: "/tools", label: "MCP servers & tools", icon: Plug },
        { to: "/policies", label: "Policies", icon: BookLock },
      ],
    },
    {
      section: "Assurance",
      items: [
        { to: "/evidence", label: "Audit ledger", icon: ShieldCheck },
        { to: "/usage", label: "Usage & cost", icon: Coins },
      ],
    },
    {
      section: "Assistant",
      items: [
        { to: "/assistant", label: "Bank assistant", icon: MessageSquare },
        { to: "/walkthrough", label: "Security walkthrough", icon: Route },
      ],
    },
  ];
}

function Brand({ caption }: { caption: string }) {
  return (
    <Link to="/" className={cx("flex items-center gap-2.5 rounded-lg px-2 py-1", focusRing)}>
      <span className="grid size-8 place-items-center rounded-lg bg-fg text-page">
        <ShieldCheck className="size-[18px]" />
      </span>
      <span className="min-w-0 leading-tight">
        <span className="block text-sm font-semibold text-fg">Aegis</span>
        <span className="block truncate text-2xs text-muted">{caption}</span>
      </span>
    </Link>
  );
}

const navItemClass = ({ isActive }: { isActive: boolean }) =>
  cx(
    "group flex h-8 items-center gap-2.5 rounded-md px-2 text-sm transition-colors",
    focusRing,
    isActive ? "bg-selected font-medium text-fg" : "text-muted hover:bg-hover hover:text-fg",
  );

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const nav = useNav();
  return (
    <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-2" aria-label="Main">
      {nav.map((group, i) => (
        <div key={group.section ?? i}>
          {group.section && <div className="mb-1 px-2 text-2xs font-semibold tracking-wider text-faint uppercase">{group.section}</div>}
          <ul className="space-y-0.5">
            {group.items.map((item) => (
              <li key={item.to}>
                <NavLink to={item.to} className={navItemClass} onClick={onNavigate}>
                  {({ isActive }) => (
                    <>
                      <item.icon className={cx("size-4 shrink-0", isActive ? "text-fg" : "text-faint group-hover:text-muted")} />
                      <span className="flex-1 truncate">{item.label}</span>
                      {!!item.badge && (
                        <span
                          className={cx(
                            "tabular rounded px-1.5 text-2xs font-semibold",
                            item.tone === "critical" ? "bg-critical/10 text-critical-ink" : "bg-warning/12 text-warning-ink",
                          )}
                          aria-label={`${item.badge} need attention`}
                        >
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function SystemStatus() {
  const ledger = useLedgerVerify();
  const ok = ledger.data?.ok;
  return (
    <Link to="/evidence" className={cx("mx-3 mb-3 flex items-center gap-2 rounded-md px-2 py-2 text-caption text-muted hover:bg-hover", focusRing)}>
      <span className={cx("size-1.5 rounded-full", ok === undefined ? "bg-faint" : ok ? "bg-good" : "bg-critical")} aria-hidden />
      {ok === undefined ? "Checking evidence ledger…" : ok ? "Evidence ledger verified" : "Evidence ledger broken"}
    </Link>
  );
}

function StaffSidebar() {
  return (
    <aside className="hidden w-60 shrink-0 flex-col bg-panel lg:flex">
      <div className="px-3 pt-4 pb-3">
        <Brand caption="ABN AMRO · Agent Foundry" />
      </div>
      <NavList />
      <SystemStatus />
    </aside>
  );
}

function CustomerSidebar() {
  return (
    <aside className="hidden w-60 shrink-0 flex-col bg-panel lg:flex">
      <div className="px-3 pt-4 pb-3">
        <Brand caption="Synthetic banking workspace" />
      </div>
      <nav className="flex-1 px-3 py-2" aria-label="Customer navigation">
        <div className="mb-1 px-2 text-2xs font-semibold tracking-wider text-faint uppercase">Your workspace</div>
        <NavLink to="/assistant" className={navItemClass}>
          <MessageSquare className="size-4" /> Bank assistant
        </NavLink>
        <NavLink to="/walkthrough" className={navItemClass}>
          <Route className="size-4" /> Security walkthrough
        </NavLink>
      </nav>
      <p className="mx-3 mb-4 rounded-lg border border-line bg-card p-3 text-caption text-muted">
        You review your own actions. Staff approvals and audit records use separate roles.
      </p>
    </aside>
  );
}

function MobileNav({ open, onClose, customer }: { open: boolean; onClose: () => void; customer: boolean }) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent side="left" className="bg-page">
        <DialogTitle className="sr-only">Navigation</DialogTitle>
        <DialogDescription className="sr-only">Main navigation</DialogDescription>
        <div className="px-3 pt-4 pb-3">
          <Brand caption={customer ? "Synthetic banking workspace" : "ABN AMRO · Agent Foundry"} />
        </div>
        {customer ? (
          <nav className="px-3 py-2">
            <NavLink to="/assistant" className={navItemClass} onClick={onClose}>
              <MessageSquare className="size-4" /> Bank assistant
            </NavLink>
            <NavLink to="/walkthrough" className={navItemClass} onClick={onClose}>
              <Route className="size-4" /> Security walkthrough
            </NavLink>
          </nav>
        ) : (
          <NavList onNavigate={onClose} />
        )}
      </DialogContent>
    </Dialog>
  );
}

function AccountMenu() {
  const { persona, source, signOut } = useSession();
  const sso = source === "sso";
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cx("flex h-9 items-center gap-2 rounded-lg px-1.5 text-sm text-fg hover:bg-hover", focusRing)}
        aria-label={`Account menu, signed in as ${persona?.name ?? "unknown"}`}
      >
        <Avatar name={persona?.name ?? "?"} size="sm" />
        <span className="hidden max-w-36 truncate font-medium xl:inline">{persona?.name}</span>
        <ChevronDown className="size-4 text-faint" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72 max-w-[calc(100vw-1.5rem)]">
        {persona && (
          <DropdownMenuLabel className="py-2">
            <div className="text-sm font-medium text-fg">{persona.name}</div>
            <div className="mt-0.5 flex items-center gap-1.5 text-xs font-normal text-muted">
              {sso ? <KeyRound className="size-3.5" /> : <ShieldCheck className="size-3.5" />}
              {sso ? "Signed in with SSO" : "Demo login"} · {persona.roles.join(", ") || "no Aegis roles"}
            </div>
          </DropdownMenuLabel>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={signOut}>
          <Repeat className="size-4 text-muted" /> Switch account
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={signOut}>
          <LogOut className="size-4 text-muted" /> Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function Notifications() {
  const { can } = useSession();
  const approvals = usePendingApprovals(can(...APPROVAL_READERS)).data ?? [];
  const alerts = (useAlerts().data ?? []).filter((a) => a.status === "new").slice(0, 5);
  const navigate = useNavigate();
  const count = approvals.length + alerts.length;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cx("relative grid size-9 place-items-center rounded-lg text-muted transition-colors hover:bg-hover hover:text-fg", focusRing)}
        aria-label={count ? `Notifications, ${count} need attention` : "Notifications"}
      >
        <Bell className="size-[18px]" />
        {count > 0 && <span aria-hidden className="absolute top-2 right-2 size-2 rounded-full bg-critical ring-2 ring-page" />}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-96 max-w-[calc(100vw-1.5rem)]">
        <DropdownMenuLabel className="text-sm font-semibold text-fg">Notifications</DropdownMenuLabel>
        {count === 0 && <div className="px-3 pt-2 pb-6 text-center text-sm text-muted">Nothing needs your attention.</div>}
        {approvals.map((a) => (
          <DropdownMenuItem key={a.id} onSelect={() => navigate("/approvals")} className="items-start py-2.5">
            <BadgeCheck className="mt-0.5 size-4 text-warning-ink" />
            <div className="min-w-0 text-sm">
              <div className="font-medium">Approval needed: {a.tool}</div>
              <div className="truncate text-caption text-muted">{a.reasons[0]?.message}</div>
            </div>
          </DropdownMenuItem>
        ))}
        {alerts.map((a) => (
          <DropdownMenuItem key={a.id} onSelect={() => navigate("/alerts")} className="items-start py-2.5">
            <Siren className={cx("mt-0.5 size-4", a.severity === "critical" ? "text-critical-ink" : "text-serious-ink")} />
            <div className="min-w-0 text-sm">
              <div className="font-medium">
                {a.rule_id} · {a.severity}
              </div>
              <div className="truncate text-caption text-muted">{a.title}</div>
            </div>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="top-[14vh] max-w-xl translate-y-0">
        <DialogTitle className="sr-only">Search</DialogTitle>
        <DialogDescription className="sr-only">Search agents by name, ID or owner, or jump to a page</DialogDescription>
        {open && <PaletteBody onClose={onClose} />}
      </DialogContent>
    </Dialog>
  );
}

/** Mounted only while the palette is open, so its queries don't poll in the background. */
function PaletteBody({ onClose }: { onClose: () => void }) {
  const pages = useNav().flatMap((g) => g.items);
  const [q, setQ] = useState("");
  const navigate = useNavigate();
  const agents = useQuery({
    queryKey: ["palette", q],
    queryFn: () => api<AgentPage>("/v1/agents", { query: { q, limit: 6 } }),
    enabled: q.length >= 2,
  });
  const go = (to: string) => {
    onClose();
    navigate(to);
  };
  const itemClass = "flex cursor-pointer items-center gap-3 rounded-md px-3 py-2 text-sm text-fg data-[selected=true]:bg-hover";
  return (
        <Command shouldFilter={false} label="Search" className="flex flex-col">
          <div className="flex items-center gap-3 border-b border-line px-4">
            <Search className="size-4 text-faint" />
            <Command.Input
              value={q}
              onValueChange={setQ}
              placeholder="Search agents by name, ID or owner, or jump to a page…"
              className="h-12 flex-1 bg-transparent text-sm text-fg outline-none placeholder:text-faint"
            />
            <Kbd>Esc</Kbd>
          </div>
          <Command.List className="max-h-96 overflow-y-auto p-2">
            <Command.Empty className="px-3 py-6 text-center text-sm text-muted">No matches.</Command.Empty>
            {!!agents.data?.items.length && (
              <Command.Group heading="Agents" className="[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-faint [&_[cmdk-group-heading]]:uppercase">
                {agents.data.items.map((a) => (
                  <Command.Item key={a.id} value={`agent-${a.id}`} onSelect={() => go(`/agents/${a.id}`)} className={itemClass}>
                    <Bot className="size-4 text-muted" />
                    <span className="flex-1 truncate">{a.name}</span>
                    <span className="font-mono text-xs text-muted">{a.id}</span>
                  </Command.Item>
                ))}
              </Command.Group>
            )}
            <Command.Group heading="Pages" className="[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-faint [&_[cmdk-group-heading]]:uppercase">
              {pages
                .filter((p) => p.label.toLowerCase().includes(q.toLowerCase()))
                .map((p) => (
                  <Command.Item key={p.to} value={`page-${p.to}`} onSelect={() => go(p.to)} className={itemClass}>
                    <p.icon className="size-4 text-muted" />
                    {p.label}
                  </Command.Item>
                ))}
            </Command.Group>
          </Command.List>
        </Command>
  );
}

/** "Agents › Agent registry" from the current path. */
function Breadcrumb() {
  const nav = useNav();
  const { pathname } = useLocation();
  const crumbs: ReactNode[] = [];
  for (const group of nav)
    for (const item of group.items)
      if (pathname === item.to || pathname.startsWith(`${item.to}/`)) {
        if (group.section) crumbs.push(<span key="s" className="text-muted">{group.section}</span>);
        crumbs.push(
          pathname === item.to ? (
            <span key="p" className="font-medium text-fg">
              {item.label}
            </span>
          ) : (
            <Link key="p" to={item.to} className={cx("rounded text-muted hover:text-fg", focusRing)}>
              {item.label}
            </Link>
          ),
        );
        if (pathname !== item.to) crumbs.push(<span key="d" className="font-medium text-fg">Detail</span>);
      }
  return (
    <nav aria-label="Breadcrumb" className="hidden min-w-0 items-center gap-1.5 truncate text-sm md:flex">
      {crumbs.map((c, i) => (
        <span key={i} className="flex items-center gap-1.5">
          {i > 0 && <ChevronRight className="size-3.5 text-faint" />}
          {c}
        </span>
      ))}
    </nav>
  );
}

export function Layout() {
  const { can, persona } = useSession();
  const customer = can("customer");
  const location = useLocation();
  const navigate = useNavigate();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, toggleTheme] = useTheme();
  const section = location.pathname.split("/")[1] || "overview";
  const isMac = useMemo(() => /Mac|iPhone|iPad/.test(navigator.platform), []);
  useEffect(() => {
    if (customer && !["assistant", "walkthrough"].includes(section)) navigate("/assistant", { replace: true });
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
      {customer ? <CustomerSidebar /> : <StaffSidebar />}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-2 border-b border-line bg-page/85 px-4 backdrop-blur sm:px-6">
          <IconButton label="Open navigation" icon={Menu} className="lg:hidden" onClick={() => setMenuOpen(true)} />
          {!customer && <Breadcrumb />}
          <div className="flex-1" />
          {!customer && (
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className={cx(
                "flex h-9 w-full max-w-72 items-center gap-2 rounded-lg border border-line-strong bg-card px-3 text-sm text-faint shadow-card transition-colors hover:text-muted",
                focusRing,
              )}
            >
              <Search className="size-4" />
              <span className="flex-1 truncate text-left">Search…</span>
              <span className="hidden sm:inline">
                <Kbd>{isMac ? "⌘K" : "Ctrl K"}</Kbd>
              </span>
            </button>
          )}
          {!customer && <Notifications />}
          <IconButton label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"} icon={theme === "dark" ? Sun : Moon} onClick={toggleTheme} />
          <AccountMenu />
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className={cx("mx-auto max-w-[1440px]", section === "assistant" ? "px-3 py-6 sm:px-6 lg:px-8" : "px-4 py-8 sm:px-6 lg:px-10")}>
            <Outlet />
          </div>
        </main>
      </div>
      <MobileNav open={menuOpen} onClose={() => setMenuOpen(false)} customer={customer} />
      {!customer && <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />}
      {!customer && section !== "copilot" && can("soc-analyst", "auditor") && <CopilotLauncher key={persona?.username} />}
    </div>
  );
}
