import { useMemo, useState } from "react";
import { Link } from "react-router";
import { CheckCircle2, CircleDashed, OctagonAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { clock } from "../lib/format";
import { responseSummary } from "../lib/alerts";
import { useAttention } from "../lib/attention";
import { isUnresolved, useAlerts, useDiscoveryStatus, useIdentityStatus, useLedgerVerify, useStats, useSummary } from "../lib/queries";
import { useSession } from "../lib/session";
import type { SocBucket } from "../lib/types";
import {
  Card,
  CardLink,
  Countdown,
  EmptyState,
  ErrorState,
  PageHeader,
  RowLink,
  SeverityPill,
  Skeleton,
  Stat,
  StatGroup,
  TBody,
  THead,
  Table,
  Tabs,
  Td,
  Th,
  TimeAgo,
  Tr,
  buttonClass,
  cx,
  focusRing,
} from "../components/ui";
import { BarList, CategoryBar, Legend, Sparkline, StackedBars, type StackSeries } from "../components/charts";

// Routine "allowed" volume stays in the de-emphasis grey; only the exceptions carry colour. Amber and orange
// are never adjacent in the stack.
const SERIES: StackSeries[] = [
  { key: "allow", label: "Allowed", color: "var(--chart-muted)" },
  { key: "require_approval", label: "Needs approval", color: "var(--warning)" },
  { key: "deny", label: "Denied", color: "var(--critical)" },
  { key: "rate_limited", label: "Rate-limited", color: "var(--serious)" },
];

const RANGES = [
  { value: "30", label: "30 min" },
  { value: "60", label: "1 hour" },
  { value: "360", label: "6 hours" },
] as const;
type Range = (typeof RANGES)[number]["value"];

/** Above an hour of 1-minute buckets, roll up into 10-minute bins so bars stay readable. */
function rollUp(buckets: SocBucket[], size: number): SocBucket[] {
  if (size <= 1) return buckets;
  const out: SocBucket[] = [];
  for (let i = 0; i < buckets.length; i += size) {
    const chunk = buckets.slice(i, i + size);
    out.push({
      t: chunk[0].t,
      allow: chunk.reduce((s, b) => s + b.allow, 0),
      require_approval: chunk.reduce((s, b) => s + b.require_approval, 0),
      deny: chunk.reduce((s, b) => s + b.deny, 0),
      rate_limited: chunk.reduce((s, b) => s + b.rate_limited, 0),
    });
  }
  return out;
}

const TONE = {
  critical: { icon: OctagonAlert, ring: "bg-critical/10 text-critical-ink", dot: "bg-critical" },
  warning: { icon: TriangleAlert, ring: "bg-warning/12 text-warning-ink", dot: "bg-warning" },
  good: { icon: CheckCircle2, ring: "bg-good/10 text-good-ink", dot: "bg-good" },
  info: { icon: CircleDashed, ring: "bg-selected text-muted", dot: "bg-accent" },
  neutral: { icon: CircleDashed, ring: "bg-selected text-muted", dot: "bg-faint" },
} as const;

function Check({ label, value, tone, to }: { label: string; value: string; tone: keyof typeof TONE; to: string }) {
  return (
    <li>
      <Link to={to} className={cx("flex items-center gap-2 rounded-md px-1 py-0.5 text-sm hover:bg-hover", focusRing)}>
        <span className={cx("size-1.5 rounded-full", TONE[tone].dot)} aria-hidden />
        <span className="text-muted">{label}</span>
        <span className="font-medium text-fg">{value}</span>
      </Link>
    </li>
  );
}

export function Overview() {
  const { persona } = useSession();
  const [range, setRange] = useState<Range>("30");
  const minutes = Number(range);
  const summary = useSummary(minutes);
  const alerts = useAlerts();
  const stats = useStats();
  const ledger = useLedgerVerify();
  const identity = useIdentityStatus();
  const discovery = useDiscoveryStatus();
  const attention = useAttention();
  const [view, setView] = useState<"chart" | "table">("chart");

  const s = summary.data;
  const unresolved = useMemo(() => (alerts.data ?? []).filter(isUnresolved), [alerts.data]);
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  for (const a of unresolved) bySeverity[a.severity] = (bySeverity[a.severity] ?? 0) + 1;
  const buckets = useMemo(() => rollUp(s?.buckets ? [...s.buckets].sort((a, b) => a.t.localeCompare(b.t)) : [], minutes > 60 ? 10 : 1), [s?.buckets, minutes]);
  const recent = unresolved.filter((a) => a.severity === "critical" || a.severity === "high").slice(0, 5);

  // The 5-second answer: worst state first.
  const ledgerBroken = ledger.data && !ledger.data.ok;
  const actionCount = attention.items.length;
  const posture: { tone: "critical" | "warning" | "good"; title: string; detail: string } = ledgerBroken
    ? { tone: "critical", title: "Action required: evidence ledger integrity is broken", detail: `The hash chain breaks at entry #${ledger.data?.broken_at_seq}.` }
    : bySeverity.critical
      ? { tone: "critical", title: `Action required: ${bySeverity.critical} critical alert${bySeverity.critical === 1 ? "" : "s"} unresolved`, detail: "Critical detections auto-suspend the agent; confirm the response and close the case." }
      : actionCount || bySeverity.high
        ? {
            tone: "warning",
            title: `${Math.max(actionCount, bySeverity.high)} item${Math.max(actionCount, bySeverity.high) === 1 ? "" : "s"} need attention`,
            detail: `${unresolved.length} unresolved alert${unresolved.length === 1 ? "" : "s"} · ${s?.pending_approvals ?? 0} approval${s?.pending_approvals === 1 ? "" : "s"} waiting · ${s?.open_findings ?? 0} shadow finding${s?.open_findings === 1 ? "" : "s"}`,
          }
        : { tone: "good", title: "All clear: every agent is operating within policy", detail: "No unresolved alerts, approvals or shadow findings right now." };
  const PostureIcon = TONE[posture.tone].icon;

  const lastRun = discovery.data?.idp_scan.last_run;
  const updated = summary.dataUpdatedAt ? new Date(summary.dataUpdatedAt).toISOString() : null;
  const hour = new Date().getHours();
  const greeting = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={`${greeting}${persona ? `, ${persona.name.split(" ")[0]}` : ""}. Security posture of every governed agent.`}
        meta={
          <>
            <span className="inline-flex items-center gap-1.5">
              <span className="live-dot size-1.5 rounded-full bg-good" aria-hidden /> Live
            </span>
            {updated && (
              <span>
                Updated <TimeAgo value={updated} />
              </span>
            )}
          </>
        }
        actions={<Tabs label="Time range" value={range} onChange={setRange} tabs={RANGES.map((r) => ({ value: r.value, label: r.label }))} />}
      />

      {/* Posture: health in one line */}
      <section className="mb-6 flex flex-wrap items-center gap-x-8 gap-y-4 rounded-xl border border-line bg-card p-5 shadow-card" aria-label="Security posture">
        <div className="flex min-w-[280px] flex-1 items-center gap-4">
          <span className={cx("grid size-10 shrink-0 place-items-center rounded-full", TONE[posture.tone].ring)}>
            <PostureIcon className="size-5" />
          </span>
          <div className="min-w-0">
            {alerts.isPending || ledger.isPending ? (
              <>
                <Skeleton className="h-5 w-72" />
                <Skeleton className="mt-2 h-4 w-96 max-w-full" />
              </>
            ) : (
              <>
                <h2 className="text-base font-semibold text-fg">{posture.title}</h2>
                <p className="mt-0.5 text-sm text-muted">{posture.detail}</p>
              </>
            )}
          </div>
        </div>
        <ul className="flex flex-wrap gap-x-5 gap-y-1" aria-label="Health checks">
          <Check
            label="Evidence ledger"
            to="/evidence"
            tone={!ledger.data ? "neutral" : ledger.data.ok ? "good" : "critical"}
            value={ledger.isError ? "Unavailable" : !ledger.data ? "Checking…" : ledger.data.ok ? `Verified · ${ledger.data.entries.toLocaleString()} entries` : `Broken at #${ledger.data.broken_at_seq}`}
          />
          <Check
            label="Identity provider"
            to="/shadow"
            tone={!identity.data ? "neutral" : identity.data.reachable ? "good" : "critical"}
            value={identity.isError ? "Unavailable" : !identity.data ? "Checking…" : identity.data.reachable ? "Reachable" : "Unreachable"}
          />
          <Check
            label="Discovery"
            to="/shadow"
            tone={!discovery.data ? "neutral" : !lastRun ? "neutral" : lastRun.ok ? "good" : "warning"}
            value={discovery.isError ? "Unavailable" : !discovery.data ? "Checking…" : !lastRun ? "No scan yet" : lastRun.ok ? "Last scan OK" : "Last scan failed"}
          />
        </ul>
      </section>

      {/* Actions + issues */}
      <div className="mb-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="Needs your attention" description="Work waiting on your role, most urgent first">
          {attention.loading ? (
            <div className="space-y-3 p-5">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-10" />
              ))}
            </div>
          ) : !attention.items.length ? (
            <EmptyState icon={ShieldCheck} title="You're all caught up">
              Nothing is waiting on your role. New approvals, alerts and reviews appear here.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-line">
              {attention.items.slice(0, 6).map((item) => (
                <li key={item.id} className="flex items-center gap-3 px-5 py-3">
                  <span className={cx("size-2 shrink-0 rounded-full", TONE[item.tone].dot)} aria-hidden />
                  <span className="sr-only">{item.tone === "critical" ? "Critical:" : item.tone === "warning" ? "Warning:" : ""}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium text-fg">{item.title}</div>
                    {item.detail && <div className="truncate text-caption text-muted">{item.detail}</div>}
                  </div>
                  {item.expiresAt && (
                    <span className="hidden text-caption text-muted sm:inline">
                      expires in <Countdown until={item.expiresAt} />
                    </span>
                  )}
                  <Link to={item.to} className={buttonClass("secondary", "sm")}>
                    {item.cta}
                  </Link>
                </li>
              ))}
            </ul>
          )}
          {attention.items.length > 6 && <div className="border-t border-line px-5 py-2.5 text-caption text-muted">+{attention.items.length - 6} more</div>}
        </Card>

        <Card title="Active issues" description="Unresolved alerts by severity" action={<CardLink to="/alerts">All alerts</CardLink>}>
          <div className="p-5">
            {alerts.isError ? (
              <ErrorState title="Couldn't load alerts" error={alerts.error} onRetry={() => void alerts.refetch()} />
            ) : alerts.isPending ? (
              <Skeleton className="h-32" />
            ) : (
              <>
                <div className="mb-4 flex items-baseline gap-2">
                  <span className="text-3xl font-semibold tracking-tight text-fg">{unresolved.length}</span>
                  <span className="text-sm text-muted">unresolved</span>
                </div>
                <CategoryBar
                  ariaLabel="Unresolved alerts by severity"
                  segments={[
                    { key: "critical", label: "Critical", value: bySeverity.critical, color: "var(--critical)", to: "/alerts" },
                    { key: "high", label: "High", value: bySeverity.high, color: "var(--serious)", to: "/alerts" },
                    { key: "medium", label: "Medium", value: bySeverity.medium, color: "var(--warning)", to: "/alerts" },
                    { key: "low", label: "Low", value: bySeverity.low, color: "var(--chart-muted)", to: "/alerts" },
                  ]}
                />
              </>
            )}
          </div>
        </Card>
      </div>

      {/* Key numbers */}
      {summary.isError ? (
        <Card className="mb-6">
          <ErrorState title="Couldn't load the decision summary" error={summary.error} onRetry={() => void summary.refetch()} />
        </Card>
      ) : (
        <StatGroup columns={5} className="mb-6">
          <Stat
            label="Decisions"
            value={s ? s.decisions.toLocaleString() : "—"}
            caption={`Last ${RANGES.find((r) => r.value === range)?.label}`}
            to="/activity"
            trend={s && <Sparkline label="Decisions per bucket" data={buckets.map((b) => b.allow + b.deny + b.require_approval + b.rate_limited)} />}
          />
          <Stat label="Denied" tone="critical" value={s ? s.totals.deny ?? 0 : "—"} caption={s ? `${(s.deny_rate * 100).toFixed(1)}% deny rate` : " "} to="/activity" />
          <Stat label="Exfiltration blocked" tone="critical" value={s ? s.alerts.exfiltration_blocked : "—"} caption="All time · trifecta breaker" to="/alerts" />
          <Stat label="Injections detected" tone="serious" value={s ? s.alerts.injections : "—"} caption="All time" to="/injection" />
          <Stat label="Active mandates" value={s ? s.active_mandates : "—"} caption="Right now" to="/access" />
        </StatGroup>
      )}

      {/* Trends */}
      <div className="mb-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title="Governed decisions"
          description={`Every tool call Aegis decided, per ${minutes > 60 ? "10 minutes" : "minute"}`}
          action={<Tabs label="View" value={view} onChange={setView} tabs={[{ value: "chart", label: "Chart" }, { value: "table", label: "Table" }]} />}
        >
          <div className="p-5">
            {!s ? (
              <Skeleton className="h-56" />
            ) : s.decisions === 0 ? (
              <EmptyState title="No decisions in this window">Start a Bank Assistant task to generate governed traffic.</EmptyState>
            ) : view === "chart" ? (
              <>
                <div className="mb-3">
                  <Legend series={SERIES} />
                </div>
                <StackedBars ariaLabel="Governed decisions by outcome over time" data={buckets} series={SERIES} xLabel={(b) => clock(b.t).slice(0, 5)} dimmed={summary.isPlaceholderData} />
              </>
            ) : (
              <div className="max-h-72 overflow-y-auto">
                <Table>
                  <THead>
                    <Th>Time</Th>
                    {SERIES.map((x) => (
                      <Th key={x.key} numeric>
                        {x.label}
                      </Th>
                    ))}
                  </THead>
                  <TBody>
                    {buckets
                      .filter((b) => b.allow + b.deny + b.require_approval + b.rate_limited > 0)
                      .map((b) => (
                        <Tr key={b.t}>
                          <Td className="tabular text-muted">{clock(b.t).slice(0, 5)}</Td>
                          {SERIES.map((x) => (
                            <Td key={x.key} numeric>
                              {b[x.key as keyof SocBucket]}
                            </Td>
                          ))}
                        </Tr>
                      ))}
                  </TBody>
                </Table>
              </div>
            )}
          </div>
        </Card>
        <Card title="Most denied agents" description="Denied actions in this window">
          <div className="p-5">
            {!s ? (
              <Skeleton className="h-40" />
            ) : s.top_denied.length ? (
              <BarList ariaLabel="Denied actions per agent" items={s.top_denied.map((d) => ({ key: d.agent_id, label: d.agent_name, value: d.denies, to: `/agents/${d.agent_id}` }))} />
            ) : (
              <EmptyState icon={CheckCircle2} title="No denied actions in this window" />
            )}
          </div>
        </Card>
      </div>

      {/* Detail */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="Unresolved critical and high alerts" action={<CardLink to="/alerts">View all</CardLink>}>
          {alerts.isPending ? (
            <div className="p-5">
              <Skeleton className="h-32" />
            </div>
          ) : !recent.length ? (
            <EmptyState icon={ShieldCheck} title="No unresolved critical or high alerts" />
          ) : (
            <Table>
              <THead>
                <Th>Severity</Th>
                <Th>Detection</Th>
                <Th>Automatic response</Th>
                <Th>Raised</Th>
              </THead>
              <TBody>
                {recent.map((a) => {
                  const response = responseSummary(a);
                  return (
                    <Tr key={a.id}>
                      <Td>
                        <SeverityPill severity={a.severity} />
                      </Td>
                      <Td>
                        <RowLink to="/alerts">{a.title}</RowLink>
                        <div className="mt-0.5 text-caption text-muted">
                          <span className="font-mono">{a.rule_id}</span> · {a.agent_name ?? "unknown agent"}
                        </div>
                      </Td>
                      <Td className={response?.tone === "critical" ? "text-critical-ink" : "text-muted"}>{response?.text ?? "—"}</Td>
                      <Td className="text-muted">
                        <TimeAgo value={a.ts} />
                      </Td>
                    </Tr>
                  );
                })}
              </TBody>
            </Table>
          )}
        </Card>

        <Card title="Agent inventory" action={<CardLink to="/agents">Registry</CardLink>}>
          <div className="p-5">
            {stats.isError ? (
              <ErrorState title="Couldn't load the registry" error={stats.error} onRetry={() => void stats.refetch()} />
            ) : !stats.data ? (
              <Skeleton className="h-40" />
            ) : (
              <>
                <div className="mb-4 flex items-baseline gap-2">
                  <span className="text-3xl font-semibold tracking-tight text-fg">{stats.data.total.toLocaleString()}</span>
                  <span className="text-sm text-muted">registered agents</span>
                </div>
                <CategoryBar
                  ariaLabel="Agents by status"
                  segments={[
                    { key: "active", label: "Active", value: stats.data.by_status.active ?? 0, color: "var(--chart-muted)", to: "/agents?status=active" },
                    { key: "pending", label: "Pending approval", value: stats.data.by_status.pending_approval ?? 0, color: "var(--warning)", to: "/agents?status=pending_approval" },
                    {
                      key: "suspended",
                      label: "Suspended or quarantined",
                      value: (stats.data.by_status.suspended ?? 0) + (stats.data.by_status.quarantined ?? 0),
                      color: "var(--critical)",
                      to: "/agents?status=suspended",
                    },
                    { key: "discovered", label: "Discovered (shadow)", value: stats.data.by_status.discovered ?? 0, color: "var(--serious)", to: "/shadow" },
                    { key: "other", label: "Draft or retired", value: (stats.data.by_status.draft ?? 0) + (stats.data.by_status.retired ?? 0), color: "var(--line-strong)" },
                  ]}
                />
                <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-4">
                  <Link to="/attestation" className={buttonClass("secondary", "sm")}>
                    {stats.data.pending_attestation} due for attestation
                  </Link>
                  <Link to="/shadow" className={buttonClass("secondary", "sm")}>
                    {s?.open_findings ?? 0} shadow findings
                  </Link>
                </div>
              </>
            )}
          </div>
        </Card>
      </div>
    </>
  );
}
