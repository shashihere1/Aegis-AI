import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { BadgeCheck, Ban, CheckCircle2, Gauge, Ghost, Hourglass, KeyRound, MonitorDot, ShieldAlert, ShieldCheck, ShieldX, Siren } from "lucide-react";
import { api } from "../lib/api";
import { clock, timeAgo } from "../lib/format";
import { useAlerts, useSummary } from "../lib/queries";
import type { LedgerVerify, SocBucket } from "../lib/types";
import { Card, EmptyState, Kpi, Loading, PageHeader, SeverityPill, Tabs, Td, Th } from "../components/ui";
import { HBars, Legend, StackedColumns, type StackSeries } from "../components/charts";

// Status palette, in the validated adjacent order (allow, approval, deny, rate-limited) so the amber and
// orange steps never sit next to each other in a stack.
const SERIES: StackSeries[] = [
  { key: "allow", label: "Allowed", color: "var(--good)", icon: CheckCircle2 },
  { key: "require_approval", label: "Needs approval", color: "var(--warning)", icon: Hourglass },
  { key: "deny", label: "Denied", color: "var(--critical)", icon: Ban },
  { key: "rate_limited", label: "Rate-limited", color: "var(--serious)", icon: Gauge },
];

export function SocDashboard() {
  const navigate = useNavigate();
  const summary = useSummary();
  const alerts = useAlerts();
  const ledger = useQuery({ queryKey: ["ledger-verify"], queryFn: () => api<LedgerVerify>("/v1/ledger/verify"), refetchInterval: 5000 });
  const [view, setView] = useState<"chart" | "table">("chart");
  const s = summary.data;
  if (!s) return <Loading />;
  const critical = (alerts.data ?? []).filter((a) => ["critical", "high"].includes(a.severity)).slice(0, 6);
  const nonEmpty = s.buckets.filter((b) => SERIES.some((x) => b[x.key as keyof SocBucket] as number));

  return (
    <>
      <PageHeader
        icon={MonitorDot}
        title="SOC Dashboard"
        subtitle={`Real-time posture of every governed agent · last ${s.window_minutes} minutes`}
        actions={
          <span className="flex items-center gap-2 text-sm text-muted">
            <span className="live-dot size-2 rounded-full bg-good" /> Live
          </span>
        }
      />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-3 2xl:grid-cols-6">
        <Kpi icon={ShieldCheck} label="Decisions" value={s.decisions} hint={`${(s.deny_rate * 100).toFixed(0)}% denied`} onClick={() => navigate("/activity")} />
        <Kpi icon={Siren} tone="critical" label="Open alerts" value={s.alerts.open} hint={`${s.alerts.by_severity.critical} critical`} onClick={() => navigate("/alerts")} />
        <Kpi icon={ShieldX} tone="critical" label="Exfiltration blocked" value={s.alerts.exfiltration_blocked} hint="Lethal-trifecta breaker" />
        <Kpi icon={ShieldAlert} tone="serious" label="Injections detected" value={s.alerts.injections} onClick={() => navigate("/injection")} hint="View detections" />
        <Kpi icon={BadgeCheck} tone="warning" label="Pending approvals" value={s.pending_approvals} onClick={() => navigate("/approvals")} hint="Open inbox" />
        <Kpi icon={KeyRound} tone="series" label="Active mandates" value={s.active_mandates} onClick={() => navigate("/access")} hint="Access control" />
      </div>

      <div className="mb-5 grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title="Decisions per minute, by outcome"
          action={<Tabs value={view} onChange={setView} tabs={[{ value: "chart", label: "Chart" }, { value: "table", label: "Table" }]} />}
        >
          <div className="p-5">
            {s.decisions === 0 ? (
              <EmptyState icon={MonitorDot} title="No decisions in this window">
                Start a Bank Assistant task to generate governed traffic.
              </EmptyState>
            ) : view === "chart" ? (
              <>
                <div className="mb-3">
                  <Legend series={SERIES} />
                </div>
                <StackedColumns data={s.buckets} series={SERIES} xLabel={(b) => clock(b.t).slice(0, 5)} />
              </>
            ) : (
              <table className="w-full">
                <thead className="border-b border-line">
                  <tr>
                    <Th>Minute</Th>
                    {SERIES.map((x) => (
                      <Th key={x.key} className="text-right">
                        {x.label}
                      </Th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {nonEmpty.map((b) => (
                    <tr key={b.t}>
                      <Td className="tabular">{clock(b.t).slice(0, 5)}</Td>
                      {SERIES.map((x) => (
                        <Td key={x.key} className="tabular text-right">
                          {b[x.key as keyof SocBucket]}
                        </Td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Card>
        <Card title="Agents with the most denied actions">
          <div className="p-5">
            {s.top_denied.length ? (
              <HBars rows={s.top_denied.map((d) => ({ label: d.agent_name, value: d.denies }))} unit="denied actions" />
            ) : (
              <EmptyState icon={CheckCircle2} title="No denied actions in this window" />
            )}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2" title="Critical and high alerts" action={<Link to="/alerts" className="text-sm text-accent hover:underline">All alerts →</Link>}>
          {!critical.length ? (
            <EmptyState icon={ShieldCheck} title="No critical or high alerts" />
          ) : (
            <ul className="divide-y divide-line">
              {critical.map((a) => (
                <li key={a.id} className="flex items-start gap-4 px-5 py-4">
                  <SeverityPill severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="font-medium">
                      <span className="mr-2 font-mono text-sm text-muted">{a.rule_id}</span>
                      {a.title}
                    </div>
                    <div className="mt-0.5 text-sm text-muted">
                      {a.agent_name ?? "—"} · {timeAgo(a.ts)}
                    </div>
                    {a.actions_taken.map((act, i) => (
                      <div key={i} className="mt-2 inline-flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/10 px-2.5 py-1 text-xs text-critical-ink">
                        <Ban className="size-3.5" /> Playbook suspended the agent · revoked {act.blast_radius.mandates.length} mandates across {act.blast_radius.agents_affected.length} agents
                      </div>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Governance posture">
          <div className="divide-y divide-line">
            {[
              {
                icon: ShieldCheck,
                label: "Evidence ledger",
                value: ledger.data ? (ledger.data.ok ? `Verified · ${ledger.data.entries} entries` : `Broken at #${ledger.data.broken_at_seq}`) : "…",
                ok: ledger.data?.ok ?? true,
                to: "/evidence",
              },
              { icon: KeyRound, label: "Active mandates", value: String(s.active_mandates), ok: true, to: "/access" },
              { icon: BadgeCheck, label: "Pending approvals", value: String(s.pending_approvals), ok: s.pending_approvals === 0, to: "/approvals" },
              { icon: Ghost, label: "Open shadow findings", value: String(s.open_findings), ok: s.open_findings === 0, to: "/shadow" },
            ].map((row) => (
              <button key={row.label} onClick={() => navigate(row.to)} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-hover">
                <row.icon className={row.ok ? "size-5 text-good-ink" : "size-5 text-warning-ink"} />
                <span className="flex-1 text-sm text-muted">{row.label}</span>
                <span className="text-sm font-medium">{row.value}</span>
              </button>
            ))}
          </div>
        </Card>
      </div>
    </>
  );
}
