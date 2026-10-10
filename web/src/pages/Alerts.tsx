import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { ShieldCheck } from "lucide-react";
import { useAlerts } from "../lib/queries";
import { DETECTIONS, responseSummary } from "../lib/alerts";
import { Investigation } from "../components/Investigation";
import { SiemForwarding } from "../components/SiemForwarding";
import { clock, titleCase } from "../lib/format";
import type { Alert } from "../lib/types";
import {
  Callout,
  Card,
  Drawer,
  EmptyState,
  ErrorState,
  FilterSelect,
  JsonBlock,
  PageHeader,
  RowLink,
  SearchInput,
  SeverityPill,
  SkeletonRows,
  StatusPill,
  TBody,
  THead,
  Table,
  TableToolbar,
  Tabs,
  Td,
  Th,
  TimeAgo,
  Tr,
  cx,
  focusRing,
} from "../components/ui";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const STATUSES = [
  { value: "unresolved", label: "Unresolved" },
  ...["new", "triage", "investigating", "resolved", "false_positive"].map((v) => ({ value: v, label: titleCase(v) })),
];
const UNRESOLVED = new Set(["new", "triage", "investigating"]);

export function Alerts() {
  const alerts = useAlerts();
  const [params, setParams] = useSearchParams();
  const severity = params.get("severity") ?? "all";
  const status = params.get("status") ?? "unresolved";
  const [q, setQ] = useState("");
  const [openId, setOpenId] = useState<string | null>(params.get("alert"));
  const set = (key: string, value: string, fallback: string) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value === fallback) next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: true },
    );

  const all = alerts.data ?? [];
  const byStatus = useMemo(() => all.filter((a) => (status === "" ? true : status === "unresolved" ? UNRESOLVED.has(a.status) : a.status === status)), [all, status]);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, byStatus.filter((a) => a.severity === s).length]));
  const needle = q.trim().toLowerCase();
  const rows = byStatus.filter(
    (a) =>
      (severity === "all" || a.severity === severity) &&
      (!needle || [a.title, a.rule_id, a.agent_name ?? "", DETECTIONS[a.rule_id] ?? ""].some((x) => x.toLowerCase().includes(needle))),
  );
  const open: Alert | undefined = all.find((a) => a.id === openId);

  return (
    <>
      <PageHeader title="Alerts" subtitle="Detections raised by the SOC engine, and the response the playbook already took." />

      <SiemForwarding />

      <TableToolbar end={<span className="tabular">{rows.length} shown{all.length >= 200 ? " · newest 200" : ""}</span>}>
        <Tabs
          label="Severity"
          value={severity}
          onChange={(v) => set("severity", v, "all")}
          tabs={[{ value: "all", label: "All", count: byStatus.length }, ...SEVERITIES.map((s) => ({ value: s, label: titleCase(s), count: counts[s] }))]}
        />
        <FilterSelect label="Status" value={status} onChange={(v) => set("status", v, "unresolved")} options={STATUSES} allLabel="Any" />
        <SearchInput label="Search alerts" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search detections or agents…" className="w-full sm:w-64" />
      </TableToolbar>

      <Card className="overflow-hidden">
        {alerts.isLoading ? (
          <SkeletonRows cols={5} />
        ) : alerts.isError ? (
          <ErrorState title="Couldn't load alerts" error={alerts.error} onRetry={() => void alerts.refetch()} />
        ) : !rows.length ? (
          <EmptyState icon={ShieldCheck} title={all.length ? "No alerts match these filters" : "No alerts"}>
            {all.length ? "Change the severity or status filter to see more." : "Alerts appear when Aegis detects suspicious requests or tool-definition drift."}
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <Th>Severity</Th>
              <Th>Detection</Th>
              <Th>Agent</Th>
              <Th>Automatic response</Th>
              <Th>Raised</Th>
              <Th>Status</Th>
            </THead>
            <TBody>
              {rows.map((a) => {
                const response = responseSummary(a);
                return (
                  <Tr key={a.id} onClick={() => setOpenId(a.id)}>
                    <Td>
                      <SeverityPill severity={a.severity} />
                    </Td>
                    <Td className="max-w-md">
                      <RowLink onClick={() => setOpenId(a.id)}>{a.title}</RowLink>
                      <div className="mt-0.5 truncate text-caption text-muted">
                        <span className="font-mono">{a.rule_id}</span>
                        {DETECTIONS[a.rule_id] && ` · ${DETECTIONS[a.rule_id]}`}
                      </div>
                    </Td>
                    <Td>
                      {a.agent_id ? (
                        <Link to={`/agents/${a.agent_id}`} onClick={(e) => e.stopPropagation()} className={cx("rounded whitespace-nowrap hover:text-accent", focusRing)}>
                          {a.agent_name ?? a.agent_id}
                        </Link>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </Td>
                    <Td className={response?.tone === "critical" ? "text-critical-ink" : "text-muted"}>{response?.text ?? "—"}</Td>
                    <Td className="text-muted">
                      <TimeAgo value={a.ts} />
                    </Td>
                    <Td>
                      <StatusPill status={a.status} />
                    </Td>
                  </Tr>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>

      <Drawer open={!!open} onClose={() => setOpenId(null)} title={open ? open.title : ""}>
        {open && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityPill severity={open.severity} />
              <StatusPill status={open.status} />
              <span className="text-caption text-muted">
                <span className="font-mono">{open.rule_id}</span> · raised {clock(open.ts)}
              </span>
            </div>
            {DETECTIONS[open.rule_id] && <p className="text-sm text-muted">{DETECTIONS[open.rule_id]}.</p>}
            {open.actions_taken.map((act, i) =>
              act.blast_radius ? (
                <Callout key={i} tone="critical" title="Automatic response">
                  Suspended the agent, disabled its identity, revoked <b className="text-fg">{act.blast_radius.mandates.length}</b> mandates across{" "}
                  <b className="text-fg">{act.blast_radius.agents_affected.length}</b> agents and cancelled {act.blast_radius.pending_approvals.length} pending approvals.
                </Callout>
              ) : (
                <Callout key={i} tone="info" title="Automatic response">
                  {act.action === "owner_reassigned" ? `Ownership reassigned${act.from ? ` from ${act.from}` : ""}${act.to ? ` to ${act.to}` : ""}.` : titleCase(act.action)}
                </Callout>
              ),
            )}
            <Investigation key={open.id} alertId={open.id} onUpdate={() => void alerts.refetch()} />
            {typeof open.evidence.mandate === "string" && (
              <Link to="/access" className={cx("inline-block rounded text-sm text-accent hover:underline", focusRing)}>
                Mandate {String(open.evidence.mandate)}
              </Link>
            )}
            <details className="group">
              <summary className={cx("cursor-pointer rounded text-sm font-medium text-fg", focusRing)}>Evidence</summary>
              <div className="mt-2">
                <JsonBlock value={open.evidence} />
              </div>
            </details>
          </div>
        )}
      </Drawer>
    </>
  );
}
