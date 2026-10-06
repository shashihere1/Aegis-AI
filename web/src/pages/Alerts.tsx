import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Ban, TriangleAlert } from "lucide-react";
import { api } from "../lib/api";
import { useAlerts } from "../lib/queries";
import { useToast } from "../lib/toast";
import { clock, timeAgo, titleCase } from "../lib/format";
import type { Alert } from "../lib/types";
import { Button, Card, Drawer, EmptyState, JsonBlock, Loading, PageHeader, Select, SeverityPill, StatusPill, Td, Th } from "../components/ui";

const DETECTIONS: Record<string, string> = {
  "DET-01": "Prompt injection detected in tool output",
  "DET-02": "Exfiltration attempt blocked (lethal trifecta)",
  "DET-03": "Tool definition drift (possible rug pull)",
  "DET-04": "Burst of denied actions",
  "DET-05": "Revoked or expired mandate presented",
  "DET-07": "Unregistered agent activity",
  "DET-12": "Orphaned agent (owner left)",
};

export function Alerts() {
  const alerts = useAlerts();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [open, setOpen] = useState<Alert | null>(null);
  const update = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => api(`/v1/alerts/${id}`, { method: "PATCH", body: { status } }),
    onSuccess: (_r, v) => {
      toast("success", `Alert marked ${titleCase(v.status)}`);
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      setOpen((a) => (a ? { ...a, status: v.status } : a));
    },
    onError: (e: Error) => toast("error", "Update refused", e.message),
  });
  const rows = (alerts.data ?? []).filter((a) => (!severity || a.severity === severity) && (!status || a.status === status));

  return (
    <>
      <PageHeader icon={TriangleAlert} title="Alert Management" subtitle="Detections raised by the SOC engine, with the response the playbook already took" />
      <Card className="mb-4 flex flex-wrap gap-3 p-4">
        <Select label="Severity" value={severity} onChange={setSeverity} options={[{ value: "", label: "All severities" }, ...["critical", "high", "medium", "low"].map((v) => ({ value: v, label: titleCase(v) }))]} />
        <Select label="Status" value={status} onChange={setStatus} options={[{ value: "", label: "All statuses" }, ...["new", "triage", "investigating", "resolved", "false_positive"].map((v) => ({ value: v, label: titleCase(v) }))]} />
        <div className="ml-auto self-center text-sm text-muted">{rows.length} alerts</div>
      </Card>
      <Card className="overflow-x-auto">
        {alerts.isLoading ? (
          <Loading />
        ) : !rows.length ? (
          <EmptyState icon={TriangleAlert} title="No alerts">
            Run scene S4 (prompt-injection attack) or A4 (rug pull) from Demo Studio.
          </EmptyState>
        ) : (
          <table className="w-full">
            <thead className="border-b border-line bg-inset">
              <tr>
                <Th>Severity</Th>
                <Th>Detection</Th>
                <Th>Agent</Th>
                <Th>Response</Th>
                <Th>Raised</Th>
                <Th>Status</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((a) => (
                <tr key={a.id} onClick={() => setOpen(a)} className="cursor-pointer hover:bg-hover">
                  <Td>
                    <SeverityPill severity={a.severity} />
                  </Td>
                  <Td>
                    <div className="font-medium">{a.title}</div>
                    <div className="font-mono text-xs text-faint">
                      {a.rule_id} · {DETECTIONS[a.rule_id] ?? ""}
                    </div>
                  </Td>
                  <Td>{a.agent_id ? <Link to={`/agents/${a.agent_id}`} onClick={(e) => e.stopPropagation()} className="hover:text-accent">{a.agent_name ?? a.agent_id}</Link> : "—"}</Td>
                  <Td>
                    {a.actions_taken.length ? (
                      <span className="inline-flex items-center gap-1.5 text-sm text-critical-ink">
                        <Ban className="size-4" /> Suspended + {a.actions_taken[0].blast_radius.mandates.length} mandates revoked
                      </span>
                    ) : (
                      <span className="text-sm text-faint">—</span>
                    )}
                  </Td>
                  <Td className="text-muted">{timeAgo(a.ts)}</Td>
                  <Td>
                    <StatusPill status={a.status} />
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Drawer open={!!open} onClose={() => setOpen(null)} title={open ? `${open.rule_id} · ${open.title}` : ""}>
        {open && (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityPill severity={open.severity} />
              <StatusPill status={open.status} />
              <span className="text-sm text-muted">raised {clock(open.ts)}</span>
            </div>
            {open.actions_taken.map((act, i) => (
              <div key={i} className="rounded-xl border border-critical/30 bg-critical/8 p-4">
                <div className="mb-2 flex items-center gap-2 font-medium text-critical-ink">
                  <Ban className="size-4" /> Automatic response
                </div>
                <div className="text-sm text-muted">
                  Suspended the agent, disabled its identity, revoked <b className="text-fg">{act.blast_radius.mandates.length}</b> mandates across{" "}
                  <b className="text-fg">{act.blast_radius.agents_affected.length}</b> agents and cancelled {act.blast_radius.pending_approvals.length} pending approvals.
                </div>
              </div>
            ))}
            <div>
              <div className="mb-2 text-xs font-semibold tracking-wide text-muted uppercase">Triage</div>
              <div className="flex flex-wrap gap-2">
                {["triage", "investigating", "resolved", "false_positive"].map((st) => (
                  <Button key={st} roles={["soc-analyst"]} disabled={open.status === st} onClick={() => update.mutate({ id: open.id, status: st })}>
                    {titleCase(st)}
                  </Button>
                ))}
              </div>
            </div>
            {typeof open.evidence.mandate === "string" && (
              <Link to={`/access`} className="text-sm text-accent hover:underline">
                Mandate {String(open.evidence.mandate)}
              </Link>
            )}
            <div>
              <div className="mb-2 text-xs font-semibold tracking-wide text-muted uppercase">Evidence</div>
              <JsonBlock value={open.evidence} />
            </div>
          </div>
        )}
      </Drawer>
    </>
  );
}
