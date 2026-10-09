import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../lib/api";
import { useSession } from "../lib/session";
import type { BankRun } from "../lib/bank-assistant";
import type { Lineage } from "../lib/types";
import { Card, JsonBlock, Pill } from "./ui";
import { LiveLineageGraph } from "../pages/Lineage";

type Proof = { graph: Lineage; alerts: { id: string; rule_id: string; title: string; reasons: unknown;
  forwarding?: { status: string; attempts: number; latency_ms: number | null } | null }[] };

export function RunGovernanceProof({ run }: { run: BankRun }) {
  const { persona, can } = useSession();
  const proof = useQuery({ queryKey: ["bank-run-proof", persona?.username, run.id], enabled: !!run.root_id,
    queryFn: () => api<Proof>(`/demo/api/agent/runs/${run.id}/proof`), refetchInterval: 2000 });
  if (!run.root_id) return null;
  return <div className="mt-5 space-y-4">
    <p className="break-all text-xs text-muted">Human: {run.subject} · Coordinator: {run.coordinator_id} · Root: {run.root_id}</p>
    {!can("customer") && run.coordinator_id && <Link className="text-sm text-accent" to={`/agents/${run.coordinator_id}`}>Open this coordinator / staff kill switch →</Link>}
    {proof.isError && <p role="alert" className="text-sm text-critical-ink">Governance evidence could not be loaded.</p>}
    {proof.data && <Card title="Live governance lineage"><LiveLineageGraph key={`${run.root_id}-${proof.data.graph.nodes.length}`} graph={proof.data.graph} />
      <p className="p-3 text-xs text-muted">Red dashed edges are denied attempts, not issued child credentials.</p></Card>}
    {proof.data?.alerts.map(alert => <div key={alert.id} className="rounded-xl border border-critical/30 p-4 text-sm">
      <p className="font-semibold">{alert.rule_id} · {alert.title}</p><p className="mt-1 font-mono text-xs text-muted">{alert.id}</p>
      <JsonBlock value={alert.reasons} />
      <Pill>SIEM: {alert.forwarding?.status ?? "not queued (forwarding disabled when raised)"}</Pill>
      {alert.forwarding?.latency_ms != null && <p className="mt-2 text-xs text-muted">Acknowledged delivery: {alert.forwarding.latency_ms.toFixed(0)} ms after alert creation</p>}
    </div>)}
  </div>;
}
