import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "../lib/api";
import { useSession } from "../lib/session";
import type { BankRun } from "../lib/bank-assistant";
import type { Lineage } from "../lib/types";
import { Badge, Button, Callout, Card, JsonBlock, Skeleton, cx, focusRing, type Tone } from "./ui";
import { LiveLineageGraph } from "../pages/Lineage";

type Proof = { graph: Lineage; alerts: { id: string; rule_id: string; title: string; reasons: unknown;
  forwarding?: { status: string; attempts: number; latency_ms: number | null } | null }[] };

const linkClass = cx("inline-flex items-center gap-1 rounded text-sm font-medium text-accent hover:underline", focusRing);
const FORWARD_TONE: Record<string, Tone> = { delivered: "good", failed: "critical", pending: "warning", queued: "warning", retrying: "warning" };

export function RunGovernanceProof({ run }: { run: BankRun }) {
  const { persona, can } = useSession();
  const proof = useQuery({ queryKey: ["bank-run-proof", persona?.username, run.id], enabled: !!run.root_id,
    queryFn: () => api<Proof>(`/demo/api/agent/runs/${run.id}/proof`), refetchInterval: 2000 });
  if (!run.root_id) return null;
  return <div className="mt-5 space-y-4">
    <p className="text-caption break-all text-muted">Human: {run.subject} · Coordinator: <span className="font-mono">{run.coordinator_id}</span> · Root: <span className="font-mono">{run.root_id}</span></p>
    {!can("customer") && run.coordinator_id && <Link className={linkClass} to={`/agents/${run.coordinator_id}`}>Open this coordinator / staff kill switch →</Link>}
    {proof.isLoading && <Card><div className="space-y-3 p-5" role="status" aria-label="Loading governance evidence"><Skeleton className="h-3.5 w-40" /><Skeleton className="h-24 w-full" /></div></Card>}
    {proof.isError && <Callout tone="critical" title="Governance evidence could not be loaded"
      action={<Button size="sm" onClick={() => void proof.refetch()}>Try again</Button>}>{proof.error.message}</Callout>}
    {proof.data && <Card className="overflow-hidden" title="Live governance lineage"
      footer={<span className="text-muted">Red dashed edges are denied attempts, not issued child credentials.</span>}>
      <LiveLineageGraph key={`${run.root_id}-${proof.data.graph.nodes.length}`} graph={proof.data.graph} />
    </Card>}
    {proof.data && !proof.data.alerts.length && <p className="text-caption text-muted">No governance alerts were raised for this run.</p>}
    {proof.data?.alerts.map(alert => <Callout key={alert.id} tone="critical" title={<>{alert.rule_id} · {alert.title}</>}>
      <p className="font-mono text-xs break-all">{alert.id}</p>
      <div className="my-3"><JsonBlock value={alert.reasons} /></div>
      <Badge tone={alert.forwarding ? FORWARD_TONE[alert.forwarding.status] ?? "neutral" : "neutral"}>SIEM: {alert.forwarding?.status ?? "not queued (forwarding disabled when raised)"}</Badge>
      {alert.forwarding?.latency_ms != null && <p className="mt-2 text-caption">Acknowledged delivery: {alert.forwarding.latency_ms.toFixed(0)} ms after alert creation</p>}
    </Callout>)}
  </div>;
}
