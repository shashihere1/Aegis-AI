import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Card } from "./ui";

interface Span { span_id: string; trace_id: string; parent_id: string | null; name: string; service: string; start_ns: string; duration_ms: number; status: string }
export function TraceWaterfall({ rootId }: { rootId: string }) {
  const query = useQuery({ queryKey: ["traces", rootId], queryFn: () => api<{ spans: Span[]; queued: number; dropped: number; failed_flushes: number }>("/v1/traces", { query: { root_id: rootId } }), refetchInterval: 3000 });
  const spans = query.data?.spans ?? [];
  const earliest = spans.length ? spans.reduce((v, s) => BigInt(s.start_ns) < v ? BigInt(s.start_ns) : v, BigInt(spans[0].start_ns)) : 0n;
  const offset = (s: Span) => Number(BigInt(s.start_ns) - earliest) / 1e6;
  const total = Math.max(1, ...spans.map(s => offset(s) + s.duration_ms));
  const parents = new Map(spans.map(s => [s.span_id, s]));
  const depth = (s: Span) => { let d = 0; let p = s.parent_id; const seen = new Set<string>(); while (p && parents.has(p) && !seen.has(p) && d < 12) { seen.add(p); d++; p = parents.get(p)!.parent_id; } return d; };
  return <Card title="Real OpenTelemetry execution trace">
    <div className="space-y-3 overflow-x-auto p-5">
      <p className="text-xs text-faint">Measured SDK, control-plane, gateway, agent and MCP spans. The graph above is registry lineage; these are actual execution timings.</p>
      {spans.length === 0 ? <p className="text-sm text-muted">{query.error?.message ?? "No exported spans yet. Run a new task; old database records cannot manufacture traces."}</p> : <>
        <p className="break-all font-mono text-xs text-muted">Trace IDs: {[...new Set(spans.map(s => s.trace_id))].join(", ")}</p>
        <div className="min-w-[650px] space-y-1">{spans.map(s => <div key={s.span_id} className="grid grid-cols-[1fr_1fr_90px] items-center gap-3 text-xs">
          <div style={{ paddingLeft: depth(s) * 12 }} className="truncate" title={`${s.service}: ${s.name} (${s.span_id})`}>{s.service} · {s.name}</div>
          <div className="relative h-4 rounded bg-inset"><div className={`absolute h-4 rounded ${s.status === "ERROR" ? "bg-critical" : "bg-accent"}`} style={{ left: `${offset(s) / total * 100}%`, width: `${Math.max(0.5, s.duration_ms / total * 100)}%`, maxWidth: "100%" }} /></div>
          <div className="text-right text-muted">{s.duration_ms.toFixed(2)} ms</div>
        </div>)}</div>
      </>}
      {query.data && <p className="text-xs text-faint">Exporter: {query.data.queued} queued · {query.data.dropped} dropped · {query.data.failed_flushes} failed flushes</p>}
    </div>
  </Card>;
}
