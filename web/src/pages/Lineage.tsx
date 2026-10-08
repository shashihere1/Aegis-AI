import { useMemo } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Ban, Bot, Database, GitFork, User, Wrench, type LucideIcon } from "lucide-react";
import { api } from "../lib/api";
import { personLabel, timeAgo } from "../lib/format";
import type { Decision, Lineage, LineageNode, Task } from "../lib/types";
import { Card, Chip, DECISIONS, EmptyState, Loading, PageHeader, Pill, StatusPill, cx } from "../components/ui";
import { DecisionTable } from "./Activity";
import { TraceWaterfall } from "../components/TraceWaterfall";

const KIND: Record<LineageNode["kind"], { icon: LucideIcon; ring: string; caption: string }> = {
  user: { icon: User, ring: "border-series/50", caption: "Initiating user" },
  agent: { icon: Bot, ring: "border-accent/50", caption: "Agent" },
  tool: { icon: Wrench, ring: "border-line-strong", caption: "Tool call" },
  data: { icon: Database, ring: "border-warning/50", caption: "Data read" },
};

function FlowNode({ data }: NodeProps) {
  const n = data as unknown as LineageNode & { blocked?: boolean; verdict?: string; rules?: string[] };
  const k = KIND[n.kind];
  const verdict = n.verdict ? DECISIONS[n.verdict] : undefined;
  return (
    <div className={cx("w-48 rounded-xl border-2 bg-card px-3 py-2.5 shadow-lg", n.blocked ? "border-critical/60" : k.ring)}>
      <Handle type="target" position={Position.Left} className="!size-2 !border-0 !bg-line-strong" />
      <div className="flex items-center gap-2">
        <k.icon className={cx("size-4 shrink-0", n.blocked ? "text-critical-ink" : "text-muted")} />
        <div className="min-w-0">
          <div className="truncate text-sm font-medium" title={n.label}>
            {n.label}
          </div>
          <div className="text-[11px] text-faint">
            {n.kind === "agent" && n.depth !== undefined ? (n.depth ? `delegate · depth ${n.depth}` : "orchestrator") : k.caption}
            {n.status && n.status !== "active" ? ` · ${n.status}` : ""}
          </div>
        </div>
      </div>
      {verdict && (
        <div className="mt-2">
          <Pill tone={verdict.tone} icon={verdict.icon}>
            {verdict.label}
            {n.rules?.length ? ` · ${n.rules.join(", ")}` : ""}
          </Pill>
        </div>
      )}
      <Handle type="source" position={Position.Right} className="!size-2 !border-0 !bg-line-strong" />
    </div>
  );
}

const nodeTypes = { aegis: FlowNode };

function layout(graph: Lineage): { nodes: Node[]; edges: Edge[] } {
  const col: Record<string, number> = {};
  const agentCol = (n?: LineageNode) => 1 + (n?.depth ?? 0);
  for (const n of graph.nodes) {
    if (n.kind === "user") col[n.id] = 0;
    if (n.kind === "agent") col[n.id] = agentCol(n);
  }
  for (const e of graph.edges.filter((x) => x.kind === "invoked")) col[e.to] = Math.max(col[e.to] ?? 0, (col[e.from] ?? 1) + 1);
  for (const e of graph.edges.filter((x) => x.kind === "read")) col[e.to] = Math.max(col[e.to] ?? 0, (col[e.from] ?? 2) + 1);
  const rows: Record<number, number> = {};
  const blocked = new Set(graph.edges.filter((e) => e.decision === "deny").map((e) => e.to));
  const verdicts = Object.fromEntries(graph.edges.filter((e) => e.kind === "invoked").map((e) => [e.to, e]));
  const nodes: Node[] = graph.nodes.map((n) => {
    const c = col[n.id] ?? 0;
    const r = (rows[c] = (rows[c] ?? -1) + 1);
    const v = verdicts[n.id];
    return {
      id: n.id,
      type: "aegis",
      position: { x: c * 252, y: r * 112 },
      data: { ...n, blocked: blocked.has(n.id), verdict: v?.decision, rules: v?.rules },
    };
  });
  const color = (e: Lineage["edges"][number]) =>
    e.decision === "deny" ? "var(--critical)" : e.decision === "require_approval" ? "var(--warning)" : e.decision === "rate_limited" ? "var(--serious)" : e.kind === "read" ? "var(--line-strong)" : "var(--accent)";
  const edges: Edge[] = graph.edges.map((e, i) => ({
    id: `e${i}`,
    source: e.from,
    target: e.to,
    animated: e.kind === "delegated_to" || e.kind === "initiated",
    style: { stroke: color(e), strokeWidth: 2, strokeDasharray: e.decision === "deny" ? "6 4" : undefined },
    markerEnd: { type: MarkerType.ArrowClosed, color: color(e) },
  }));
  return { nodes, edges };
}

export function LineagePage() {
  const { rootId } = useParams();
  const navigate = useNavigate();
  const tasks = useQuery({ queryKey: ["tasks"], queryFn: () => api<Task[]>("/v1/tasks", { query: { limit: 40 } }), refetchInterval: 3000 });
  const selected = rootId ?? tasks.data?.[0]?.root_id;
  const graph = useQuery({ queryKey: ["lineage", selected], queryFn: () => api<Lineage>(`/v1/lineage/${selected}`), enabled: !!selected, refetchInterval: 3000 });
  const decisions = useQuery({ queryKey: ["decisions", "root", selected], queryFn: () => api<Decision[]>("/v1/decisions", { query: { root_id: selected, limit: 100 } }), enabled: !!selected, refetchInterval: 3000 });
  const flow = useMemo(() => (graph.data ? layout(graph.data) : null), [graph.data]);
  const task = tasks.data?.find((t) => t.root_id === selected);

  return (
    <>
      <PageHeader icon={GitFork} title="Agent Lineage" subtitle="End-to-end path from the initiating user, through every delegated agent, to the tools and data touched" />
      {tasks.isLoading ? (
        <Loading />
      ) : !tasks.data?.length ? (
        <Card>
          <EmptyState icon={GitFork} title="No tasks yet">
            Run scene S2 from Demo Studio to create a governed task with a delegation.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-[340px_1fr]">
          <Card title="Recent tasks" className="max-h-[calc(100vh-14rem)] overflow-auto">
            <ul className="divide-y divide-line">
              {tasks.data.map((t) => (
                <li key={t.root_id}>
                  <button
                    onClick={() => navigate(`/lineage/${t.root_id}`)}
                    className={cx("w-full px-4 py-3 text-left hover:bg-hover", t.root_id === selected && "bg-accent-soft")}
                  >
                    <div className="line-clamp-2 text-sm font-medium">{t.intent}</div>
                    <div className="mt-1 text-xs text-muted">
                      {personLabel(t.subject)} → {t.agents.map((a) => a.name.split("-")[0]).join(" → ")}
                    </div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <StatusPill status={t.status} />
                      {t.decisions.deny ? (
                        <span className="inline-flex items-center gap-1 text-xs text-critical-ink">
                          <Ban className="size-3" />
                          {t.decisions.deny} denied
                        </span>
                      ) : null}
                      <span className="ml-auto text-xs text-faint">{timeAgo(t.issued_at)}</span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          <div className="min-w-0 space-y-5">
            <Card
              title={task ? task.intent : "Lineage"}
              action={task && <div className="flex flex-wrap gap-1.5">{task.intent_categories.map((c) => <Chip key={c} mono>{c}</Chip>)}</div>}
            >
              <div className="h-[400px]">
                {flow ? (
                  <ReactFlow nodes={flow.nodes} edges={flow.edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.12, maxZoom: 1.15 }} proOptions={{ hideAttribution: true }} nodesConnectable={false}>
                    <Background gap={22} color="var(--line)" />
                    <Controls showInteractive={false} />
                  </ReactFlow>
                ) : (
                  <Loading />
                )}
              </div>
              {task?.status === "revoked" && <div className="border-t border-line px-5 py-3 text-sm text-critical-ink">Task revoked: {task.revoked_reason}</div>}
              {task?.status === "completed" && <div className="border-t border-line px-5 py-3 text-sm text-muted">Task closed by the agent: every mandate in it was revoked automatically.</div>}
            </Card>
            <Card title="Decisions in this task" action={task && <Link to={`/agents/${task.agent_id}`} className="text-sm text-accent hover:underline">{task.agent_name} →</Link>}>
              <div className="overflow-x-auto">{decisions.data ? <DecisionTable rows={decisions.data} /> : <Loading />}</div>
            </Card>
            {selected && <TraceWaterfall rootId={selected} />}
          </div>
        </div>
      )}
    </>
  );
}
