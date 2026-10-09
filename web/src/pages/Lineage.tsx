import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { BadgeCheck, Ban, Bot, Database, Flag, GitFork, User, Wrench, X, type LucideIcon } from "lucide-react";
import { api } from "../lib/api";
import { personLabel, timeAgo } from "../lib/format";
import type { CallOutcome, Decision, Lineage, LineageEdge, LineageNode, Task, TaskOutcome } from "../lib/types";
import { Card, Chip, DECISIONS, EmptyState, Loading, PageHeader, Pill, StatusPill, Tabs, cx } from "../components/ui";
import { DecisionTable } from "./Activity";
import { TraceWaterfall } from "../components/TraceWaterfall";

type Scope = "task" | "user" | "agent";
type Tone = "good" | "warning" | "serious" | "critical" | "neutral" | "info";

const HOURS = 24;

const KIND: Record<LineageNode["kind"], { icon: LucideIcon; ring: string; caption: string }> = {
  user: { icon: User, ring: "border-series/50", caption: "Initiating user" },
  agent: { icon: Bot, ring: "border-accent/50", caption: "Agent" },
  tool: { icon: Wrench, ring: "border-line-strong", caption: "Tool call" },
  data: { icon: Database, ring: "border-warning/50", caption: "Data read" },
  approval: { icon: BadgeCheck, ring: "border-warning/50", caption: "Human approval" },
  result: { icon: Flag, ring: "border-line-strong", caption: "Result" },
};

const RING: Record<Tone, string> = {
  good: "border-good/60",
  warning: "border-warning/60",
  serious: "border-serious/60",
  critical: "border-critical/60",
  neutral: "border-line-strong",
  info: "border-accent/50",
};

const CALL: Record<CallOutcome, { tone: Tone; label: string }> = {
  executed: { tone: "good", label: "executed" },
  tool_error: { tone: "critical", label: "tool error" },
  failed: { tone: "critical", label: "failed" },
  denied: { tone: "critical", label: "not executed" },
  rate_limited: { tone: "serious", label: "rate limited" },
  awaiting_approval: { tone: "warning", label: "held for approval" },
  not_recorded: { tone: "neutral", label: "outcome not recorded" },
};

const TASK: Record<TaskOutcome, Tone> = {
  completed: "good",
  in_progress: "info",
  waiting: "warning",
  blocked: "serious",
  expired: "neutral",
  failed: "critical",
  revoked: "critical",
};

const APPROVAL: Record<string, Tone> = { pending: "warning", approved: "good", consumed: "good", rejected: "critical" };

function nodeTone(n: LineageNode): Tone | undefined {
  if (n.kind === "result") return TASK[n.outcome as TaskOutcome];
  if (n.kind === "approval") return n.approval_status ? (APPROVAL[n.approval_status] ?? "neutral") : "warning";
  return undefined;
}

function outcomeSummary(outcomes: LineageNode["outcomes"]): string {
  return Object.entries(outcomes ?? {})
    .map(([k, n]) => `${n} ${CALL[k as CallOutcome]?.label ?? k}`)
    .join(" · ");
}

type FlowData = LineageNode & { blocked?: boolean; verdict?: string; rules?: string[]; aggregate?: boolean };

function FlowNode({ data }: NodeProps) {
  const n = data as unknown as FlowData;
  const k = KIND[n.kind];
  const tone = nodeTone(n);
  const verdict = n.verdict ? DECISIONS[n.verdict] : undefined;
  const call = n.kind === "tool" && !n.aggregate && n.outcome ? CALL[n.outcome as CallOutcome] : undefined;
  return (
    <div className={cx("rounded-xl border-2 bg-card px-3 py-2.5 shadow-lg", n.kind === "result" ? "w-60" : "w-48", n.blocked ? "border-critical/60" : tone ? RING[tone] : k.ring)}>
      <Handle type="target" position={Position.Left} className="!size-2 !border-0 !bg-line-strong" />
      <div className="flex items-center gap-2">
        <k.icon className={cx("size-4 shrink-0", n.blocked ? "text-critical-ink" : "text-muted")} />
        <div className="min-w-0">
          <div className={cx("truncate text-sm", n.kind === "result" ? "font-semibold" : "font-medium")} title={n.label}>
            {n.label}
          </div>
          <div className="text-[11px] text-faint">
            {n.kind === "agent" && n.depth !== undefined ? (n.depth ? `delegate · depth ${n.depth}` : "orchestrator") : k.caption}
            {n.kind === "agent" && !n.aggregate && n.status && n.status !== "active" ? ` · ${n.status}` : ""}
          </div>
        </div>
      </div>
      {n.kind === "result" && n.detail && <div className="mt-1.5 line-clamp-3 text-xs text-muted" title={n.detail}>{n.detail}</div>}
      {n.kind === "tool" && n.aggregate && n.outcomes && <div className="mt-1.5 text-[11px] text-muted">{outcomeSummary(n.outcomes)}</div>}
      {(verdict || call) && (
        <div className="mt-2 flex flex-wrap gap-1">
          {verdict && (
            <Pill tone={verdict.tone} icon={verdict.icon}>
              {verdict.label}
              {n.rules?.length ? ` · ${n.rules.join(", ")}` : ""}
            </Pill>
          )}
          {call && n.outcome !== "denied" && <Pill tone={call.tone}>{call.label}</Pill>}
        </div>
      )}
      <Handle type="source" position={Position.Right} className="!size-2 !border-0 !bg-line-strong" />
    </div>
  );
}

const nodeTypes = { aegis: FlowNode };

function edgeColor(e: LineageEdge, aggregate: boolean): string {
  if (e.kind === "resulted_in" || e.kind === "read") return "var(--line-strong)";
  if (e.kind === "approval") return "var(--warning)";
  const d = aggregate ? (e.decisions.deny ? "deny" : e.decisions.require_approval ? "require_approval" : e.decisions.rate_limited ? "rate_limited" : e.decision) : e.decision;
  return d === "deny" ? "var(--critical)" : d === "require_approval" ? "var(--warning)" : d === "rate_limited" ? "var(--serious)" : "var(--accent)";
}

function edgeLabel(e: LineageEdge, aggregate: boolean): string | undefined {
  if (!aggregate || e.kind === "resulted_in" || e.count < 2) return undefined;
  return e.decisions.deny ? `${e.count}× · ${e.decisions.deny} denied` : `${e.count}×`;
}

function layout(graph: Lineage, aggregate: boolean): { nodes: Node[]; edges: Edge[] } {
  const col: Record<string, number> = {};
  for (const n of graph.nodes) {
    if (n.kind === "user") col[n.id] = 0;
    if (n.kind === "agent") col[n.id] = 1 + (n.depth ?? 0);
  }
  for (const kind of ["invoked", "read", "approval"] as const) {
    for (const e of graph.edges.filter((x) => x.kind === kind)) col[e.to] = Math.max(col[e.to] ?? 0, (col[e.from] ?? 1) + 1);
  }
  const last = Math.max(0, ...Object.values(col));
  for (const n of graph.nodes) if (n.kind === "result") col[n.id] = last + 1;

  const rows: Record<number, number> = {};
  const verdicts = Object.fromEntries(graph.edges.filter((e) => e.kind === "invoked").map((e) => [e.to, e]));
  const nodes: Node[] = graph.nodes.map((n) => {
    const c = col[n.id] ?? 0;
    const r = (rows[c] = (rows[c] ?? -1) + 1);
    const v = verdicts[n.id];
    const blocked = n.kind === "tool" && (aggregate ? !!n.outcomes && Object.keys(n.outcomes).every((o) => o === "denied") : n.outcome === "denied");
    return {
      id: n.id,
      type: "aegis",
      position: { x: c * 262, y: r * 128 },
      data: { ...n, aggregate, blocked, verdict: aggregate ? undefined : v?.decision, rules: aggregate ? undefined : v?.rules },
    };
  });
  const edges: Edge[] = graph.edges.map((e, i) => {
    const color = edgeColor(e, aggregate);
    const onlyDenied = aggregate ? e.kind === "invoked" && Object.keys(e.decisions).every((d) => d === "deny") : e.decision === "deny";
    return {
      id: `e${i}`,
      source: e.from,
      target: e.to,
      data: { kind: e.kind },
      label: edgeLabel(e, aggregate),
      labelStyle: { fill: "var(--muted)", fontSize: 11 },
      labelBgStyle: { fill: "var(--card)" },
      animated: e.kind === "delegated_to" || e.kind === "initiated",
      style: {
        stroke: color,
        strokeWidth: aggregate ? 2 + Math.min(4, Math.log2(e.count)) : 2,
        strokeDasharray: onlyDenied ? "6 4" : e.kind === "resulted_in" ? "3 3" : undefined,
        cursor: e.kind === "invoked" ? "pointer" : undefined,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color },
    };
  });
  return { nodes, edges };
}

interface CallFilter {
  agentId: string;
  agentLabel: string;
  action: string;
}

export function LineagePage() {
  const { rootId } = useParams();
  const navigate = useNavigate();
  const [scope, setScope] = useState<Scope>("task");
  const [filter, setFilter] = useState<CallFilter | null>(null);
  const tasks = useQuery({ queryKey: ["tasks"], queryFn: () => api<Task[]>("/v1/tasks", { query: { limit: 40 } }), refetchInterval: 3000 });
  const selected = rootId ?? tasks.data?.[0]?.root_id;
  const task = tasks.data?.find((t) => t.root_id === selected);
  const aggregate = scope !== "task";
  const across = aggregate && task ? (scope === "user" ? { subject: task.subject } : { agent_id: task.agent_id }) : null;

  const graph = useQuery({
    queryKey: ["lineage", selected, scope, across],
    queryFn: () => (across ? api<Lineage>("/v1/lineage", { query: { ...across, hours: HOURS } }) : api<Lineage>(`/v1/lineage/${selected}`)),
    enabled: !!selected && (!aggregate || !!across),
    refetchInterval: 3000,
  });
  const decisions = useQuery({
    queryKey: ["decisions", "lineage", selected, scope, across],
    queryFn: () => api<Decision[]>("/v1/decisions", { query: across ? { ...across, hours: HOURS, limit: 200 } : { root_id: selected, limit: 100 } }),
    enabled: !!selected,
    refetchInterval: 3000,
  });
  const flow = useMemo(() => (graph.data ? layout(graph.data, aggregate) : null), [graph.data, aggregate]);
  const rows = (decisions.data ?? []).filter((d) => !filter || (d.agent_id === filter.agentId && d.action === filter.action));

  const changeScope = (s: Scope) => (setScope(s), setFilter(null));
  const openTask = (id: string) => (setFilter(null), navigate(`/lineage/${id}`));
  const onEdgeClick = (_: unknown, edge: Edge) => {
    if ((edge.data as { kind?: string } | undefined)?.kind !== "invoked") return;
    const agentNode = graph.data?.nodes.find((n) => n.id === edge.source);
    setFilter({ agentId: edge.source.replace(/^agent:/, ""), agentLabel: agentNode?.label ?? edge.source, action: edge.target.replace(/^tool:/, "") });
  };

  const title = !task
    ? "Lineage"
    : scope === "user"
      ? `All tasks for ${personLabel(task.subject)} · last ${HOURS} h`
      : scope === "agent"
        ? `All tasks involving ${task.agent_name ?? task.agent_id} · last ${HOURS} h`
        : task.intent;

  return (
    <>
      <PageHeader icon={GitFork} title="Agent Lineage" subtitle="End-to-end path from the initiating user, through every delegated agent and tool, to the approvals and the final result" />
      {tasks.isLoading ? (
        <Loading />
      ) : !tasks.data?.length ? (
        <Card>
          <EmptyState icon={GitFork} title="No tasks yet">
            Ask Bank Assistant to check document D-77 to create a governed task with a KYC delegation.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-[340px_1fr]">
          <Card title="Recent tasks" className="max-h-[calc(100vh-14rem)] overflow-auto">
            <ul className="divide-y divide-line">
              {tasks.data.map((t) => (
                <li key={t.root_id}>
                  <button
                    onClick={() => openTask(t.root_id)}
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
              title={title}
              action={!aggregate && task && <div className="flex flex-wrap gap-1.5">{task.intent_categories.map((c) => <Chip key={c} mono>{c}</Chip>)}</div>}
            >
              <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3">
                <Tabs<Scope>
                  value={scope}
                  onChange={changeScope}
                  tabs={[
                    { value: "task", label: "This task" },
                    { value: "user", label: "All tasks by this user" },
                    { value: "agent", label: "All tasks by this agent" },
                  ]}
                />
                {aggregate && graph.data && (
                  <span className="text-xs text-muted">
                    Merged view of {graph.data.tasks} {graph.data.tasks === 1 ? "task" : "tasks"} from the last {HOURS} h
                    {graph.data.truncated ? " (most recent 50 shown)" : ""} · line thickness = number of calls · click a tool call to filter the decisions
                  </span>
                )}
              </div>
              <div className="h-[440px]">
                {graph.data && !graph.data.nodes.length ? (
                  <EmptyState icon={GitFork} title="No tasks in this window">
                    Nothing matched in the last {HOURS} hours.
                  </EmptyState>
                ) : flow ? (
                  <ReactFlow
                    key={`${scope}-${selected}`}
                    nodes={flow.nodes}
                    edges={flow.edges}
                    nodeTypes={nodeTypes}
                    onEdgeClick={onEdgeClick}
                    fitView
                    fitViewOptions={{ padding: 0.12, maxZoom: 1.15 }}
                    proOptions={{ hideAttribution: true }}
                    nodesConnectable={false}
                  >
                    <Background gap={22} color="var(--line)" />
                    <Controls showInteractive={false} />
                  </ReactFlow>
                ) : (
                  <Loading />
                )}
              </div>
              {!aggregate && task?.status === "revoked" && <div className="border-t border-line px-5 py-3 text-sm text-critical-ink">Task revoked: {task.revoked_reason}</div>}
              {!aggregate && task?.status === "completed" && <div className="border-t border-line px-5 py-3 text-sm text-muted">Task closed by the agent: every mandate in it was revoked automatically.</div>}
            </Card>
            <Card
              title={aggregate ? `Decisions · last ${HOURS} h` : "Decisions in this task"}
              action={
                filter ? (
                  <button onClick={() => setFilter(null)} className="inline-flex items-center gap-1 rounded-md border border-line bg-inset px-2 py-0.5 text-xs text-muted hover:text-fg">
                    {filter.agentLabel} → {filter.action}
                    <X className="size-3" />
                  </button>
                ) : (
                  task && <Link to={`/agents/${task.agent_id}`} className="text-sm text-accent hover:underline">{task.agent_name} →</Link>
                )
              }
            >
              <div className="overflow-x-auto">{decisions.data ? <DecisionTable rows={rows} /> : <Loading />}</div>
            </Card>
            {!aggregate && selected && <TraceWaterfall rootId={selected} />}
          </div>
        </div>
      )}
    </>
  );
}
