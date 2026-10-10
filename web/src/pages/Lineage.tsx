import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { BadgeCheck, Ban, Bot, Database, Flag, GitFork, User, Wrench, X, type LucideIcon } from "lucide-react";
import { api } from "../lib/api";
import { personLabel, timeAgo, titleCase } from "../lib/format";
import type { CallOutcome, Decision, Lineage, LineageEdge, LineageNode, Task, TaskOutcome } from "../lib/types";
import { Badge, Button, Callout, Card, Chip, DECISIONS, EmptyState, ErrorState, FilterSelect, Loading, PageHeader, SkeletonRows, StatusPill, Tabs, cx, focusRing } from "../components/ui";
import { DecisionTable } from "./Activity";
import { TraceWaterfall } from "../components/TraceWaterfall";

type Scope = "task" | "user" | "agent";
type Tone = "good" | "warning" | "serious" | "critical" | "neutral" | "info";

const HOURS = 24;

const KIND: Record<LineageNode["kind"], { icon: LucideIcon; caption: string }> = {
  user: { icon: User, caption: "Initiating user" },
  agent: { icon: Bot, caption: "Agent" },
  tool: { icon: Wrench, caption: "Tool call" },
  data: { icon: Database, caption: "Data read" },
  approval: { icon: BadgeCheck, caption: "Human approval" },
  result: { icon: Flag, caption: "Result" },
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
  // Status always carries a text label; the border only turns critical for a blocked call.
  const statusLabel = n.kind === "result" && n.outcome ? titleCase(n.outcome) : n.kind === "approval" ? titleCase(n.approval_status ?? "pending") : undefined;
  const showBlocked = n.blocked && !verdict;
  return (
    <div className={cx("rounded-xl border bg-card px-3 py-2.5 shadow-card", n.kind === "result" ? "w-60" : "w-48", n.blocked ? "border-critical/50" : "border-line-strong")}>
      <Handle type="target" position={Position.Left} className="!size-1.5 !min-h-0 !min-w-0 !border-0 !bg-line-strong" />
      <div className="flex items-center gap-2">
        <k.icon className={cx("size-4 shrink-0", n.blocked ? "text-critical-ink" : "text-muted")} aria-hidden />
        <div className="min-w-0">
          <div className={cx("truncate text-sm text-fg", n.kind === "result" ? "font-semibold" : "font-medium")} title={n.label}>
            {n.label}
          </div>
          <div className="text-2xs text-muted">
            {n.kind === "agent" && n.depth !== undefined ? (n.depth ? `delegate · depth ${n.depth}` : "orchestrator") : k.caption}
            {n.kind === "agent" && !n.aggregate && n.status && n.status !== "active" ? ` · ${n.status}` : ""}
          </div>
        </div>
      </div>
      {n.kind === "result" && n.detail && (
        <div className="mt-1.5 line-clamp-3 text-xs text-muted" title={n.detail}>
          {n.detail}
        </div>
      )}
      {n.kind === "tool" && n.aggregate && n.outcomes && <div className="mt-1.5 text-2xs text-muted">{outcomeSummary(n.outcomes)}</div>}
      {(verdict || call || statusLabel || showBlocked) && (
        <div className="mt-2 flex flex-wrap gap-1">
          {verdict && (
            <Badge tone={verdict.tone} icon={verdict.icon}>
              {verdict.label}
              {n.rules?.length ? ` · ${n.rules.join(", ")}` : ""}
            </Badge>
          )}
          {call && n.outcome !== "denied" && <Badge tone={call.tone}>{call.label}</Badge>}
          {statusLabel && <Badge tone={tone ?? "neutral"}>{statusLabel}</Badge>}
          {showBlocked && <Badge tone="critical">Blocked</Badge>}
        </div>
      )}
      <Handle type="source" position={Position.Right} className="!size-1.5 !min-h-0 !min-w-0 !border-0 !bg-line-strong" />
    </div>
  );
}

const nodeTypes = { aegis: FlowNode };

function edgeColor(e: LineageEdge, aggregate: boolean): string {
  if (e.kind === "resulted_in") return "var(--line-strong)";
  if (e.kind === "read") return "var(--muted)";
  if (e.kind === "approval") return "var(--warning)";
  const d = aggregate ? (e.decisions.deny ? "deny" : e.decisions.require_approval ? "require_approval" : e.decisions.rate_limited ? "rate_limited" : e.decision) : e.decision;
  return d === "deny" ? "var(--critical)" : d === "require_approval" ? "var(--warning)" : d === "rate_limited" ? "var(--serious)" : "var(--series)";
}

/** Legend for edge colours and dash styles; colour is never the only cue (denied is dashed, results are dotted). */
const EDGE_LEGEND: { key: string; label: string; color: string; dash?: string }[] = [
  { key: "allowed", label: "Allowed or delegated", color: "var(--series)" },
  { key: "approval", label: "Needs approval", color: "var(--warning)" },
  { key: "rate", label: "Rate-limited", color: "var(--serious)" },
  { key: "deny", label: "Denied (dashed)", color: "var(--critical)", dash: "6 4" },
  { key: "read", label: "Data read", color: "var(--muted)" },
  { key: "result", label: "Result (dotted)", color: "var(--line-strong)", dash: "3 3" },
];

function EdgeLegend() {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-caption text-muted" aria-label="Edge legend">
      {EDGE_LEGEND.map((l) => (
        <li key={l.key} className="flex items-center gap-1.5">
          <svg width="22" height="6" aria-hidden className="shrink-0">
            <line x1="1" x2="21" y1="3" y2="3" stroke={l.color} strokeWidth="2" strokeDasharray={l.dash} strokeLinecap="round" />
          </svg>
          {l.label}
        </li>
      ))}
    </ul>
  );
}

function edgeLabel(e: LineageEdge, aggregate: boolean): string | undefined {
  if (e.kind === "attempted_delegation") return `Attempt denied · ${e.rules?.join(", ") ?? ""}`;
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
  const verdicts = Object.fromEntries(graph.edges.filter((e) => ["invoked", "attempted_delegation"].includes(e.kind)).map((e) => [e.to, e]));
  const nodes: Node[] = graph.nodes.map((n) => {
    const c = col[n.id] ?? 0;
    const r = (rows[c] = (rows[c] ?? -1) + 1);
    const v = verdicts[n.id];
    const blocked = n.status === "attempted_only" || (n.kind === "tool" && (aggregate ? !!n.outcomes && Object.keys(n.outcomes).every((o) => o === "denied") : n.outcome === "denied"));
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

export function LiveLineageGraph({ graph }: { graph: Lineage }) {
  const flow = useMemo(() => layout(graph, false), [graph]);
  return <div className="h-[360px]" aria-label="Live lineage from recorded decisions">
    <ReactFlow nodes={flow.nodes} edges={flow.edges} nodeTypes={nodeTypes} fitView
      fitViewOptions={{ padding: 0.15, maxZoom: 1.1 }} proOptions={{ hideAttribution: true }}>
      <Background /><Controls />
    </ReactFlow>
  </div>;
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

  // Tool-call edges double as a keyboard-reachable filter (the graph edges themselves are pointer-only).
  const callEdges = useMemo(() => {
    const seen = new Set<string>();
    const out: { value: string; label: string; filter: CallFilter }[] = [];
    for (const e of graph.data?.edges ?? []) {
      if (e.kind !== "invoked") continue;
      const value = `${e.from}::${e.to}`;
      if (seen.has(value)) continue;
      seen.add(value);
      const agentLabel = graph.data?.nodes.find((n) => n.id === e.from)?.label ?? e.from;
      const action = e.to.replace(/^tool:/, "");
      out.push({ value, label: `${agentLabel} → ${action}`, filter: { agentId: e.from.replace(/^agent:/, ""), agentLabel, action } });
    }
    return out;
  }, [graph.data]);
  const filterValue = filter ? (callEdges.find((c) => c.filter.agentId === filter.agentId && c.filter.action === filter.action)?.value ?? "") : "";

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
      <PageHeader title="Agent lineage" subtitle="End-to-end path from the initiating user, through every delegated agent and tool, to the approvals and the final result." />
      {tasks.isLoading ? (
        <Card className="overflow-hidden">
          <SkeletonRows rows={5} cols={3} />
        </Card>
      ) : tasks.isError ? (
        <Card>
          <ErrorState title="Couldn't load tasks" error={tasks.error} onRetry={() => void tasks.refetch()} />
        </Card>
      ) : !tasks.data?.length ? (
        <Card>
          <EmptyState icon={GitFork} title="No tasks yet">
            Ask Bank Assistant to check document D-77 to create a governed task with a KYC delegation.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[340px_1fr]">
          <Card title="Recent tasks" className="max-h-[calc(100vh-14rem)] overflow-auto">
            <ul className="divide-y divide-line">
              {tasks.data.map((t) => (
                <li key={t.root_id}>
                  <button
                    type="button"
                    onClick={() => openTask(t.root_id)}
                    aria-current={t.root_id === selected ? "true" : undefined}
                    className={cx("w-full px-4 py-3 text-left transition-colors hover:bg-hover focus-visible:-outline-offset-2", focusRing, t.root_id === selected && "bg-accent-soft")}
                  >
                    <div className="line-clamp-2 text-sm font-medium text-fg">{t.intent}</div>
                    <div className="mt-1 text-caption text-muted">
                      {personLabel(t.subject)} → {t.agents.map((a) => a.name.split("-")[0]).join(" → ")}
                    </div>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <StatusPill status={t.status} />
                      {t.decisions.deny ? (
                        <span className="inline-flex items-center gap-1 text-caption text-critical-ink">
                          <Ban className="size-3" aria-hidden />
                          {t.decisions.deny} denied
                        </span>
                      ) : null}
                      <span className="ml-auto text-caption text-muted">{timeAgo(t.issued_at)}</span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          <div className="min-w-0 space-y-6">
            <Card
              title={title}
              action={
                !aggregate &&
                task && (
                  <div className="flex flex-wrap gap-1.5">
                    {task.intent_categories.map((c) => (
                      <Chip key={c} mono>
                        {c}
                      </Chip>
                    ))}
                  </div>
                )
              }
            >
              <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3">
                <Tabs<Scope>
                  label="Lineage scope"
                  value={scope}
                  onChange={changeScope}
                  tabs={[
                    { value: "task", label: "This task" },
                    { value: "user", label: "All tasks by this user" },
                    { value: "agent", label: "All tasks by this agent" },
                  ]}
                />
                {aggregate && graph.data && (
                  <span className="text-caption text-muted">
                    Merged view of {graph.data.tasks} {graph.data.tasks === 1 ? "task" : "tasks"} from the last {HOURS} h
                    {graph.data.truncated ? " (most recent 50 shown)" : ""} · line thickness = number of calls · click a tool-call edge, or use the tool call filter below, to filter the decisions
                  </span>
                )}
              </div>
              <div className="h-[440px]" role="region" aria-label="Lineage graph">
                {graph.isError ? (
                  <ErrorState title="Couldn't load the lineage graph" error={graph.error} onRetry={() => void graph.refetch()} />
                ) : graph.data && !graph.data.nodes.length ? (
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
                ) : graph.isLoading ? (
                  <Loading />
                ) : (
                  <EmptyState icon={GitFork} title="Nothing to merge yet">
                    Select a task from the list to see its user or agent across tasks.
                  </EmptyState>
                )}
              </div>
              <div className="border-t border-line px-5 py-3">
                <EdgeLegend />
              </div>
              {!aggregate && task?.status === "revoked" && (
                <div className="border-t border-line p-4">
                  <Callout tone="critical" title="Task revoked">
                    {task.revoked_reason}
                  </Callout>
                </div>
              )}
              {!aggregate && task?.status === "completed" && (
                <div className="border-t border-line p-4">
                  <Callout tone="info" title="Task closed by the agent">
                    Every mandate in it was revoked automatically.
                  </Callout>
                </div>
              )}
            </Card>
            <Card
              className="overflow-hidden"
              title={aggregate ? `Decisions · last ${HOURS} h` : "Decisions in this task"}
              action={
                <div className="flex flex-wrap items-center gap-2">
                  {callEdges.length > 0 && (
                    <FilterSelect
                      label="Tool call"
                      value={filterValue}
                      onChange={(v) => setFilter(callEdges.find((c) => c.value === v)?.filter ?? null)}
                      options={callEdges.map((c) => ({ value: c.value, label: c.label }))}
                    />
                  )}
                  {filter ? (
                    <>
                      <Chip>
                        {filter.agentLabel} → {filter.action}
                      </Chip>
                      <Button variant="ghost" size="sm" icon={X} onClick={() => setFilter(null)}>
                        Clear filter
                      </Button>
                    </>
                  ) : (
                    task && (
                      <Link to={`/agents/${task.agent_id}`} className={cx("rounded text-sm text-accent hover:underline", focusRing)}>
                        {task.agent_name} →
                      </Link>
                    )
                  )}
                </div>
              }
            >
              {decisions.isLoading ? (
                <SkeletonRows rows={4} cols={5} />
              ) : decisions.isError ? (
                <ErrorState title="Couldn't load decisions" error={decisions.error} onRetry={() => void decisions.refetch()} />
              ) : !rows.length ? (
                <EmptyState title={filter ? "No decisions for this tool call" : "No decisions recorded"}>
                  {filter ? "Clear the filter to see every decision." : "Decisions appear as the agents in this task call tools."}
                </EmptyState>
              ) : (
                <div className="overflow-x-auto">
                  <DecisionTable rows={rows} />
                </div>
              )}
            </Card>
            {!aggregate && selected && <TraceWaterfall rootId={selected} />}
          </div>
        </div>
      )}
    </>
  );
}
