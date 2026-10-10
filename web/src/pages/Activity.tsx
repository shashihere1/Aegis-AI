import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Activity, EyeOff, Gauge } from "lucide-react";
import { api } from "../lib/api";
import { clock, personLabel } from "../lib/format";
import type { Decision } from "../lib/types";
import { Card, Chip, DECISIONS, DecisionPill, EmptyState, ErrorState, PageHeader, SkeletonRows, TBody, THead, Table, TableToolbar, Tabs, Td, Th, Tr, cx, focusRing } from "../components/ui";

export function DecisionTable({ rows, fresh }: { rows: Decision[]; fresh?: Set<string> }) {
  return (
    <Table>
      <THead>
        <Th>Time</Th>
        <Th>Agent</Th>
        <Th>Action</Th>
        <Th>Decision</Th>
        <Th>Why</Th>
        <Th>Obligations</Th>
        <Th>For</Th>
        <Th numeric>Latency</Th>
        <Th>
          <span className="sr-only">Lineage</span>
        </Th>
      </THead>
      <TBody>
        {rows.map((d) => (
          <Tr key={d.id} className={cx(fresh?.has(d.id) && "row-new")}>
            <Td className="tabular whitespace-nowrap text-muted">{clock(d.ts)}</Td>
            <Td className="whitespace-nowrap">
              {d.agent_id ? (
                <Link to={`/agents/${d.agent_id}`} className={cx("rounded font-medium text-fg hover:text-accent", focusRing)}>
                  {d.agent_name ?? d.agent_id}
                </Link>
              ) : (
                <span className="text-muted">Aegis STS</span>
              )}
            </Td>
            <Td className="font-mono text-xs whitespace-nowrap">{d.action_label}</Td>
            <Td>
              <DecisionPill decision={d.decision} />
            </Td>
            <Td className="max-w-80">
              {d.reasons.length ? (
                <div className="space-y-0.5">
                  {d.reasons.slice(0, 2).map((r) => (
                    <div key={r.rule} className="truncate text-xs" title={r.message}>
                      <span className="font-mono font-semibold">{r.rule}</span> <span className="text-muted">{r.message}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-muted">All rules passed</span>
              )}
            </Td>
            <Td>
              <div className="flex flex-wrap gap-1">
                {d.obligations.map((o) =>
                  o.type === "redact" ? (
                    <Chip key="r">
                      <EyeOff className="mr-1 size-3" />
                      {d.redactions ? `${d.redactions} redacted` : "redact"}
                    </Chip>
                  ) : (
                    <Chip key="l">
                      <Gauge className="mr-1 size-3" />
                      {o.limit}/min
                    </Chip>
                  ),
                )}
              </div>
            </Td>
            <Td className="text-muted">{personLabel(d.subject)}</Td>
            <Td numeric className="text-muted">
              {d.latency_ms ? `${d.latency_ms.toFixed(0)} ms` : "—"}
            </Td>
            <Td>
              {d.root_id && (
                <Link to={`/lineage/${d.root_id}`} className={cx("rounded text-sm whitespace-nowrap text-accent hover:underline", focusRing)}>
                  Lineage →
                </Link>
              )}
            </Td>
          </Tr>
        ))}
      </TBody>
    </Table>
  );
}

export function ActivityFeed() {
  const [filter, setFilter] = useState<string>("all");
  const seen = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const list = useQuery({
    queryKey: ["decisions", "feed", filter],
    queryFn: () => api<Decision[]>("/v1/decisions", { query: { limit: 150, decision: filter === "all" ? undefined : filter } }),
    refetchInterval: 1500,
  });
  useEffect(() => {
    if (!list.data) return;
    const ids = new Set(list.data.map((d) => d.id));
    if (seen.current) setFresh(new Set([...ids].filter((id) => !seen.current!.has(id))));
    seen.current = ids;
  }, [list.data]);
  useEffect(() => {
    seen.current = null;
  }, [filter]);

  return (
    <>
      <PageHeader
        title="Activity"
        subtitle="Every decision the Gateway and STS made, as it happens"
        meta={
          <span className="inline-flex items-center gap-2">
            <span className="live-dot size-2 rounded-full bg-good" aria-hidden /> Live
          </span>
        }
      />
      <TableToolbar end={list.data && <span className="tabular">{list.data.length} shown</span>}>
        <Tabs
          label="Decision"
          value={filter}
          onChange={setFilter}
          tabs={[{ value: "all", label: "All" }, ...Object.entries(DECISIONS).map(([value, d]) => ({ value, label: d.label }))]}
        />
      </TableToolbar>
      <Card className="overflow-hidden">
        {list.isLoading ? (
          <SkeletonRows cols={7} />
        ) : list.isError ? (
          <ErrorState title="Couldn't load activity" error={list.error} onRetry={() => void list.refetch()} />
        ) : !list.data?.length ? (
          <EmptyState icon={Activity} title="No activity yet">
            Start a Bank Assistant task to see authorized tool decisions stream in.
          </EmptyState>
        ) : (
          <DecisionTable rows={list.data} fresh={fresh} />
        )}
      </Card>
    </>
  );
}
