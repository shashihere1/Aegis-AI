import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Activity, EyeOff, Gauge } from "lucide-react";
import { api } from "../lib/api";
import { clock, personLabel } from "../lib/format";
import type { Decision } from "../lib/types";
import { Card, Chip, DECISIONS, DecisionPill, EmptyState, Loading, PageHeader, Tabs, Td, Th, cx } from "../components/ui";

export function DecisionTable({ rows, fresh }: { rows: Decision[]; fresh?: Set<string> }) {
  return (
    <table className="w-full">
      <thead className="border-b border-line bg-inset">
        <tr>
          <Th>Time</Th>
          <Th>Agent</Th>
          <Th>Action</Th>
          <Th>Decision</Th>
          <Th>Why</Th>
          <Th>Obligations</Th>
          <Th>For</Th>
          <Th className="text-right">Latency</Th>
          <Th></Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {rows.map((d) => (
          <tr key={d.id} className={cx("hover:bg-hover", fresh?.has(d.id) && "row-new")}>
            <Td className="tabular whitespace-nowrap text-muted">{clock(d.ts)}</Td>
            <Td className="whitespace-nowrap">
              {d.agent_id ? (
                <Link to={`/agents/${d.agent_id}`} className="font-medium hover:text-accent">
                  {d.agent_name ?? d.agent_id}
                </Link>
              ) : (
                <span className="text-faint">Aegis STS</span>
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
                <span className="text-xs text-faint">all rules passed</span>
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
            <Td className="tabular text-right text-muted">{d.latency_ms ? `${d.latency_ms.toFixed(0)} ms` : "—"}</Td>
            <Td>
              {d.root_id && (
                <Link to={`/lineage/${d.root_id}`} className="text-sm whitespace-nowrap text-accent hover:underline">
                  Lineage →
                </Link>
              )}
            </Td>
          </tr>
        ))}
      </tbody>
    </table>
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
        icon={Activity}
        title="Activity"
        subtitle="Every decision the Gateway and STS made, as it happens"
        actions={
          <span className="flex items-center gap-2 text-sm text-muted">
            <span className="live-dot size-2 rounded-full bg-good" /> Live
          </span>
        }
      />
      <div className="mb-4">
        <Tabs
          value={filter}
          onChange={setFilter}
          tabs={[{ value: "all", label: "All" }, ...Object.entries(DECISIONS).map(([value, d]) => ({ value, label: d.label }))]}
        />
      </div>
      <Card className="overflow-x-auto">
        {list.isLoading ? (
          <Loading />
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
