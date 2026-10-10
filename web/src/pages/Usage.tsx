import { useQuery } from "@tanstack/react-query";
import { Coins } from "lucide-react";
import { api } from "../lib/api";
import { compact, euro } from "../lib/format";
import type { Usage } from "../lib/types";
import { Card, EmptyState, ErrorState, PageHeader, Skeleton, SkeletonRows, Stat, StatGroup, TBody, THead, Table, Td, Th, Tr } from "../components/ui";
import { BarList } from "../components/charts";

export function UsagePage() {
  const usage = useQuery({ queryKey: ["usage"], queryFn: () => api<Usage[]>("/v1/usage"), refetchInterval: 4000 });
  const rows = usage.data ?? [];
  const tokens = rows.reduce((s, r) => s + r.input_tokens + r.output_tokens, 0);
  const cost = rows.reduce((s, r) => s + r.cost_eur, 0);
  const calls = rows.reduce((s, r) => s + r.calls, 0);
  const latency = calls ? rows.reduce((s, r) => s + r.avg_latency_ms * r.calls, 0) / calls : 0;
  const ready = !!usage.data;

  return (
    <>
      <PageHeader title="Usage and cost" subtitle="Token use, cost and latency of every LLM call made through the Gateway, per agent." />

      <StatGroup columns={3} className="mb-8">
        <Stat label="Tokens" value={ready ? compact(tokens) : "—"} caption={ready ? `${calls.toLocaleString()} LLM calls` : " "} />
        <Stat label="Cost" value={ready ? euro(cost, 4) : "—"} caption="At the configured price per 1K tokens" />
        <Stat label="Average latency" value={ready ? `${latency.toFixed(0)} ms` : "—"} caption="Weighted by calls" />
      </StatGroup>

      {usage.isLoading ? (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <Card title="Cost by agent">
            <div className="space-y-2 p-5" role="status" aria-label="Loading">
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-8" />
              ))}
            </div>
          </Card>
          <Card title="By agent and model" className="overflow-hidden xl:col-span-2">
            <SkeletonRows cols={6} />
          </Card>
        </div>
      ) : usage.isError ? (
        <Card>
          <ErrorState title="Couldn't load usage" error={usage.error} onRetry={() => void usage.refetch()} />
        </Card>
      ) : !rows.length ? (
        <Card>
          <EmptyState icon={Coins} title="No LLM calls yet">
            LLM calls are recorded when agents use the Gateway's OpenAI-compatible endpoint, which forwards to the approved Azure OpenAI deployment.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <Card title="Cost by agent" description="EUR, all recorded calls">
            <div className="p-5">
              <BarList ariaLabel="Cost in EUR by agent" items={rows.map((r) => ({ key: r.agent_id + r.model, label: r.agent_name, value: r.cost_eur }))} format={(v) => v.toFixed(5)} />
            </div>
          </Card>
          <Card title="By agent and model" className="overflow-hidden xl:col-span-2">
            <Table>
              <THead>
                <Th>Agent</Th>
                <Th>Model</Th>
                <Th numeric>Calls</Th>
                <Th numeric>Input</Th>
                <Th numeric>Output</Th>
                <Th numeric>Cost</Th>
                <Th numeric>Avg latency</Th>
              </THead>
              <TBody>
                {rows.map((r) => (
                  <Tr key={r.agent_id + r.model}>
                    <Td className="font-medium">{r.agent_name}</Td>
                    <Td className="font-mono text-xs text-muted">{r.model}</Td>
                    <Td numeric>{r.calls}</Td>
                    <Td numeric>{r.input_tokens.toLocaleString()}</Td>
                    <Td numeric>{r.output_tokens.toLocaleString()}</Td>
                    <Td numeric>{euro(r.cost_eur, 5)}</Td>
                    <Td numeric>{r.avg_latency_ms} ms</Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </Card>
        </div>
      )}
    </>
  );
}
