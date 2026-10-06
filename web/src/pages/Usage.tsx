import { useQuery } from "@tanstack/react-query";
import { Coins, Cpu, Timer } from "lucide-react";
import { api } from "../lib/api";
import { compact, euro } from "../lib/format";
import type { Usage } from "../lib/types";
import { Card, EmptyState, Kpi, Loading, PageHeader, Td, Th } from "../components/ui";
import { HBars } from "../components/charts";

export function UsagePage() {
  const usage = useQuery({ queryKey: ["usage"], queryFn: () => api<Usage[]>("/v1/usage"), refetchInterval: 4000 });
  const rows = usage.data ?? [];
  const tokens = rows.reduce((s, r) => s + r.input_tokens + r.output_tokens, 0);
  const cost = rows.reduce((s, r) => s + r.cost_eur, 0);
  const calls = rows.reduce((s, r) => s + r.calls, 0);
  const latency = calls ? rows.reduce((s, r) => s + r.avg_latency_ms * r.calls, 0) / calls : 0;

  return (
    <>
      <PageHeader icon={Coins} title="Usage & Cost" subtitle="Token use, cost and latency of every LLM call made through the Gateway, per agent" />
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Kpi icon={Cpu} tone="series" label="Tokens" value={compact(tokens)} hint={`${calls} LLM calls`} />
        <Kpi icon={Coins} tone="series" label="Cost" value={euro(cost, 4)} hint="At the configured price per 1K tokens" />
        <Kpi icon={Timer} tone="series" label="Average latency" value={`${latency.toFixed(0)} ms`} />
      </div>
      {usage.isLoading ? (
        <Loading />
      ) : !rows.length ? (
        <Card>
          <EmptyState icon={Coins} title="No LLM calls yet">
            LLM calls are recorded when agents use the Gateway's OpenAI-compatible endpoint, which forwards to the approved Azure OpenAI deployment.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
          <Card title="Cost by agent (EUR)">
            <div className="p-5">
              <HBars rows={rows.map((r) => ({ label: r.agent_name, value: r.cost_eur }))} unit="EUR" format={(v) => v.toFixed(5)} />
            </div>
          </Card>
          <Card title="By agent and model" className="xl:col-span-2">
            <table className="w-full">
              <thead className="border-b border-line bg-inset">
                <tr>
                  <Th>Agent</Th>
                  <Th>Model</Th>
                  <Th className="text-right">Calls</Th>
                  <Th className="text-right">Input</Th>
                  <Th className="text-right">Output</Th>
                  <Th className="text-right">Cost</Th>
                  <Th className="text-right">Avg latency</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map((r) => (
                  <tr key={r.agent_id + r.model}>
                    <Td className="font-medium">{r.agent_name}</Td>
                    <Td className="font-mono text-xs text-muted">{r.model}</Td>
                    <Td className="tabular text-right">{r.calls}</Td>
                    <Td className="tabular text-right">{r.input_tokens.toLocaleString()}</Td>
                    <Td className="tabular text-right">{r.output_tokens.toLocaleString()}</Td>
                    <Td className="tabular text-right">{euro(r.cost_eur, 5)}</Td>
                    <Td className="tabular text-right">{r.avg_latency_ms} ms</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>
      )}
    </>
  );
}
