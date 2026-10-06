import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Ghost, Radar, ShieldBan, UserPlus } from "lucide-react";
import { post } from "../lib/api";
import { useFindings, useStats } from "../lib/queries";
import { useToast } from "../lib/toast";
import { timeAgo } from "../lib/format";
import type { Finding } from "../lib/types";
import { Button, Card, Chip, EmptyState, Kpi, Loading, Modal, PageHeader, Pill, StatusPill } from "../components/ui";
import { AgentForm, type AgentDraft } from "./RegisterAgent";

const SOURCE_LABEL: Record<string, string> = { gateway: "Gateway traffic", idp: "IdP scan", otel: "Telemetry", repo: "Code scan", cloud: "Cloud scan" };

function evidenceSummary(f: Finding): string {
  const e = f.evidence[f.evidence.length - 1] ?? {};
  if (e.user_agent) return `${e.user_agent} → ${String(e.resource ?? "").replace(/^https?:\/\/[^/]+/, "")}`;
  if (e.client_id) return `IdP client "${e.client_id}" (${e.name ?? "no name"}) exists outside the registry`;
  return JSON.stringify(e);
}

export function ShadowAgents() {
  const findings = useFindings();
  const stats = useStats().data;
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [claiming, setClaiming] = useState<Finding | null>(null);

  const scan = useMutation({
    mutationFn: () => post<{ found: string[] }>("/v1/discovery/scan"),
    onSuccess: (r) => (toast("success", "IdP scan complete", `${r.found.length} unmanaged identities`), queryClient.invalidateQueries({ queryKey: ["findings"] })),
    onError: (e: Error) => toast("error", "Scan refused", e.message),
  });
  const quarantine = useMutation({
    mutationFn: (f: Finding) => post(`/v1/discovery/findings/${f.id}/quarantine`),
    onSuccess: () => (toast("success", "Quarantined", "The Gateway now blocks this caller and its IdP identity is disabled."), queryClient.invalidateQueries()),
    onError: (e: Error) => toast("error", "Quarantine refused", e.message),
  });
  const claim = useMutation({
    mutationFn: ({ f, d }: { f: Finding; d: AgentDraft }) => post<{ agent_id: string }>(`/v1/discovery/findings/${f.id}/claim`, d),
    onSuccess: (r) => {
      toast("success", "Claimed into the registry as a draft", "It now goes through the normal approval flow.");
      setClaiming(null);
      queryClient.invalidateQueries();
      navigate(`/agents/${r.agent_id}`);
    },
    onError: (e: Error) => toast("error", "Claim refused", e.message),
  });

  const list = findings.data ?? [];
  const open = list.filter((f) => f.status === "open");

  return (
    <>
      <PageHeader
        icon={Ghost}
        title="Shadow Agents"
        subtitle="Agents acting without a governed identity, found from Gateway traffic and IdP scans"
        actions={
          <Button icon={Radar} roles={["soc-analyst", "admin"]} loading={scan.isPending} onClick={() => scan.mutate()}>
            Run IdP scan
          </Button>
        }
      />
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Kpi icon={Ghost} tone="warning" label="Open findings" value={open.length} />
        <Kpi icon={ShieldBan} tone="critical" label="Quarantined" value={list.filter((f) => f.status === "quarantined").length} />
        <Kpi icon={Fingerprint} label="Discovered in inventory" value={stats?.shadow ?? "—"} hint="Imported from cloud inventories" onClick={() => navigate("/agents")} />
      </div>
      <Card title="Findings">
        {findings.isLoading ? (
          <Loading />
        ) : !list.length ? (
          <EmptyState icon={Radar} title="No shadow agents found yet">
            Run scene S5 from Demo Studio, or call any MCP server through the Gateway without a Mandate.
          </EmptyState>
        ) : (
          <ul className="divide-y divide-line">
            {list.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-4 px-5 py-4">
                <div className="grid size-10 place-items-center rounded-xl bg-warning/12 text-warning-ink">
                  <Ghost className="size-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-medium">{f.fingerprint}</span>
                    <StatusPill status={f.status} />
                    {f.sources.map((s) => (
                      <Chip key={s}>{SOURCE_LABEL[s] ?? s}</Chip>
                    ))}
                  </div>
                  <div className="mt-1 truncate text-sm text-muted">{evidenceSummary(f)}</div>
                  <div className="mt-0.5 text-xs text-faint">
                    {f.hits} {f.hits === 1 ? "signal" : "signals"} · first seen {timeAgo(f.first_seen)} · last seen {timeAgo(f.last_seen)}
                  </div>
                </div>
                {f.status === "open" ? (
                  <div className="flex gap-2">
                    <Button icon={UserPlus} roles={["agent-developer", "agent-owner"]} onClick={() => setClaiming(f)}>
                      Claim
                    </Button>
                    <Button variant="danger" icon={ShieldBan} roles={["soc-analyst"]} loading={quarantine.isPending && quarantine.variables?.id === f.id} onClick={() => quarantine.mutate(f)}>
                      Quarantine
                    </Button>
                  </div>
                ) : (
                  f.agent_id && (
                    <Pill tone="accent" className="cursor-pointer" icon={UserPlus}>
                      <span onClick={() => navigate(`/agents/${f.agent_id}`)}>Registered as {f.agent_id}</span>
                    </Pill>
                  )
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Modal open={!!claiming} onClose={() => setClaiming(null)} title="Claim this agent" wide>
        <p className="mb-4 text-sm text-muted">Claiming creates a draft registration with an accountable owner. Its unmanaged identity is disabled; it receives a governed identity once approved.</p>
        {claiming && (
          <AgentForm
            submitLabel="Claim as draft"
            initial={{ name: claiming.fingerprint.replace(/^idp-client:/, "").replace(/[^a-zA-Z0-9-]/g, "-").slice(0, 60), purpose: "Describe what this agent is for." }}
            onSubmit={(d) => claim.mutate({ f: claiming, d })}
            busy={claim.isPending}
          />
        )}
      </Modal>
    </>
  );
}
