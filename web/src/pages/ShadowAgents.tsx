import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Activity, Cloud, FileCode, Fingerprint, Ghost, KeyRound, Network, Radar, RefreshCw, ShieldBan, UserPlus, type LucideIcon } from "lucide-react";
import { post } from "../lib/api";
import { useDiscoveryStatus, useFindings, useIdentityStatus, useStats } from "../lib/queries";
import { useToast } from "../lib/toast";
import { timeAgo } from "../lib/format";
import type { DiscoverySourceState, DiscoveryStatus, Finding, ReconcileReport } from "../lib/types";
import { Button, Card, Chip, EmptyState, Kpi, Loading, Modal, PageHeader, Pill, StatusPill } from "../components/ui";
import { AgentForm, type AgentDraft } from "./RegisterAgent";

const SOURCE_LABEL: Record<string, string> = { gateway: "Gateway traffic", idp: "IdP scan", otel: "Telemetry", repo: "Code scan", cloud: "Cloud scan" };

const SOURCES: { key: keyof DiscoveryStatus["sources"]; label: string; icon: LucideIcon; text: string }[] = [
  { key: "gateway", label: "Gateway traffic", icon: Network, text: "Unknown callers at the Gateway, flagged in real time" },
  { key: "idp", label: "Identity provider", icon: KeyRound, text: "Accounts no registered agent owns" },
  { key: "otel", label: "Telemetry", icon: Activity, text: "Unknown services in monitoring data" },
  { key: "repo", label: "Code scan", icon: FileCode, text: "Agent libraries in unregistered code" },
  { key: "cloud", label: "Cloud scan", icon: Cloud, text: "AI resources in cloud subscriptions" },
];

const STATE: Record<DiscoverySourceState, { tone: "good" | "warning" | "neutral"; label: string }> = {
  active: { tone: "good", label: "Active" },
  scheduled: { tone: "good", label: "Scheduled" },
  manual: { tone: "warning", label: "On demand" },
  planned: { tone: "neutral", label: "Planned" },
};

function every(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${Math.round(seconds / 3600)} h`;
}

function idpScanSummary(scan: DiscoveryStatus["idp_scan"]): { text: string; failed: boolean } {
  const cadence = scan.automatic ? `Automatic every ${every(scan.interval_seconds)}` : "On demand only";
  const run = scan.last_run;
  if (!run) return { text: `${cadence} · no scan yet`, failed: false };
  const when = `last run ${timeAgo(run.at)} (${run.trigger})`;
  if (!run.ok) return { text: `${cadence} · ${when} failed: identity provider unavailable${scan.automatic ? " · retrying automatically" : ""}`, failed: true };
  return { text: `${cadence} · ${when} · ${run.new} new`, failed: false };
}

function DiscoverySources({ status }: { status: DiscoveryStatus }) {
  const scan = idpScanSummary(status.idp_scan);
  return (
    <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
      {SOURCES.map((s) => {
        const state = STATE[status.sources[s.key]];
        const planned = status.sources[s.key] === "planned";
        return (
          <div key={s.key} className={`rounded-xl border border-line bg-card p-4 ${planned ? "opacity-70" : ""}`}>
            <div className="mb-2 flex items-center gap-2">
              <s.icon className={`size-4 ${planned ? "text-faint" : "text-accent"}`} />
              <span className="flex-1 text-sm font-medium">{s.label}</span>
              <Pill tone={s.key === "idp" && scan.failed ? "warning" : state.tone}>{state.label}</Pill>
            </div>
            <p className="text-xs text-muted">{s.text}</p>
            {s.key === "idp" && <p className={`mt-2 text-xs ${scan.failed ? "text-warning-ink" : "text-faint"}`}>{scan.text}</p>}
          </div>
        );
      })}
    </div>
  );
}

function evidenceSummary(f: Finding): string {
  const e = f.evidence[f.evidence.length - 1] ?? {};
  if (e.user_agent) return `${e.user_agent} → ${String(e.resource ?? "").replace(/^https?:\/\/[^/]+/, "")}`;
  if (e.client_id) return `IdP client "${e.client_id}" (${e.name ?? "no name"}) exists outside the registry`;
  return JSON.stringify(e);
}

export function ShadowAgents() {
  const findings = useFindings();
  const stats = useStats().data;
  const identity = useIdentityStatus().data;
  const discovery = useDiscoveryStatus().data;
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [claiming, setClaiming] = useState<Finding | null>(null);

  const scan = useMutation({
    mutationFn: () => post<{ found: string[] }>("/v1/discovery/scan"),
    onSuccess: (r) => {
      toast("success", "Identity scan complete", `${r.found.length} unmanaged identities`);
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["discovery-status"] });
    },
    onError: (e: Error) => (toast("error", "Scan refused", e.message), queryClient.invalidateQueries({ queryKey: ["discovery-status"] })),
  });
  const reconcile = useMutation({
    mutationFn: () => post<ReconcileReport>("/v1/identity/reconcile"),
    onSuccess: (r) => {
      const fixed = r.enabled.length + r.disabled.length;
      const problems = r.missing.length + r.orphaned.length + r.errors.length;
      toast(
        problems ? "error" : "success",
        "Identities reconciled",
        `${r.checked} checked, ${fixed} repaired${problems ? `, ${r.missing.length} missing, ${r.orphaned.length} orphaned, ${r.errors.length} errors` : ""}`,
      );
      queryClient.invalidateQueries({ queryKey: ["identity-status"] });
    },
    onError: (e: Error) => toast("error", "Reconcile refused", e.message),
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
        subtitle="Agents acting without a governed identity, found from Gateway traffic and scheduled scans of the identity provider"
        actions={
          <Button icon={Radar} roles={["soc-analyst", "admin"]} loading={scan.isPending} onClick={() => scan.mutate()}>
            Run IdP scan
          </Button>
        }
      />
      {discovery && <DiscoverySources status={discovery} />}
      {identity && (
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-line bg-card px-4 py-3 text-sm">
          <KeyRound className="size-4 text-accent" />
          <span>
            Agent identities live in <b>{identity.provider === "keycloak" ? "Keycloak" : "the built-in development IdP"}</b>
          </span>
          <Pill tone={identity.reachable ? "good" : "critical"}>{identity.reachable ? "reachable" : "unreachable"}</Pill>
          <span className="text-muted">{identity.agents_with_identity} governed agent identities</span>
          {identity.detail && <span className="truncate text-xs text-critical-ink">{identity.detail}</span>}
          <Button className="ml-auto" icon={RefreshCw} roles={["admin", "security-approver"]} loading={reconcile.isPending} onClick={() => reconcile.mutate()}>
            Reconcile
          </Button>
        </div>
      )}
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Kpi icon={Ghost} tone="warning" label="Open findings" value={open.length} />
        <Kpi icon={ShieldBan} tone="critical" label="Quarantined" value={list.filter((f) => f.status === "quarantined").length} />
        <Kpi icon={Fingerprint} label="Discovered / quarantined agents" value={stats?.shadow ?? "—"} hint="In the registry, not yet governed" onClick={() => navigate("/agents")} />
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
