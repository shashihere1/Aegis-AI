import { useState } from "react";
import { Link, useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Activity, Cloud, FileCode, KeyRound, Network, Radar, RefreshCw, ShieldBan, UserPlus, type LucideIcon } from "lucide-react";
import { post } from "../lib/api";
import { useDiscoveryStatus, useFindings, useIdentityStatus, useStats } from "../lib/queries";
import { useToast } from "../lib/toast";
import { timeAgo } from "../lib/format";
import type { DiscoverySourceState, DiscoveryStatus, Finding, ReconcileReport } from "../lib/types";
import {
  Badge,
  Button,
  Callout,
  Card,
  Chip,
  EmptyState,
  ErrorState,
  Modal,
  PageHeader,
  Skeleton,
  SkeletonRows,
  Stat,
  StatGroup,
  StatusPill,
  TBody,
  THead,
  Table,
  Td,
  Th,
  TimeAgo,
  Tr,
  cx,
  focusRing,
} from "../components/ui";
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
    <Card title="Discovery sources" description="Where Aegis looks for agents that are not in the registry" className="mb-6">
      <ul className="divide-y divide-line">
        {SOURCES.map((s) => {
          const state = STATE[status.sources[s.key]];
          const planned = status.sources[s.key] === "planned";
          return (
            <li key={s.key} className={cx("flex items-start gap-3 px-5 py-3.5", planned && "opacity-70")}>
              <s.icon className={cx("mt-0.5 size-4 shrink-0", planned ? "text-faint" : "text-muted")} aria-hidden />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium text-fg">{s.label}</div>
                <p className="text-caption text-muted">{s.text}</p>
                {s.key === "idp" && <p className={cx("mt-1 text-caption", scan.failed ? "text-warning-ink" : "text-muted")}>{scan.text}</p>}
              </div>
              <Badge tone={s.key === "idp" && scan.failed ? "warning" : state.tone}>{state.label}</Badge>
            </li>
          );
        })}
      </ul>
    </Card>
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
  const statsQuery = useStats();
  const identityQuery = useIdentityStatus();
  const discoveryQuery = useDiscoveryStatus();
  const stats = statsQuery.data;
  const identity = identityQuery.data;
  const discovery = discoveryQuery.data;
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

  const retryButton = (refetch: () => unknown) => (
    <Button size="sm" onClick={() => void refetch()}>
      Try again
    </Button>
  );

  return (
    <>
      <PageHeader
        title="Shadow agents"
        subtitle="Agents acting without a governed identity, found from Gateway traffic and scheduled scans of the identity provider"
        actions={
          <Button icon={Radar} roles={["soc-analyst", "admin"]} loading={scan.isPending} onClick={() => scan.mutate()}>
            Run IdP scan
          </Button>
        }
      />

      <StatGroup columns={3} className="mb-8">
        <Stat label="Open findings" tone="warning" value={findings.data ? open.length : "—"} caption="Awaiting claim or quarantine" />
        <Stat label="Quarantined" value={findings.data ? list.filter((f) => f.status === "quarantined").length : "—"} caption="Blocked at the Gateway" />
        <Stat label="Discovered or quarantined agents" value={stats?.shadow ?? "—"} caption="In the registry, not yet governed" to="/agents" />
      </StatGroup>

      {discovery ? (
        <DiscoverySources status={discovery} />
      ) : discoveryQuery.isError ? (
        <Callout tone="warning" title="Couldn't load discovery sources" className="mb-6" action={retryButton(discoveryQuery.refetch)}>
          {discoveryQuery.error instanceof Error ? discoveryQuery.error.message : "Discovery status is unavailable."}
        </Callout>
      ) : (
        <Skeleton className="mb-6 h-40 rounded-xl" />
      )}

      {identity ? (
        <Callout
          tone={identity.reachable ? "good" : "critical"}
          icon={KeyRound}
          title={`Agent identities live in ${identity.provider === "keycloak" ? "Keycloak" : "the built-in development IdP"} · ${identity.reachable ? "Reachable" : "Unreachable"}`}
          className="mb-6"
          action={
            <Button icon={RefreshCw} roles={["admin", "security-approver"]} loading={reconcile.isPending} onClick={() => reconcile.mutate()}>
              Reconcile
            </Button>
          }
        >
          {identity.agents_with_identity} governed agent identities
          {identity.detail && <span className="block truncate text-xs text-critical-ink">{identity.detail}</span>}
        </Callout>
      ) : identityQuery.isError ? (
        <Callout tone="warning" title="Couldn't load identity status" className="mb-6" action={retryButton(identityQuery.refetch)}>
          {identityQuery.error instanceof Error ? identityQuery.error.message : "Identity provider status is unavailable."}
        </Callout>
      ) : (
        <Skeleton className="mb-6 h-16 rounded-lg" />
      )}

      <Card title="Findings" className="overflow-hidden">
        {findings.isLoading ? (
          <SkeletonRows cols={6} />
        ) : findings.isError ? (
          <ErrorState title="Couldn't load findings" error={findings.error} onRetry={() => void findings.refetch()} />
        ) : !list.length ? (
          <EmptyState icon={Radar} title="No shadow agents found yet">
            Discovery findings come from identity scans and requests to the Gateway without a valid Mandate.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <Th>Finding</Th>
              <Th>Sources</Th>
              <Th numeric>Signals</Th>
              <Th>First seen</Th>
              <Th>Last seen</Th>
              <Th>Status</Th>
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            </THead>
            <TBody>
              {list.map((f) => (
                <Tr key={f.id} className="align-top">
                  <Td className="max-w-md">
                    <div className="font-mono text-sm font-medium text-fg">{f.fingerprint}</div>
                    <div className="mt-0.5 truncate text-caption text-muted" title={evidenceSummary(f)}>
                      {evidenceSummary(f)}
                    </div>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {f.sources.map((s) => (
                        <Chip key={s}>{SOURCE_LABEL[s] ?? s}</Chip>
                      ))}
                    </div>
                  </Td>
                  <Td numeric>{f.hits}</Td>
                  <Td className="text-muted">
                    <TimeAgo value={f.first_seen} />
                  </Td>
                  <Td className="text-muted">
                    <TimeAgo value={f.last_seen} />
                  </Td>
                  <Td>
                    <StatusPill status={f.status} />
                  </Td>
                  <Td>
                    <div className="flex justify-end gap-2">
                      {f.status === "open" ? (
                        <>
                          <Button size="sm" icon={UserPlus} roles={["agent-developer", "agent-owner"]} onClick={() => setClaiming(f)}>
                            Claim
                          </Button>
                          <Button variant="danger" size="sm" icon={ShieldBan} roles={["soc-analyst"]} loading={quarantine.isPending && quarantine.variables?.id === f.id} onClick={() => quarantine.mutate(f)}>
                            Quarantine
                          </Button>
                        </>
                      ) : (
                        f.agent_id && (
                          <Link to={`/agents/${f.agent_id}`} className={cx("inline-flex items-center gap-1.5 rounded text-sm whitespace-nowrap text-accent hover:underline", focusRing)}>
                            <UserPlus className="size-3.5" aria-hidden />
                            Registered as <span className="font-mono text-xs">{f.agent_id}</span>
                          </Link>
                        )
                      )}
                    </div>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
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
