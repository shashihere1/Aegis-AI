import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Bot, CheckCircle2, ChevronLeft, ClipboardCheck, FileSignature, KeyRound, MoreHorizontal, PlayCircle, Send, ShieldAlert, Trash2, XCircle } from "lucide-react";
import { ApiError, api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import { AdaptiveRisk } from "../components/AdaptiveRisk";
import { clock, titleCase, toDate } from "../lib/format";
import type { Agent, BlastRadius, Decision, LedgerEntry, Tool } from "../lib/types";
import {
  Avatar,
  Badge,
  Button,
  Card,
  Chip,
  CopyButton,
  DLRow,
  DataClassPill,
  DecisionPill,
  DescriptionList,
  EmptyState,
  ErrorState,
  Field,
  JsonBlock,
  Loading,
  Meter,
  Modal,
  PageHeader,
  RiskPill,
  Skeleton,
  Stat,
  StatGroup,
  StatusPill,
  TBody,
  THead,
  Table,
  Tabs,
  Td,
  TextInput,
  Th,
  TimeAgo,
  Tr,
  cx,
  focusRing,
  type Tone,
} from "../components/ui";
import { AreaChart, Legend } from "../components/charts";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "../components/shadcn/dropdown-menu";

const SIDE_EFFECT_TONE: Record<string, Tone> = { read: "neutral", write: "info", financial: "warning", destructive: "critical" };
// Mirrors the weights in registry.py's inherent_risk(): each factor's share of the 0-100 score.
const RISK_FACTOR_MAX: Record<string, number> = {
  autonomy: 30,
  tool_criticality: 30,
  data_class: 20,
  exposure: 15,
  capability_breadth: 5,
  compounding: 15,
};
const ACTIVITY_SERIES = [
  { key: "allowed", label: "Allowed", color: "var(--chart-muted)" },
  { key: "held", label: "Denied or held", color: "var(--critical)" },
];

type TabKey = "overview" | "capabilities" | "decisions" | "evidence";

/** This agent's decisions over the last 6 hours, in 30-minute bins (client-side from the decision log). */
function useActivity(id: string) {
  const q = useQuery({
    queryKey: ["decisions", "agent-activity", id],
    queryFn: () => api<Decision[]>("/v1/decisions", { query: { agent_id: id, hours: 6, limit: 500 } }),
    refetchInterval: 15000,
  });
  const bins = useMemo(() => {
    const size = 30 * 60 * 1000;
    const end = Math.ceil(Date.now() / size) * size;
    const out = Array.from({ length: 12 }, (_, i) => ({ t: new Date(end - (12 - i) * size).toISOString(), allowed: 0, held: 0 }));
    for (const d of q.data ?? []) {
      const i = Math.floor((toDate(d.ts).getTime() - (end - 12 * size)) / size);
      if (i < 0 || i >= out.length) continue;
      if (d.decision === "allow") out[i].allowed++;
      else out[i].held++;
    }
    return out;
  }, [q.data]);
  return { ...q, bins };
}

export function AgentDetail() {
  const { id = "" } = useParams();
  const { persona, can } = useSession();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<TabKey>("overview");
  const agent = useQuery({ queryKey: ["agent", id], queryFn: () => api<Agent>(`/v1/agents/${id}`), refetchInterval: 3000 });
  const decisions = useQuery({ queryKey: ["decisions", "agent", id], queryFn: () => api<Decision[]>("/v1/decisions", { query: { agent_id: id, limit: 25 } }), refetchInterval: 3000 });
  const history = useQuery({ queryKey: ["ledger", id], queryFn: () => api<LedgerEntry[]>("/v1/ledger", { query: { subject: id, limit: 50 } }), refetchInterval: 5000 });
  const tools = useQuery({ queryKey: ["tools"], queryFn: () => api<Tool[]>("/v1/tools") });
  const activity = useActivity(id);
  const peers = useQueries({
    queries: [...new Set([...(agent.data?.can_delegate_to ?? []), ...(agent.data?.can_receive_from ?? [])])].map((pid) => ({
      queryKey: ["agent", pid],
      queryFn: () => api<Agent>(`/v1/agents/${pid}`),
    })),
  });
  const peerName = (pid: string) => peers.find((p) => p.data?.id === pid)?.data?.name ?? pid;

  const [modal, setModal] = useState<null | "suspend" | "approve" | "reject" | "resume" | "retire" | "passport" | "credentials">(null);
  const [reason, setReason] = useState("");
  const [credentials, setCredentials] = useState<{ client_id: string; private_key_pem: string; token_endpoint?: string; assertion_audience?: string | null } | null>(null);
  const radius = useQuery({ queryKey: ["blast", id], queryFn: () => api<BlastRadius>(`/v1/agents/${id}/blast-radius`), enabled: modal === "suspend" });
  const passport = useQuery({ queryKey: ["passport", id], queryFn: () => api<{ passport: unknown; jws: string }>(`/v1/agents/${id}/passport`), enabled: modal === "passport" });

  const act = useMutation({
    mutationFn: ({ path, body }: { path: string; body?: unknown }) => post<{ credentials?: typeof credentials }>(`/v1/agents/${id}/${path}`, body ?? {}),
    onSuccess: (result, vars) => {
      queryClient.invalidateQueries();
      setReason("");
      if (vars.path === "approve" && result?.credentials) {
        setCredentials(result.credentials);
        setModal("credentials");
      } else setModal(null);
      toast("success", `Agent ${titleCase(vars.path)} done`);
    },
    onError: (e: Error) => toast("error", "Action refused by Aegis", e.message),
  });

  const back = (
    <Link to="/agents" className={cx("inline-flex items-center gap-1 rounded hover:text-fg", focusRing)}>
      <ChevronLeft className="size-3.5" /> Agent registry
    </Link>
  );
  if (agent.isLoading)
    return (
      <>
        <PageHeader eyebrow={back} title={<Skeleton className="h-7 w-64" />} />
        <Skeleton className="h-28 w-full rounded-xl" />
      </>
    );
  if (agent.isError && !(agent.error instanceof ApiError && agent.error.status === 404))
    return (
      <>
        <PageHeader eyebrow={back} title="Agent" />
        <Card>
          <ErrorState title="Couldn't load this agent" error={agent.error} onRetry={() => void agent.refetch()} />
        </Card>
      </>
    );
  if (!agent.data)
    return (
      <>
        <PageHeader eyebrow={back} title="Agent not found" />
        <Card>
          <EmptyState icon={Bot} title="No agent with this ID">
            It may have been retired or the link is wrong.
          </EmptyState>
        </Card>
      </>
    );

  const a = agent.data;
  const toolById = Object.fromEntries((tools.data ?? []).map((t) => [t.id, t]));
  const breakdown = a.risk_breakdown ?? {};
  const isOwner = persona?.username === a.owner;
  const denied = (decisions.data ?? []).filter((d) => d.decision !== "allow").length;
  const canRetire = ["active", "suspended", "draft"].includes(a.status);

  const primary =
    a.status === "draft" ? (
      <Button variant="primary" icon={Send} roles={["agent-developer", "agent-owner", "admin"]} loading={act.isPending} onClick={() => act.mutate({ path: "submit" })}>
        Submit for approval
      </Button>
    ) : a.status === "pending_approval" ? (
      <>
        <Button icon={XCircle} roles={["risk-approver"]} onClick={() => setModal("reject")}>
          Reject
        </Button>
        <Button variant="primary" icon={CheckCircle2} roles={["risk-approver"]} onClick={() => setModal("approve")}>
          Approve
        </Button>
      </>
    ) : a.status === "active" ? (
      <Button variant="danger" icon={Ban} roles={["soc-analyst", "risk-approver", "agent-owner"]} onClick={() => setModal("suspend")}>
        Suspend
      </Button>
    ) : a.status === "suspended" ? (
      <Button variant="primary" icon={PlayCircle} roles={["risk-approver"]} onClick={() => setModal("resume")}>
        Resume
      </Button>
    ) : null;

  return (
    <>
      <PageHeader
        eyebrow={back}
        title={
          <span className="flex flex-wrap items-center gap-2.5">
            {a.name}
            <StatusPill status={a.status} />
            <RiskPill tier={a.risk_tier} />
            {a.orphaned && <Badge tone="serious">Orphaned</Badge>}
          </span>
        }
        meta={
          <>
            <span className="inline-flex items-center gap-1 font-mono">
              {a.id} <CopyButton value={a.id} />
            </span>
            <span>{a.environment}</span>
            <span>{a.cloud}</span>
            <span>{a.framework}</span>
            <span>
              Last active <TimeAgo value={a.last_active_at} />
            </span>
          </>
        }
        actions={
          <>
            <Button icon={FileSignature} onClick={() => setModal("passport")}>
              Passport
            </Button>
            {primary}
            {(canRetire || (a.attestation_due && isOwner)) && (
              <DropdownMenu>
                <DropdownMenuTrigger className={cx("grid size-9 place-items-center rounded-lg border border-line-strong bg-card text-muted shadow-card hover:bg-hover hover:text-fg", focusRing)} aria-label="More actions">
                  <MoreHorizontal className="size-4" />
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  {a.attestation_due && isOwner && (
                    <DropdownMenuItem onSelect={() => act.mutate({ path: "attest" })}>
                      <ClipboardCheck className="size-4 text-muted" /> Attest ownership
                    </DropdownMenuItem>
                  )}
                  {canRetire && (
                    <DropdownMenuItem disabled={!can("agent-owner", "admin")} onSelect={() => setModal("retire")} className="text-critical-ink">
                      <Trash2 className="size-4" /> Retire agent{!can("agent-owner", "admin") && " (owner or admin)"}
                    </DropdownMenuItem>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </>
        }
      />

      <Tabs
        variant="underline"
        label="Agent sections"
        className="mb-6"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "overview", label: "Overview" },
          { value: "capabilities", label: "Capabilities", count: a.capabilities.length },
          { value: "decisions", label: "Decisions" },
          { value: "evidence", label: "Evidence" },
        ]}
      />

      {tab === "overview" && (
        <div className="space-y-6">
          <StatGroup>
            <Stat label="Inherent risk" value={`${a.inherent_risk} / 100`} caption={`${titleCase(a.risk_tier)} tier · sets approvers and mandate lifetime`} />
            <Stat label="Capabilities" value={a.capabilities.length} caption="Tools this agent may call" onClick={() => setTab("capabilities")} />
            <Stat label="Denied or held" tone="critical" value={decisions.data ? denied : "—"} caption="Of the last 25 decisions" onClick={() => setTab("decisions")} />
            <Stat label="Data ceiling" value={<span className="text-xl">{titleCase(a.max_data_class)}</span>} caption={a.customer_facing ? "Customer-facing" : "Internal only"} />
          </StatGroup>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
            <Card title="Agent passport" description="Who this agent is, who answers for it, and what it may do" className="xl:col-span-2">
              <DescriptionList className="px-5">
                <DLRow label="Purpose">{a.purpose}</DLRow>
                <DLRow label="Intent categories">
                  <div className="flex flex-wrap gap-1.5">
                    {a.intent_categories.map((c) => (
                      <Chip key={c} mono>
                        {c}
                      </Chip>
                    ))}
                  </div>
                </DLRow>
                <DLRow label="Owner">
                  <span className="flex items-center gap-2">
                    <Avatar name={a.owner} size="sm" /> {a.owner}
                    <span className="text-muted">· sponsor {a.sponsor}</span>
                  </span>
                </DLRow>
                <DLRow label="Registered by">{a.registered_by}</DLRow>
                <DLRow label="Autonomy">
                  {a.autonomy}
                  {a.customer_facing && <span className="text-muted"> · customer-facing</span>}
                </DLRow>
                <DLRow label="Data ceiling">
                  <DataClassPill value={a.max_data_class} />
                </DLRow>
                <DLRow label="Identity">
                  {a.idp_client_id ? (
                    <span className="inline-flex flex-wrap items-center gap-2">
                      <KeyRound className="size-3.5 text-muted" /> <span className="font-mono text-xs">{a.idp_client_id}</span>
                      <span className="text-caption text-muted">private_key_jwt, no shared secret</span>
                    </span>
                  ) : (
                    <span className="text-muted">Provisioned at approval</span>
                  )}
                </DLRow>
                <DLRow label="Delegation">
                  <div className="space-y-1">
                    <div>
                      <span className="text-muted">Can delegate to </span>
                      {a.can_delegate_to.length
                        ? a.can_delegate_to.map((p) => (
                            <Link key={p} to={`/agents/${p}`} className={cx("mr-2 rounded text-accent hover:underline", focusRing)}>
                              {peerName(p)}
                            </Link>
                          ))
                        : "—"}
                    </div>
                    <div>
                      <span className="text-muted">Accepts from </span>
                      {a.can_receive_from.length
                        ? a.can_receive_from.map((p) => (
                            <Link key={p} to={`/agents/${p}`} className={cx("mr-2 rounded text-accent hover:underline", focusRing)}>
                              {peerName(p)}
                            </Link>
                          ))
                        : "—"}
                      <span className="text-muted"> · max depth {a.max_depth}</span>
                    </div>
                  </div>
                </DLRow>
                {a.attestation_due && <DLRow label="Attestation due">{new Date(a.attestation_due).toLocaleDateString()}</DLRow>}
              </DescriptionList>
            </Card>

            <Card title="Inherent risk" description={`${a.inherent_risk} of 100, explainable`}>
              <div className="space-y-4 p-5">
                {Object.entries(breakdown).map(([k, v]) => (
                  <Meter key={k} label={titleCase(k)} value={v} max={RISK_FACTOR_MAX[k] ?? 30} />
                ))}
                <p className="text-caption text-muted">
                  Weighted autonomy (30%), tool criticality (30%), data class (20%), exposure (15%) and capability breadth (5%), plus a compounding bonus when high
                  autonomy meets a financial or destructive tool.
                </p>
              </div>
            </Card>
          </div>

          <AdaptiveRisk agentId={id} />
        </div>
      )}

      {tab === "capabilities" && (
        <Card title="Capabilities" description="Every tool the agent may call, with its classification" className="overflow-hidden">
          {a.capabilities.length === 0 ? (
            <EmptyState title="No tools" />
          ) : (
            <Table>
              <THead>
                <Th>Tool</Th>
                <Th>Side effect</Th>
                <Th>Egress</Th>
                <Th>Returns</Th>
                <Th>Status</Th>
              </THead>
              <TBody>
                {a.capabilities.map((tid) => {
                  const t = toolById[tid];
                  const effect = t?.classification.side_effect;
                  return (
                    <Tr key={tid}>
                      <Td className="font-mono text-xs">{tid}</Td>
                      <Td>{effect ? <Badge tone={SIDE_EFFECT_TONE[effect] ?? "neutral"}>{titleCase(effect)}</Badge> : <span className="text-muted">—</span>}</Td>
                      <Td className="text-muted">{t?.classification.egress ?? "—"}</Td>
                      <Td>{t?.classification.returns_data_class ? <DataClassPill value={t.classification.returns_data_class} /> : <span className="text-muted">—</span>}</Td>
                      <Td>{t ? <StatusPill status={t.status} /> : <span className="text-muted">—</span>}</Td>
                    </Tr>
                  );
                })}
              </TBody>
            </Table>
          )}
        </Card>
      )}

      {tab === "decisions" && (
        <div className="space-y-6">
          <Card title="Activity" description="Governed decisions for this agent, last 6 hours (30-minute bins)" action={<Legend line series={ACTIVITY_SERIES} />}>
            <div className="p-5">
              {activity.isError ? (
                <ErrorState title="Couldn't load activity" error={activity.error} onRetry={() => void activity.refetch()} />
              ) : !activity.data ? (
                <Skeleton className="h-48" />
              ) : (
                <AreaChart ariaLabel="Decisions over the last 6 hours" data={activity.bins} series={ACTIVITY_SERIES} xLabel={(b) => clock(b.t).slice(0, 5)} />
              )}
            </div>
          </Card>
          <Card title="Recent decisions" className="overflow-hidden">
            {decisions.isError ? (
              <ErrorState title="Couldn't load decisions" error={decisions.error} onRetry={() => void decisions.refetch()} />
            ) : !decisions.data ? (
              <div className="p-5">
                <Skeleton className="h-32" />
              </div>
            ) : !decisions.data.length ? (
              <EmptyState icon={ShieldAlert} title="No decisions yet">
                Start a Bank Assistant task or an Investigation Copilot query to see this agent act.
              </EmptyState>
            ) : (
              <Table>
                <THead>
                  <Th>Time</Th>
                  <Th>Action</Th>
                  <Th>Decision</Th>
                  <Th>Rules</Th>
                  <Th>On behalf of</Th>
                  <Th />
                </THead>
                <TBody>
                  {decisions.data.map((d) => (
                    <Tr key={d.id}>
                      <Td className="tabular text-muted">{clock(d.ts)}</Td>
                      <Td className="font-mono text-xs">{d.action_label}</Td>
                      <Td>
                        <DecisionPill decision={d.decision} />
                      </Td>
                      <Td className="text-caption text-muted">{d.reasons.map((r) => r.rule).join(", ") || "—"}</Td>
                      <Td className="text-muted">{d.subject?.replace("user:", "")}</Td>
                      <Td className="text-right">
                        {d.root_id && (
                          <Link to={`/lineage/${d.root_id}`} className={cx("rounded text-caption font-medium whitespace-nowrap text-accent hover:underline", focusRing)}>
                            Lineage →
                          </Link>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
        </div>
      )}

      {tab === "evidence" && (
        <Card title="Lifecycle and evidence" description="Every ledger entry recorded for this agent, newest first">
          {history.isError ? (
            <ErrorState title="Couldn't load the ledger" error={history.error} onRetry={() => void history.refetch()} />
          ) : !history.data ? (
            <div className="p-5">
              <Skeleton className="h-40" />
            </div>
          ) : !history.data.length ? (
            <EmptyState title="No ledger entries yet" />
          ) : (
            <ol className="relative space-y-4 p-5 before:absolute before:top-7 before:bottom-7 before:left-[25px] before:w-px before:bg-line">
              {history.data.map((e) => (
                <li key={e.seq} className="relative flex gap-3 text-sm">
                  <span className="relative mt-1.5 size-2.5 shrink-0 rounded-full border-2 border-card bg-chart-muted ring-1 ring-line" />
                  <div className="min-w-0">
                    <div className="font-medium text-fg">{titleCase(e.event_type)}</div>
                    <div className="text-caption text-muted">
                      {e.actor} · <TimeAgo value={e.ts} /> · <span className="font-mono">#{e.seq}</span>
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Card>
      )}

      <Modal open={modal === "suspend"} onClose={() => setModal(null)} title={`Suspend ${a.name}?`} description="The kill switch disables the agent's identity, revokes every mandate it appears in (and everything delegated from them), and cancels pending approvals.">
        {radius.isError ? (
          <ErrorState title="Couldn't compute the blast radius" error={radius.error} />
        ) : (
          <StatGroup columns={3} className="mb-5 shadow-none">
            <Stat label="Mandates revoked" value={radius.data?.mandates.length ?? "…"} />
            <Stat label="Agents affected" value={radius.data?.agents_affected.length ?? "…"} />
            <Stat label="Approvals cancelled" value={radius.data?.pending_approvals.length ?? "…"} />
          </StatGroup>
        )}
        <Field label="Reason" hint="Recorded in the evidence ledger">
          <TextInput value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Suspicious behaviour reported by the SOC" />
        </Field>
        <div className="mt-5 flex justify-end gap-2">
          <Button onClick={() => setModal(null)}>Cancel</Button>
          <Button variant="destructive" icon={Ban} loading={act.isPending} onClick={() => act.mutate({ path: "suspend", body: { reason: reason || "manual suspension" } })}>
            Suspend now
          </Button>
        </div>
      </Modal>

      {(["approve", "reject", "resume", "retire"] as const).map((kind) => (
        <Modal
          key={kind}
          open={modal === kind}
          onClose={() => setModal(null)}
          title={`${titleCase(kind)} ${a.name}`}
          description={kind === "approve" ? "Approval provisions a governed identity in the IdP. Segregation of duties: the registrant and the owner cannot approve their own agent." : undefined}
        >
          <Field label="Justification" hint="Recorded in the evidence ledger">
            <TextInput value={reason} onChange={(e) => setReason(e.target.value)} />
          </Field>
          <div className="mt-5 flex justify-end gap-2">
            <Button onClick={() => setModal(null)}>Cancel</Button>
            <Button variant={kind === "retire" || kind === "reject" ? "destructive" : "primary"} loading={act.isPending} onClick={() => act.mutate({ path: kind, body: { reason } })}>
              {titleCase(kind)}
            </Button>
          </div>
        </Modal>
      ))}

      <Modal open={modal === "credentials"} onClose={() => setModal(null)} title="Agent identity provisioned" description="This private key is shown once. In production it goes straight to the agent runtime's secret store (Key Vault), never to a person.">
        <Field label="Client ID">
          <div className="font-mono text-sm">{credentials?.client_id}</div>
        </Field>
        {credentials?.token_endpoint && (
          <div className="mt-3">
            <Field label="Signs in at">
              <div className="font-mono text-xs break-all">{credentials.token_endpoint}</div>
              {credentials.assertion_audience && <div className="mt-1 text-caption text-muted">Audience of the signed login note: {credentials.assertion_audience}</div>}
            </Field>
          </div>
        )}
        <div className="mt-3">
          <JsonBlock value={credentials?.private_key_pem.split("\n").slice(0, 2).join("\n") + "\n…"} />
        </div>
      </Modal>

      <Modal open={modal === "passport"} onClose={() => setModal(null)} title="Signed agent passport" description="A portable statement of who this agent is and what it is for, signed by the Aegis STS (ES256)." wide>
        {passport.isError ? (
          <ErrorState title="Couldn't load the passport" error={passport.error} onRetry={() => void passport.refetch()} />
        ) : passport.data ? (
          <>
            <JsonBlock value={passport.data.passport} />
            <div className="mt-4 mb-1.5 text-caption font-medium text-fg">JWS</div>
            <div className="rounded-lg border border-line bg-inset p-3 font-mono text-xs break-all text-muted">{passport.data.jws}</div>
          </>
        ) : (
          <Loading />
        )}
      </Modal>
    </>
  );
}
