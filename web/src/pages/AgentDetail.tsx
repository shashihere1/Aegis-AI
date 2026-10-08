import { useState } from "react";
import { Link, useParams } from "react-router";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Bot, CheckCircle2, ClipboardCheck, FileSignature, KeyRound, PlayCircle, Send, ShieldAlert, Trash2, XCircle } from "lucide-react";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import { AdaptiveRisk } from "../components/AdaptiveRisk";
import { clock, timeAgo, titleCase } from "../lib/format";
import type { Agent, BlastRadius, Decision, LedgerEntry, Tool } from "../lib/types";
import {
  Avatar,
  Button,
  Card,
  Chip,
  CopyButton,
  DataClassPill,
  DecisionPill,
  EmptyState,
  Field,
  JsonBlock,
  Loading,
  Meter,
  Modal,
  RiskPill,
  StatusPill,
  Td,
  TextInput,
  Th,
} from "../components/ui";

const SIDE_EFFECT_TONE: Record<string, string> = { read: "text-muted", write: "text-info-ink", financial: "text-warning-ink", destructive: "text-critical-ink" };
// Mirrors the weights in registry.py's inherent_risk(): each factor's share of the 0-100 score.
const RISK_FACTOR_MAX: Record<string, number> = {
  autonomy: 30, tool_criticality: 30, data_class: 20, exposure: 15, capability_breadth: 5, compounding: 15,
};

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-3 py-2 text-sm">
      <div className="text-muted">{label}</div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

export function AgentDetail() {
  const { id = "" } = useParams();
  const { persona } = useSession();
  const toast = useToast();
  const queryClient = useQueryClient();
  const agent = useQuery({ queryKey: ["agent", id], queryFn: () => api<Agent>(`/v1/agents/${id}`), refetchInterval: 3000 });
  const decisions = useQuery({ queryKey: ["decisions", "agent", id], queryFn: () => api<Decision[]>("/v1/decisions", { query: { agent_id: id, limit: 25 } }), refetchInterval: 3000 });
  const history = useQuery({ queryKey: ["ledger", id], queryFn: () => api<LedgerEntry[]>("/v1/ledger", { query: { subject: id, limit: 50 } }), refetchInterval: 5000 });
  const tools = useQuery({ queryKey: ["tools"], queryFn: () => api<Tool[]>("/v1/tools") });
  const peers = useQueries({
    queries: [...new Set([...(agent.data?.can_delegate_to ?? []), ...(agent.data?.can_receive_from ?? [])])].map((pid) => ({
      queryKey: ["agent", pid],
      queryFn: () => api<Agent>(`/v1/agents/${pid}`),
    })),
  });
  const peerName = (pid: string) => peers.find((p) => p.data?.id === pid)?.data?.name ?? pid;

  const [modal, setModal] = useState<null | "suspend" | "approve" | "reject" | "resume" | "retire" | "passport" | "credentials">(null);
  const [reason, setReason] = useState("");
  const [credentials, setCredentials] = useState<{ client_id: string; private_key_pem: string } | null>(null);
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

  if (agent.isLoading) return <Loading />;
  if (!agent.data) return <EmptyState icon={Bot} title="Agent not found" />;
  const a = agent.data;
  const toolById = Object.fromEntries((tools.data ?? []).map((t) => [t.id, t]));
  const breakdown = a.risk_breakdown ?? {};
  const isOwner = persona?.username === a.owner;

  return (
    <>
      <div className="mb-6 flex flex-wrap items-start gap-4">
        <div className="grid size-14 place-items-center rounded-2xl border border-line bg-accent-soft text-accent">
          <Bot className="size-7" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight">{a.name}</h1>
            <StatusPill status={a.status} />
            <RiskPill tier={a.risk_tier} />
            {a.orphaned && <StatusPill status="open" />}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-3 text-sm text-muted">
            <span className="inline-flex items-center gap-1.5 font-mono">
              {a.id} <CopyButton value={a.id} />
            </span>
            <span>·</span>
            <span>{a.environment}</span>
            <span>·</span>
            <span>{a.cloud}</span>
            <span>·</span>
            <span>{a.framework}</span>
            <span>·</span>
            <span>last active {timeAgo(a.last_active_at)}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button icon={FileSignature} onClick={() => setModal("passport")}>
            Signed passport
          </Button>
          {a.status === "draft" && (
            <Button variant="primary" icon={Send} roles={["agent-developer", "agent-owner", "admin"]} loading={act.isPending} onClick={() => act.mutate({ path: "submit" })}>
              Submit for approval
            </Button>
          )}
          {a.status === "pending_approval" && (
            <>
              <Button variant="primary" icon={CheckCircle2} roles={["risk-approver"]} onClick={() => setModal("approve")}>
                Approve
              </Button>
              <Button icon={XCircle} roles={["risk-approver"]} onClick={() => setModal("reject")}>
                Reject
              </Button>
            </>
          )}
          {a.status === "active" && (
            <Button variant="danger" icon={Ban} roles={["soc-analyst", "risk-approver", "agent-owner"]} onClick={() => setModal("suspend")}>
              Suspend (kill switch)
            </Button>
          )}
          {a.status === "suspended" && (
            <Button variant="primary" icon={PlayCircle} roles={["risk-approver"]} onClick={() => setModal("resume")}>
              Resume
            </Button>
          )}
          {a.attestation_due && isOwner && (
            <Button icon={ClipboardCheck} loading={act.isPending} onClick={() => act.mutate({ path: "attest" })}>
              Attest
            </Button>
          )}
          {["active", "suspended", "draft"].includes(a.status) && (
            <Button variant="ghost" icon={Trash2} roles={["agent-owner", "admin"]} onClick={() => setModal("retire")}>
              Retire
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Card title="Agent passport" className="xl:col-span-2">
          <div className="divide-y divide-line px-5 py-2">
            <Row label="Purpose">{a.purpose}</Row>
            <Row label="Intent categories">
              <div className="flex flex-wrap gap-1.5">
                {a.intent_categories.map((c) => (
                  <Chip key={c} mono>
                    {c}
                  </Chip>
                ))}
              </div>
            </Row>
            <Row label="Owner / sponsor">
              <div className="flex items-center gap-2">
                <Avatar name={a.owner} size="sm" /> {a.owner} <span className="text-faint">· sponsor {a.sponsor}</span>
              </div>
            </Row>
            <Row label="Registered by">{a.registered_by}</Row>
            <Row label="Autonomy">{a.autonomy}{a.customer_facing && <span className="text-muted"> · customer-facing</span>}</Row>
            <Row label="Data ceiling">
              <DataClassPill value={a.max_data_class} />
            </Row>
            <Row label="Identity">
              {a.idp_client_id ? (
                <span className="inline-flex items-center gap-2 font-mono text-xs">
                  <KeyRound className="size-3.5 text-accent" /> {a.idp_client_id} <span className="font-sans text-faint">(private_key_jwt, no shared secret)</span>
                </span>
              ) : (
                <span className="text-faint">provisioned at approval</span>
              )}
            </Row>
            <Row label="Delegation">
              <div className="space-y-1">
                <div>
                  <span className="text-faint">can delegate to </span>
                  {a.can_delegate_to.length ? a.can_delegate_to.map((p) => <Link key={p} to={`/agents/${p}`} className="mr-2 text-accent hover:underline">{peerName(p)}</Link>) : "—"}
                </div>
                <div>
                  <span className="text-faint">accepts from </span>
                  {a.can_receive_from.length ? a.can_receive_from.map((p) => <Link key={p} to={`/agents/${p}`} className="mr-2 text-accent hover:underline">{peerName(p)}</Link>) : "—"}
                  <span className="text-faint"> · max depth {a.max_depth}</span>
                </div>
              </div>
            </Row>
            {a.attestation_due && <Row label="Attestation due">{new Date(a.attestation_due).toLocaleDateString()}</Row>}
          </div>
        </Card>

        <Card title={`Inherent risk · ${a.inherent_risk} / 100`}>
          <div className="space-y-4 p-5">
            {Object.entries(breakdown).map(([k, v]) => (
              <Meter key={k} label={titleCase(k)} value={v} max={RISK_FACTOR_MAX[k] ?? 30} />
            ))}
            <p className="text-xs text-faint">
              Explainable score: weighted autonomy (30%) + tool criticality (30%) + data class (20%) + exposure
              (15%) + capability breadth (5%), plus a compounding bonus when high autonomy meets a
              financial/destructive tool. It sets the approvers, Mandate lifetime and attestation frequency.
            </p>
          </div>
        </Card>

        <AdaptiveRisk agentId={id} />
        <Card title={`Capabilities · ${a.capabilities.length} tools`} className="xl:col-span-2">
          {a.capabilities.length === 0 ? (
            <EmptyState title="No tools" />
          ) : (
            <table className="w-full">
              <thead className="border-b border-line">
                <tr>
                  <Th>Tool</Th>
                  <Th>Side effect</Th>
                  <Th>Egress</Th>
                  <Th>Returns</Th>
                  <Th>Status</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {a.capabilities.map((tid) => {
                  const t = toolById[tid];
                  return (
                    <tr key={tid}>
                      <Td className="font-mono text-xs">{tid}</Td>
                      <Td className={SIDE_EFFECT_TONE[t?.classification.side_effect ?? "read"]}>{titleCase(t?.classification.side_effect ?? "—")}</Td>
                      <Td className="text-muted">{t?.classification.egress ?? "—"}</Td>
                      <Td>{t?.classification.returns_data_class && <DataClassPill value={t.classification.returns_data_class} />}</Td>
                      <Td>{t && <StatusPill status={t.status} />}</Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Lifecycle & evidence">
          <ol className="max-h-80 space-y-3 overflow-auto p-5">
            {(history.data ?? []).map((e) => (
              <li key={e.seq} className="flex gap-3 text-sm">
                <span className="mt-1.5 size-2 shrink-0 rounded-full bg-accent" />
                <div>
                  <div className="font-medium">{e.event_type}</div>
                  <div className="text-xs text-muted">
                    {e.actor} · {timeAgo(e.ts)}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </Card>

        <Card title="Recent decisions" className="xl:col-span-3">
          {!decisions.data?.length ? (
            <EmptyState icon={ShieldAlert} title="No decisions yet">
              Run a scene from Demo Studio to see this agent act.
            </EmptyState>
          ) : (
            <table className="w-full">
              <thead className="border-b border-line">
                <tr>
                  <Th>Time</Th>
                  <Th>Action</Th>
                  <Th>Decision</Th>
                  <Th>Rules</Th>
                  <Th>On behalf of</Th>
                  <Th></Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {decisions.data.map((d) => (
                  <tr key={d.id}>
                    <Td className="tabular text-muted">{clock(d.ts)}</Td>
                    <Td className="font-mono text-xs">{d.action_label}</Td>
                    <Td>
                      <DecisionPill decision={d.decision} />
                    </Td>
                    <Td className="text-xs text-muted">{d.reasons.map((r) => r.rule).join(", ") || "—"}</Td>
                    <Td className="text-muted">{d.subject?.replace("user:", "")}</Td>
                    <Td>{d.root_id && <Link to={`/lineage/${d.root_id}`} className="text-sm text-accent hover:underline">Lineage →</Link>}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <Modal open={modal === "suspend"} onClose={() => setModal(null)} title={`Suspend ${a.name}?`}>
        <p className="mb-4 text-sm text-muted">The kill switch disables the agent's identity, revokes every mandate in which it appears (and everything delegated from them), and cancels pending approvals.</p>
        {radius.data && (
          <div className="mb-4 grid grid-cols-3 gap-3 text-center">
            {[
              ["Mandates revoked", radius.data.mandates.length],
              ["Agents affected", radius.data.agents_affected.length],
              ["Approvals cancelled", radius.data.pending_approvals.length],
            ].map(([label, n]) => (
              <div key={label} className="rounded-xl border border-line bg-inset p-3">
                <div className="text-2xl font-semibold">{n}</div>
                <div className="text-xs text-muted">{label}</div>
              </div>
            ))}
          </div>
        )}
        <Field label="Reason (recorded in the ledger)">
          <TextInput value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Suspicious behaviour reported by the SOC" />
        </Field>
        <div className="mt-5 flex justify-end">
          <Button variant="danger" icon={Ban} loading={act.isPending} onClick={() => act.mutate({ path: "suspend", body: { reason: reason || "manual suspension" } })}>
            Suspend now
          </Button>
        </div>
      </Modal>

      {(["approve", "reject", "resume", "retire"] as const).map((kind) => (
        <Modal key={kind} open={modal === kind} onClose={() => setModal(null)} title={`${titleCase(kind)} ${a.name}`}>
          {kind === "approve" && <p className="mb-4 text-sm text-muted">Approval provisions a governed identity in the IdP. Segregation of duties: the registrant and the owner cannot approve their own agent.</p>}
          <Field label="Justification">
            <TextInput value={reason} onChange={(e) => setReason(e.target.value)} />
          </Field>
          <div className="mt-5 flex justify-end">
            <Button variant={kind === "retire" ? "danger" : "primary"} loading={act.isPending} onClick={() => act.mutate({ path: kind, body: { reason } })}>
              {titleCase(kind)}
            </Button>
          </div>
        </Modal>
      ))}

      <Modal open={modal === "credentials"} onClose={() => setModal(null)} title="Agent identity provisioned">
        <p className="mb-3 text-sm text-muted">This private key is shown once. In production it goes straight to the agent runtime's secret store (Key Vault), never to a person.</p>
        <Field label="Client ID">
          <div className="font-mono text-sm">{credentials?.client_id}</div>
        </Field>
        <div className="mt-3">
          <JsonBlock value={credentials?.private_key_pem.split("\n").slice(0, 2).join("\n") + "\n…"} />
        </div>
      </Modal>

      <Modal open={modal === "passport"} onClose={() => setModal(null)} title="Signed agent passport" wide>
        <p className="mb-3 text-sm text-muted">A portable statement of who this agent is and what it is for, signed by the Aegis STS (ES256).</p>
        {passport.data ? (
          <>
            <JsonBlock value={passport.data.passport} />
            <div className="mt-3 text-xs font-semibold tracking-wide text-muted uppercase">JWS</div>
            <div className="mt-1 rounded-lg border border-line bg-inset p-3 font-mono text-[11px] break-all text-faint">{passport.data.jws}</div>
          </>
        ) : (
          <Loading />
        )}
      </Modal>
    </>
  );
}
