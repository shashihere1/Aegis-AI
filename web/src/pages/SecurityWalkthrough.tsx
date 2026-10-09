import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { GitFork, ShieldCheck, TriangleAlert } from "lucide-react";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { bankStatusLabel, OPEN_BANK_STATUSES, type BankRun, type BankStatus } from "../lib/bank-assistant";
import type { Lineage } from "../lib/types";
import { Button, Card, JsonBlock, PageHeader, Pill, Select, TextInput } from "../components/ui";
import { LiveLineageGraph } from "./Lineage";

type Pair = { coordinator_id: string; payments_id: string; name: string; owner: string;
  coordinator_status: string; payments_status: string; connected: boolean };
type Pairs = { items: Pair[]; payment_threshold_eur: number | null; development_identity: boolean };
type Proof = { graph: Lineage; alerts: { id: string; rule_id: string; title: string; reasons: unknown }[];
  decisions: { id: string; action: string; decision: string; reasons: unknown; subject: string;
    agent_id: string; root_id: string; trace_id: string | null }[] };

export function SecurityWalkthrough() {
  const { persona, can } = useSession();
  const cache = useQueryClient();
  const customer = can("customer") && persona?.username === "jan.devries";
  const setup = can("agent-developer", "agent-owner", "admin");
  const [prefix, setPrefix] = useState("Judge");
  const [pairId, setPairId] = useState("");
  const [runId, setRunId] = useState<string | null>(null);
  const [consent, setConsent] = useState(false);
  const [amount, setAmount] = useState("5000");
  const [amountEdited, setAmountEdited] = useState(false);
  const [reason, setReason] = useState("");
  const [suspendConsent, setSuspendConsent] = useState(false);
  const [requestId, setRequestId] = useState(() => crypto.randomUUID());
  const pairs = useQuery({ queryKey: ["walkthrough-pairs", persona?.username],
    queryFn: () => api<Pairs>("/demo/api/walkthrough/pairs"), refetchInterval: 1000 });
  const pair = pairs.data?.items.find(p => p.coordinator_id === pairId);
  const ready = pair?.connected && pair.coordinator_status === "active" && pair.payments_status === "active";
  const status = useQuery({ queryKey: ["walkthrough-status", persona?.username],
    queryFn: () => api<BankStatus>("/demo/api/agent/status"), refetchInterval: 4000 });
  const history = useQuery({ queryKey: ["walkthrough-runs", persona?.username],
    queryFn: () => api<BankRun[]>("/demo/api/agent/runs"), refetchInterval: 1000 });
  const runs = history.data?.filter(r => r.coordinator_id === pairId) ?? [];
  const selectedId = runId ?? runs[0]?.id;
  const selected = useQuery({ queryKey: ["walkthrough-run", persona?.username, selectedId], enabled: !!selectedId,
    queryFn: () => api<BankRun>(`/demo/api/agent/runs/${selectedId}`), refetchInterval: 1000 });
  const run = selected.data;
  const proof = useQuery({ queryKey: ["walkthrough-proof", persona?.username, selectedId], enabled: !!run?.root_id,
    queryFn: () => api<Proof>(`/demo/api/agent/runs/${selectedId}/proof`), refetchInterval: 1000 });
  const account = useQuery({ queryKey: ["walkthrough-account", persona?.username], enabled: customer,
    queryFn: () => api<{ balance_eur: number; payments: unknown[] }>("/demo/api/bank/account"), refetchInterval: 1000 });
  useEffect(() => { if (!pairId && pairs.data?.items.length) setPairId(pairs.data.items[0].coordinator_id); }, [pairs.data, pairId]);
  useEffect(() => { if (!amountEdited && pairs.data?.payment_threshold_eur != null)
    setAmount(String(Math.max(5000, pairs.data.payment_threshold_eur + 1000))); }, [pairs.data?.payment_threshold_eur, amountEdited]);
  useEffect(() => { setConsent(false); setSuspendConsent(false); setReason(""); }, [persona?.username]);
  const refresh = () => cache.invalidateQueries();
  const register = useMutation({ retry: false, mutationFn: () =>
    post<{ coordinator_id: string }>("/demo/api/walkthrough/register", { name_prefix: prefix, owner: "niels.vandijk" }),
    onSuccess: item => { setPairId(item.coordinator_id); setRunId(null); refresh(); } });
  const approve = useMutation({ retry: false, mutationFn: () => post("/demo/api/walkthrough/approve", {
    coordinator_id: pairId, reason }), onSuccess: refresh });
  const connect = useMutation({ retry: false, mutationFn: () => post("/demo/api/walkthrough/connect", {
    coordinator_id: pairId }), onSuccess: refresh });
  const start = useMutation({ retry: false, mutationFn: (test: "read" | "payment" | "delegation") => {
    const message = test === "read" ? "What is my current account balance?"
      : test === "delegation" ? "Bounded security test: arrange a synthetic payment without permission widening."
      : `Transfer EUR ${amount} to the demo landlord as a new beneficiary, reference Judge-${requestId.slice(0, 8)}.`;
    return post<BankRun>("/demo/api/agent/runs", { request_id: requestId, coordinator_id: pairId,
      mode: test === "read" ? "inquiry" : "transfer", message, confirm_synthetic_external_call: true,
      walkthrough_case: test === "delegation" ? "delegation_widening" : "normal", auto_resume: true });
  }, onSuccess: item => { setRunId(item.id); setConsent(false); setRequestId(crypto.randomUUID()); refresh(); } });
  const proceed = useMutation({ retry: false, mutationFn: (action: "confirm" | "cancel") =>
    post(`/demo/api/agent/runs/${selectedId}/continue`, { action }), onSuccess: refresh });
  const suspend = useMutation({ retry: false, mutationFn: () => post(`/v1/agents/${pairId}/suspend`, { reason }),
    onSuccess: () => { setSuspendConsent(false); refresh(); } });
  const radius = useQuery({ queryKey: ["walkthrough-radius", persona?.username, pairId],
    enabled: !!pair && can("soc-analyst", "risk-approver", "agent-owner"),
    queryFn: () => api<{ mandates: string[]; agents_affected: string[]; pending_approvals: string[] }>(`/v1/agents/${pairId}/blast-radius`),
    refetchInterval: 1000 });
  const busy = history.data?.some(r => r.subject === "jan.devries" && OPEN_BANK_STATUSES.includes(r.status));
  const canStart = customer && ready && consent && !busy && !start.isPending && !history.isPending && !history.isError;
  const error = register.error ?? approve.error ?? connect.error ?? start.error ?? proceed.error ?? suspend.error
    ?? pairs.error ?? selected.error ?? proof.error ?? history.error;

  return <>
    <PageHeader icon={ShieldCheck} title="Security Walkthrough"
      subtitle="Two registered runtime instances. Real authorization, delegation rejection, approvals and revocation." />
    <p className="mb-5 text-sm text-muted">Synthetic banking only. Read/payment planning uses LangGraph and paid Azure requests.
      The bounded delegation challenge calls the real token service, not Azure, and never calls a bank tool.
      Sign-in remains development personas, not enterprise IAM. Runtime connections require reconnecting after a restart.</p>
    {error && <p role="alert" className="mb-4 rounded-xl border border-critical/40 p-3 text-critical-ink">{error.message}</p>}
    <div className="grid gap-5 xl:grid-cols-[380px_minmax(0,1fr)]">
      <div className="space-y-5">
        <Card title="1 · Register and independently approve">
          <div className="space-y-3 p-5 text-sm">
            <p>Priya registers two DEV agents owned by Niels. Their permissions, delegation pair and local endpoint
              are configured before approval. No default agents are changed.</p>
            {setup && <><label htmlFor="judge-prefix">Pair name prefix</label><TextInput id="judge-prefix" value={prefix}
              onChange={e => setPrefix(e.target.value)} maxLength={45} />
              <Button disabled={!pairs.data?.development_identity || prefix.trim().length < 3} loading={register.isPending}
                onClick={() => register.mutate()}>Register and submit two agents</Button></>}
            <Select label="Walkthrough agent pair" value={pairId} onChange={value => {
              setPairId(value); setRunId(null); setConsent(false); setRequestId(crypto.randomUUID());
            }} options={[{ value: "", label: "Select a registered pair" }, ...(pairs.data?.items ?? []).map(p =>
              ({ value: p.coordinator_id, label: p.name }))]} />
            {pair && <><p>A: {pair.coordinator_id} · {pair.coordinator_status}<br />B: {pair.payments_id} · {pair.payments_status}</p>
              {!customer && <div className="flex gap-3 text-accent"><Link to={`/agents/${pair.coordinator_id}`}>Review A</Link>
                <Link to={`/agents/${pair.payments_id}`}>Review B</Link></div>}
              {can("risk-approver") && <><TextInput aria-label="Agent approval reason" value={reason} onChange={e => setReason(e.target.value)}
                placeholder="Independent approval justification" />
                <Button disabled={reason.trim().length < 10 || (pair.coordinator_status !== "pending_approval" && pair.payments_status !== "pending_approval")}
                  loading={approve.isPending} onClick={() => approve.mutate()}>Approve reviewed pair</Button></>}
              {setup && <Button disabled={pair.coordinator_status !== "active" || pair.payments_status !== "active"}
                loading={connect.isPending} onClick={() => connect.mutate()}>Connect approved runtime templates</Button>}
              <Pill tone={ready ? "good" : "warning"}>{ready ? "Connected and active" : "Approval / connection required"}</Pill></>}
          </div>
        </Card>
        <Card title="2–4 · Run as Jan">
          <div className="space-y-3 p-5 text-sm">
            <p>Switch to Jan. Complete one task before starting the next. Read first, challenge second, payment third.</p>
            <label className="flex items-start gap-2"><input type="checkbox" checked={consent} disabled={!customer}
              onChange={e => setConsent(e.target.checked)} /><span>I authorize these synthetic tasks and paid Azure inference
              for read/payment planning. The delegation challenge makes no Azure call.</span></label>
            <Button disabled={!canStart || !status.data?.ready} loading={start.isPending} onClick={() => start.mutate("read")}>Run normal account inquiry</Button>
            <Button disabled={!canStart} loading={start.isPending} onClick={() => start.mutate("delegation")}>Attempt forbidden permission widening</Button>
            <p className="text-xs text-muted">The parent permits payment initiation. B additionally requests payments.status.read.
              Aegis must reject the extra purpose with DLG-004.</p>
            <label htmlFor="judge-amount">Synthetic transfer amount (EUR)</label><TextInput id="judge-amount" value={amount}
              type="number" min="0.01" max="100000" step="0.01" onChange={e => { setAmount(e.target.value); setAmountEdited(true); }} />
            <p className="text-xs text-muted">Active threshold: {pairs.data?.payment_threshold_eur ?? "unavailable"} EUR.
              PAY-010 applies above the threshold AND for a new beneficiary. This request specifies a new beneficiary.</p>
            <Button disabled={!canStart || !status.data?.ready || !Number.isFinite(Number(amount)) || Number(amount) > 100000
              || pairs.data?.payment_threshold_eur == null || Number(amount) <= pairs.data.payment_threshold_eur
              || (account.data !== undefined && Number(amount) > account.data.balance_eur)}
              loading={start.isPending} onClick={() => start.mutate("payment")}>Prepare high-risk transfer</Button>
            {busy && <p className="text-warning-ink">Finish or cancel Jan's existing task before another test.</p>}
            {account.data && <p>Stored balance: €{account.data.balance_eur.toFixed(2)} · committed payments: {account.data.payments.length}</p>}
          </div>
        </Card>
        {pair && can("soc-analyst", "risk-approver", "agent-owner") && <Card title="5 · Suspend A while delegated work is waiting">
          <div className="space-y-3 p-5 text-sm">
            <p>After the first payment completes, prepare and customer-confirm a second transfer. Leave it awaiting risk approval,
              switch to Mark, then suspend A here.</p>
            {radius.data && <p>Blast radius: {radius.data.mandates.length} active Mandates, {radius.data.agents_affected.length} agents,
              {radius.data.pending_approvals.length} pending approvals.</p>}
            <TextInput aria-label="Suspension reason" value={reason} onChange={e => setReason(e.target.value)} placeholder="Reason for stopping A" />
            <label className="flex items-start gap-2"><input type="checkbox" checked={suspendConsent}
              onChange={e => setSuspendConsent(e.target.checked)} /><span>I reviewed the blast radius and want to suspend this coordinator,
              revoke its delegated work and cancel pending approvals. Committed payments are not undone.</span></label>
            <Button disabled={!suspendConsent || !reason.trim() || !radius.data || pair.coordinator_status !== "active"}
              loading={suspend.isPending} onClick={() => suspend.mutate()}>Suspend A and revoke delegated work</Button>
          </div>
        </Card>}
      </div>
      <div className="space-y-5">
        <Card title="Live workflow and execution receipts">
          <div className="space-y-4 p-5 text-sm">
            {!run ? <p className="text-muted">No run selected. No model call is made by opening this page.</p> : <>
              <div className="flex flex-wrap items-center justify-between gap-2"><Pill>{bankStatusLabel(run.status)}</Pill><span>{run.id.slice(0, 8)}</span></div>
              <p className="text-muted">Originating human: {run.subject} · A: {run.coordinator_id} · B: {run.payments_id}</p>
              {run.status === "confirmation_required" && <div className="rounded-xl border border-warning/40 p-4">
                <p className="font-semibold">Customer review — nothing has executed</p><JsonBlock value={run.pending.arguments} />
                {customer && run.resumable && <Button variant="primary" loading={proceed.isPending}
                  onClick={() => proceed.mutate("confirm")}>Confirm this synthetic action</Button>}</div>}
              {run.status === "approval_required" && <div className="rounded-xl border border-warning/40 p-4">
                <p className="font-semibold">Risk approval required — banking execution is paused</p>
                <p className="mt-2">Switch to Sanne, approve the matching request in the inbox, and this same confirmed action resumes automatically once.</p>
                <p className="mt-2 font-mono text-xs">{run.pending.approval_id}</p>
                {!customer && <Link className="text-accent" to="/approvals">Open approval inbox →</Link>}</div>}
              {run.reply && <p className="whitespace-pre-wrap">{run.reply}</p>}
              {customer && run.resumable && <Button loading={proceed.isPending} onClick={() => proceed.mutate("cancel")}>Cancel pending run</Button>}
              {run.events.map((event, i) => <details key={i} className="rounded-lg border border-line p-3"
                open={event.kind === "denial" || event.kind === "approval"}>
                <summary>{i + 1}. {event.label} {event.kind === "tool" ? "· verified receipt" : ""}</summary>
                <JsonBlock value={event.result ?? event.arguments ?? event.metadata ?? event} /></details>)}
            </>}
          </div>
        </Card>
        {proof.data && <Card title="Live lineage · recorded enforcement, not a scripted picture" action={<GitFork className="size-4 text-accent" />}>
          <LiveLineageGraph key={`${run?.root_id}-${proof.data.graph.nodes.length}`} graph={proof.data.graph} />
          <div className="border-t border-line p-5 text-sm"><p>Green: issued / allowed. Red dashed: attempted delegation denied — no child Mandate was issued.</p>
            {run?.root_id && !customer && <Link className="text-accent" to={`/lineage/${run.root_id}`}>Open complete audit and traces →</Link>}</div>
        </Card>}
        {!!proof.data?.alerts.length && <Card title="Linked SOC alerts"><div className="space-y-3 p-5 text-sm">
          {proof.data.alerts.map(a => <div key={a.id}><p className="flex items-center gap-2 text-critical-ink"><TriangleAlert className="size-4" />{a.title} · {a.rule_id}</p>
            <p className="text-xs text-muted">{a.id}</p><JsonBlock value={a.reasons} /></div>)}
          {!customer && <Link className="text-accent" to="/alerts">Open Alert Management →</Link>}
        </div></Card>}
        {proof.data && <Card title="6 · Reconstruct the task back to its human"><div className="space-y-3 p-5 text-sm">
          <p>Root task: {run?.root_id} · originating human: {run?.subject}. Each decision below is stored with the task and trace IDs.</p>
          <JsonBlock value={proof.data.decisions} />
        </div></Card>}
        <Card title="Recorded runs for this pair"><div className="flex flex-wrap gap-2 p-5">{runs.map(item =>
          <Button key={item.id} onClick={() => setRunId(item.id)}>{item.id.slice(0, 8)} · {bankStatusLabel(item.status)}</Button>)}</div></Card>
      </div>
    </div>
  </>;
}
