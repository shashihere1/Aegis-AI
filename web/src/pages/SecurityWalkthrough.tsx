import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, GitFork, History, ShieldCheck } from "lucide-react";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { bankStatusLabel, OPEN_BANK_STATUSES, type BankRun, type BankStatus } from "../lib/bank-assistant";
import type { Lineage } from "../lib/types";
import { Badge, Button, Callout, Card, EmptyState, Field, JsonBlock, PageHeader, Select, Skeleton, SkeletonRows, StatusPill, TextInput, cx, focusRing, type Tone } from "../components/ui";
import { LiveLineageGraph } from "./Lineage";

type Pair = { coordinator_id: string; payments_id: string; name: string; owner: string;
  coordinator_status: string; payments_status: string; connected: boolean };
type Pairs = { items: Pair[]; payment_threshold_eur: number | null; development_identity: boolean };
type Proof = { graph: Lineage; alerts: { id: string; rule_id: string; title: string; reasons: unknown }[];
  decisions: { id: string; action: string; decision: string; reasons: unknown; subject: string;
    agent_id: string; root_id: string; trace_id: string | null }[] };

/** Text link in the accent colour, with the shared focus ring. */
const linkClass = cx("inline-flex items-center gap-1 rounded text-sm font-medium text-accent hover:underline", focusRing);
/** Visible focus ring on a label that wraps a native checkbox. */
const wrapFocus = "has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-solid has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-accent";

function runTone(status: string): Tone {
  if (status === "completed") return "good";
  if (status === "running") return "info";
  if (["confirmation_required", "approval_required", "not_executed", "uncertain"].includes(status)) return "warning";
  if (["failed", "denied", "blocked"].includes(status)) return "critical";
  return "neutral";
}

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
    ?? pairs.error ?? selected.error ?? proof.error ?? history.error ?? status.error ?? account.error ?? radius.error;

  return <>
    <PageHeader title="Security walkthrough"
      subtitle="Two registered runtime instances. Real authorization, delegation rejection, approvals and revocation." />
    <Callout tone="info" className="mb-6" title="Synthetic banking only">
      Read/payment planning uses LangGraph and paid Azure requests.
      The bounded delegation challenge calls the real token service, not Azure, and never calls a bank tool.
      Sign-in remains development personas, not enterprise IAM. Runtime connections require reconnecting after a restart.
    </Callout>
    {error && <Callout tone="critical" className="mb-6" title="The request could not be completed"><span className="break-words">{error.message}</span></Callout>}
    <div className="grid gap-6 xl:grid-cols-[380px_minmax(0,1fr)]">
      <div className="min-w-0 space-y-6">
        <Card title="1 · Register and independently approve">
          <div className="space-y-3 p-5 text-sm">
            <p>Priya registers two DEV agents owned by Niels. Their permissions, delegation pair and local endpoint
              are configured before approval. No default agents are changed.</p>
            {setup && <>
              <Field label="Pair name prefix"><TextInput value={prefix} onChange={e => setPrefix(e.target.value)} maxLength={45} /></Field>
              <Button disabled={!pairs.data?.development_identity || prefix.trim().length < 3} loading={register.isPending}
                onClick={() => register.mutate()}>Register and submit two agents</Button></>}
            <Field label="Walkthrough agent pair" hint={!pairs.isLoading && !pairs.data?.items.length ? "No registered pairs yet." : undefined}>
              {pairs.isLoading ? <Skeleton className="h-9 w-full" /> : <Select label="Walkthrough agent pair" value={pairId} onChange={value => {
                setPairId(value); setRunId(null); setConsent(false); setRequestId(crypto.randomUUID());
              }} options={[{ value: "", label: "Select a registered pair" }, ...(pairs.data?.items ?? []).map(p =>
                ({ value: p.coordinator_id, label: p.name }))]} />}
            </Field>
            {pair && <>
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2"><span className="font-medium">A</span><span className="font-mono text-xs break-all">{pair.coordinator_id}</span><StatusPill status={pair.coordinator_status} /></div>
                <div className="flex flex-wrap items-center gap-2"><span className="font-medium">B</span><span className="font-mono text-xs break-all">{pair.payments_id}</span><StatusPill status={pair.payments_status} /></div>
              </div>
              {!customer && <div className="flex gap-4"><Link className={linkClass} to={`/agents/${pair.coordinator_id}`}>Review A</Link>
                <Link className={linkClass} to={`/agents/${pair.payments_id}`}>Review B</Link></div>}
              {can("risk-approver") && <>
                <Field label="Agent approval reason"><TextInput value={reason} onChange={e => setReason(e.target.value)}
                  placeholder="Independent approval justification" /></Field>
                <Button variant="primary" disabled={reason.trim().length < 10 || (pair.coordinator_status !== "pending_approval" && pair.payments_status !== "pending_approval")}
                  loading={approve.isPending} onClick={() => approve.mutate()}>Approve reviewed pair</Button></>}
              {setup && <Button disabled={pair.coordinator_status !== "active" || pair.payments_status !== "active"}
                loading={connect.isPending} onClick={() => connect.mutate()}>Connect approved runtime templates</Button>}
              <div><Badge tone={ready ? "good" : "warning"}>{ready ? "Connected and active" : "Approval / connection required"}</Badge></div></>}
          </div>
        </Card>
        <Card title="2–4 · Run as Jan">
          <div className="space-y-3 p-5 text-sm">
            <p>Switch to Jan. Complete one task before starting the next. Read first, challenge second, payment third.</p>
            <label className={cx("flex cursor-pointer items-start gap-2 rounded has-[:disabled]:cursor-not-allowed", wrapFocus)}>
              <input type="checkbox" className="mt-0.5 size-4 shrink-0 accent-accent" checked={consent} disabled={!customer}
                onChange={e => setConsent(e.target.checked)} /><span>I authorize these synthetic tasks and paid Azure inference
              for read/payment planning. The delegation challenge makes no Azure call.</span></label>
            <Button disabled={!canStart || !status.data?.ready} loading={start.isPending} onClick={() => start.mutate("read")}>Run normal account inquiry</Button>
            <Button disabled={!canStart} loading={start.isPending} onClick={() => start.mutate("delegation")}>Attempt forbidden permission widening</Button>
            <p className="text-caption text-muted">The parent permits payment initiation. B additionally requests <span className="font-mono">payments.status.read</span>.
              Aegis must reject the extra purpose with <span className="font-mono">DLG-004</span>.</p>
            <Field label="Synthetic transfer amount (EUR)"><TextInput value={amount}
              type="number" min="0.01" max="100000" step="0.01" onChange={e => { setAmount(e.target.value); setAmountEdited(true); }} /></Field>
            <p className="text-caption text-muted">Active threshold: {pairs.data?.payment_threshold_eur ?? "unavailable"} EUR.
              <span className="font-mono"> PAY-010</span> applies above the threshold AND for a new beneficiary. This request specifies a new beneficiary.</p>
            <Button disabled={!canStart || !status.data?.ready || !Number.isFinite(Number(amount)) || Number(amount) > 100000
              || pairs.data?.payment_threshold_eur == null || Number(amount) <= pairs.data.payment_threshold_eur
              || (account.data !== undefined && Number(amount) > account.data.balance_eur)}
              loading={start.isPending} onClick={() => start.mutate("payment")}>Prepare high-risk transfer</Button>
            {busy && <Callout tone="warning" title="Finish or cancel Jan's existing task before another test." />}
            {customer && account.isLoading && <Skeleton className="h-4 w-56" />}
            {account.data && <p>Stored balance: <span className="tabular">€{account.data.balance_eur.toFixed(2)}</span> · committed payments: {account.data.payments.length}</p>}
          </div>
        </Card>
        {pair && can("soc-analyst", "risk-approver", "agent-owner") && <Card title="5 · Suspend A while delegated work is waiting">
          <div className="space-y-3 p-5 text-sm">
            <p>After the first payment completes, prepare and customer-confirm a second transfer. Leave it awaiting risk approval,
              switch to Mark, then suspend A here.</p>
            {radius.isLoading && <Skeleton className="h-4 w-64" />}
            {radius.data && <Callout tone="warning" title="Blast radius">{radius.data.mandates.length} active Mandates, {radius.data.agents_affected.length} agents,{" "}
              {radius.data.pending_approvals.length} pending approvals.</Callout>}
            <Field label="Suspension reason"><TextInput value={reason} onChange={e => setReason(e.target.value)} placeholder="Reason for stopping A" /></Field>
            <label className={cx("flex cursor-pointer items-start gap-2 rounded", wrapFocus)}>
              <input type="checkbox" className="mt-0.5 size-4 shrink-0 accent-accent" checked={suspendConsent}
                onChange={e => setSuspendConsent(e.target.checked)} /><span>I reviewed the blast radius and want to suspend this coordinator,
              revoke its delegated work and cancel pending approvals. Committed payments are not undone.</span></label>
            <Button variant="danger" disabled={!suspendConsent || !reason.trim() || !radius.data || pair.coordinator_status !== "active"}
              loading={suspend.isPending} onClick={() => suspend.mutate()}>Suspend A and revoke delegated work</Button>
          </div>
        </Card>}
      </div>
      <div className="min-w-0 space-y-6">
        <Card className="overflow-hidden" title="Live workflow and execution receipts">
          {selectedId && selected.isLoading ? <div className="space-y-3 p-5" role="status" aria-label="Loading the selected run"><Skeleton className="h-6 w-32" /><Skeleton className="h-16 w-full" /><Skeleton className="h-24 w-full" /></div>
            : !run ? <EmptyState icon={ShieldCheck} title="No run selected">No model call is made by opening this page.</EmptyState>
            : <div className="space-y-4 p-5 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2"><Badge tone={runTone(run.status)}>{bankStatusLabel(run.status)}</Badge><span className="font-mono text-xs text-muted">{run.id.slice(0, 8)}</span></div>
              <p className="text-muted">Originating human: {run.subject} · A: <span className="font-mono text-xs">{run.coordinator_id}</span> · B: <span className="font-mono text-xs">{run.payments_id}</span></p>
              {run.status === "confirmation_required" && <Callout tone="warning" title="Customer review — nothing has executed">
                <div className="mt-2"><JsonBlock value={run.pending.arguments} /></div>
                {customer && run.resumable && <div className="mt-3"><Button variant="primary" loading={proceed.isPending}
                  onClick={() => proceed.mutate("confirm")}>Confirm this synthetic action</Button></div>}</Callout>}
              {run.status === "approval_required" && <Callout tone="warning" title="Risk approval required — banking execution is paused">
                <p>Switch to Sanne, approve the matching request in the inbox, and this same confirmed action resumes automatically once.</p>
                <p className="mt-2 font-mono text-xs break-all">{run.pending.approval_id}</p>
                {!customer && <div className="mt-2"><Link className={linkClass} to="/approvals">Open approval inbox →</Link></div>}</Callout>}
              {run.reply && <p className="break-words whitespace-pre-wrap">{run.reply}</p>}
              {customer && run.resumable && <Button loading={proceed.isPending} onClick={() => proceed.mutate("cancel")}>Cancel pending run</Button>}
              {run.events.map((event, i) => <details key={i} className="group rounded-lg border border-line"
                open={event.kind === "denial" || event.kind === "approval"}>
                <summary className={cx("flex cursor-pointer list-none flex-wrap items-center gap-2 rounded-lg px-3 py-2.5 font-medium text-fg", focusRing)}>
                  <ChevronDown className="size-3.5 shrink-0 text-muted transition-transform group-open:rotate-180" aria-hidden />
                  <span className="break-words">{i + 1}. {event.label}</span>{event.kind === "tool" && <Badge tone="good">Verified receipt</Badge>}</summary>
                <div className="px-3 pb-3"><JsonBlock value={event.result ?? event.arguments ?? event.metadata ?? event} /></div></details>)}
            </div>}
        </Card>
        {run?.root_id && proof.isLoading && <Card><div className="space-y-3 p-5" role="status" aria-label="Loading lineage"><Skeleton className="h-3.5 w-48" /><Skeleton className="h-32 w-full" /></div></Card>}
        {proof.data && <Card className="overflow-hidden" title="Live lineage · recorded enforcement, not a scripted picture" action={<GitFork className="size-4 text-muted" aria-hidden />}
          footer={<div className="space-y-2 text-muted"><p>Green: issued / allowed. Red dashed: attempted delegation denied — no child Mandate was issued.</p>
            {run?.root_id && !customer && <Link className={linkClass} to={`/lineage/${run.root_id}`}>Open complete audit and traces →</Link>}</div>}>
          <LiveLineageGraph key={`${run?.root_id}-${proof.data.graph.nodes.length}`} graph={proof.data.graph} />
        </Card>}
        {!!proof.data?.alerts.length && <Card title="Linked SOC alerts"><div className="space-y-3 p-5 text-sm">
          {proof.data.alerts.map(a => <Callout key={a.id} tone="critical" title={<>{a.title} · <span className="font-mono">{a.rule_id}</span></>}>
            <p className="font-mono text-xs break-all">{a.id}</p><div className="mt-2"><JsonBlock value={a.reasons} /></div></Callout>)}
          {!customer && <Link className={linkClass} to="/alerts">Open Alert Management →</Link>}
        </div></Card>}
        {proof.data && <Card className="overflow-hidden" title="6 · Reconstruct the task back to its human">
          <div className="space-y-3 p-5 text-sm">
            <p>Root task: <span className="font-mono text-xs break-all">{run?.root_id}</span> · originating human: {run?.subject}. Each decision below is stored with the task and trace IDs.</p>
            {proof.data.decisions.length ? <JsonBlock value={proof.data.decisions} /> : <EmptyState title="No decisions recorded yet" />}
          </div>
        </Card>}
        <Card className="overflow-hidden" title="Recorded runs for this pair">
          {history.isLoading ? <SkeletonRows rows={2} cols={2} />
            : !runs.length ? <EmptyState icon={History} title="No recorded runs for this pair">Runs you start for the selected pair appear here.</EmptyState>
            : <div className="flex flex-wrap gap-2 p-5">{runs.map(item =>
              <Button key={item.id} variant={item.id === selectedId ? "primary" : "secondary"} aria-pressed={item.id === selectedId}
                onClick={() => setRunId(item.id)}><span className="font-mono text-xs">{item.id.slice(0, 8)}</span> · {bankStatusLabel(item.status)}</Button>)}</div>}
        </Card>
      </div>
    </div>
  </>;
}
