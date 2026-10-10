import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRight, ArrowUpRight, BadgeCheck, Bot, CheckCircle2, ChevronDown, ChevronRight,
  CircleHelp, Clock3, FileCheck2, History, Info, LockKeyhole, MapPin,
  MessageSquare, ReceiptText, Send, ShieldCheck, Sparkles, TriangleAlert, Wallet, X, type LucideIcon,
} from "lucide-react";
import { api, post } from "../lib/api";
import {
  BANK_TASKS, DELEGATION_TEST_PROMPT, OPEN_BANK_STATUSES, bankReceipt, bankRunStats, bankStatusLabel, eventEstimate, lacksChangeReceipt, record,
  type BankEvent, type BankMode, type BankRun, type BankStatus, type RuntimePairs,
} from "../lib/bank-assistant";
import { euro, titleCase } from "../lib/format";
import { useSession } from "../lib/session";
import {
  Badge, Button, Callout, Card, EmptyState, ErrorState, Field, JsonBlock, PageHeader, Select, Skeleton, SkeletonRows, Spinner, Stat, StatGroup, Textarea, cx, focusRing,
} from "../components/ui";
import { RunGovernanceProof } from "../components/RunGovernanceProof";

const TASK_ICONS: Record<BankMode, LucideIcon> = {
  inquiry: Wallet, documents: FileCheck2, address: MapPin, transfer: ArrowUpRight,
};

/** Text link / link-button in the accent colour, with the shared focus ring. */
const linkClass = cx("inline-flex items-center gap-1 rounded text-sm font-medium text-accent hover:underline", focusRing);
/** Visible focus ring on a label that wraps a visually-hidden input. */
const wrapFocus = "has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-solid has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-accent";

type AccountSnapshot = {
  balance_eur: number; address: string; storage: string;
  payments: { payment_id: string; amount: number; status: string; reference: string; created_at: string }[];
};

function SandboxAccount({ enabled }: { enabled: boolean }) {
  const { persona } = useSession();
  const account = useQuery({ queryKey: ["sandbox-account", persona?.username], enabled,
    queryFn: () => api<AccountSnapshot>("/demo/api/bank/account"), refetchInterval: 4000 });
  if (!enabled) return null;
  return <Card title="Your synthetic sandbox account" className="mb-6" action={<Badge>Database view · no Azure call</Badge>}>
    {account.isPending ? <div className="space-y-3 p-5" role="status" aria-label="Loading account"><Skeleton className="h-3.5 w-32" /><Skeleton className="h-8 w-40" /><Skeleton className="h-3.5 w-full max-w-md" /></div>
      : account.isError ? <div className="p-5"><Callout tone="critical" title="The account database is unavailable" action={<Button size="sm" onClick={() => void account.refetch()}>Try again</Button>}>No cached balance is shown as current.</Callout></div>
      : <div className="p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div><p className="text-caption text-muted">Current stored balance</p><p className="mt-1 text-3xl font-semibold tracking-tight text-fg">{euro(account.data.balance_eur)}</p></div>
          <div className="text-sm"><Badge>{account.data.storage}</Badge><p className="mt-2 max-w-lg text-muted">{account.data.address}</p></div>
        </div>
        <p className="mt-3 text-caption text-muted">Only an authorized transfer changes this balance. Confirmation and approval alone do not. Synthetic funds only.</p>
        <div className="mt-4 border-t border-line pt-3"><h3 className="text-sm font-medium text-fg">Recent committed payments</h3>
          {!account.data.payments.length ? <p className="mt-2 text-sm text-muted">No payments yet. Records persist across server restarts.</p>
            : <ul className="mt-2 divide-y divide-line">{account.data.payments.map(payment => <li key={payment.payment_id} className="flex flex-wrap justify-between gap-2 py-2 text-sm">
              <div><span className="font-mono text-xs">{payment.payment_id}</span><p className="text-caption text-muted">{payment.reference || "No reference"} · {new Date(payment.created_at).toLocaleString()}</p></div>
              <div className="text-right font-medium">{euro(payment.amount)}<p className="text-caption font-normal text-muted">Synthetic · {payment.status}</p></div>
            </li>)}</ul>}
        </div>
      </div>}
  </Card>;
}

function RunStatus({ status }: { status: string }) {
  if (status === "running") return <Badge tone="info" icon={Clock3}>{bankStatusLabel(status)}</Badge>;
  if (status === "completed") return <Badge tone="good" icon={CheckCircle2}>{bankStatusLabel(status)}</Badge>;
  if (["confirmation_required", "approval_required", "not_executed", "uncertain"].includes(status)) return <Badge tone="warning" icon={CircleHelp}>{bankStatusLabel(status)}</Badge>;
  if (["failed", "denied", "blocked"].includes(status)) return <Badge tone="critical" icon={TriangleAlert}>{bankStatusLabel(status)}</Badge>;
  return <Badge icon={X}>{bankStatusLabel(status)}</Badge>;
}

function DataDetails({ title, value }: { title: string; value: unknown }) {
  return <details className="group mt-3 rounded-lg border border-line bg-inset">
    <summary className={cx("flex cursor-pointer list-none items-center gap-2 rounded-lg px-3 py-2.5 text-caption font-medium text-muted", focusRing)}>
      <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" />{title}
    </summary>
    <div className="px-3 pb-3"><JsonBlock value={value} /></div>
  </details>;
}

function ReceiptHighlight({ event }: { event: BankEvent }) {
  const receipt = bankReceipt(event);
  if (!receipt) return null;
  const Icon = TASK_ICONS[event.label === "get_balance" ? "inquiry" : event.label === "verify_document" ? "documents" : event.label === "update_address" ? "address" : "transfer"];
  return <div className="min-w-0 rounded-xl border border-line bg-inset p-4">
    <div className="flex items-center gap-2 text-caption font-medium text-muted"><Icon className="size-4" />{receipt.title}</div>
    <div className={cx("mt-2 font-semibold tracking-tight break-words text-fg", receipt.money ? "text-2xl" : "text-base")}>{receipt.money ? euro(receipt.value as number) : receipt.value}</div>
    {receipt.detail && <div className="mt-1 font-mono text-xs break-all text-muted">{receipt.detail}</div>}
    <div className="mt-3 flex items-center gap-1.5 text-caption font-medium text-good-ink"><BadgeCheck className="size-3.5" />Verified tool result · synthetic bank</div>
  </div>;
}

function WorkflowEvent({ event, index, last }: { event: BankEvent; index: number; last: boolean }) {
  const verified = event.kind === "tool" && event.result !== undefined && event.result !== null;
  const model = event.kind === "model";
  const caution = ["approval", "warning"].includes(event.kind);
  const Icon = verified ? BadgeCheck : model ? Sparkles : caution ? TriangleAlert : ArrowRight;
  const estimate = eventEstimate(event);
  const label = verified ? `Result: ${titleCase(event.label)}` : model ? "Azure model response"
    : event.kind === "proposal" ? `Requested: ${titleCase(event.label)}` : event.label;
  return <li className="relative flex min-w-0 gap-3 pb-5 last:pb-0">
    <div className="relative flex w-8 shrink-0 justify-center">
      {!last && <span className="absolute top-8 bottom-[-4px] w-px bg-line" aria-hidden />}
      <span className={cx("relative grid size-8 place-items-center rounded-full border",
        verified ? "border-good/30 bg-good/10 text-good-ink" : model ? "border-series/30 bg-series/10 text-info-ink"
          : caution ? "border-warning/30 bg-warning/10 text-warning-ink" : "border-line-strong bg-inset text-muted")}><Icon className="size-4" /></span>
    </div>
    <div className="min-w-0 flex-1 rounded-xl border border-line p-3.5">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1"><span className="font-mono text-2xs text-muted">{String(index + 1).padStart(2, "0")}</span>
        <h3 className="min-w-0 text-sm font-medium break-words text-fg">{label}</h3>{verified && <span className="text-caption font-medium text-good-ink">Verified receipt</span>}</div>
      {model && <p className="mt-1 text-caption text-muted">Model output guides the workflow; it is not proof of a banking action.</p>}
      {event.kind === "proposal" && <p className="mt-1 text-caption text-muted">Proposed tool arguments, not an execution receipt.</p>}
      {event.runtime && <p className="mt-1 text-caption text-muted">Executed through <span className="font-medium text-fg">{event.runtime}</span></p>}
      {event.usage && <div className="tabular mt-2 flex flex-wrap gap-x-3 gap-y-1 text-caption text-muted">
        <span>{event.usage.prompt_tokens.toLocaleString()} input / {event.usage.completion_tokens.toLocaleString()} output tokens</span>
        <span>{estimate === null ? "Estimate unavailable" : `${euro(estimate, 6)} estimated`}</span></div>}
      {event.arguments !== undefined && <DataDetails title="Inspect proposed arguments" value={event.arguments} />}
      {event.result !== undefined && <DataDetails title={verified ? "Inspect full receipt" : "Inspect result data"} value={event.result} />}
      {event.metadata && Object.keys(event.metadata).length > 0 && <DataDetails title="Request and trace details" value={event.metadata} />}
      {event.approval_id && <p className="mt-2 font-mono text-xs break-all text-warning-ink">Approval: {event.approval_id}</p>}
    </div>
  </li>;
}

function ProposedArguments({ value }: { value: unknown }) {
  const data = record(value);
  if (!data || !Object.keys(data).length) return <JsonBlock value={value ?? {}} />;
  return <dl className="my-3 divide-y divide-line rounded-lg border border-line bg-card px-3">
    {Object.entries(data).map(([key, item]) => <div key={key} className="grid gap-1 py-2.5 sm:grid-cols-[110px_minmax(0,1fr)] sm:gap-3">
      <dt className="text-caption text-muted">{titleCase(key)}</dt><dd className="min-w-0 text-sm font-medium break-words text-fg">
        {key === "amount" && typeof item === "number" ? euro(item) : typeof item === "string" ? item : typeof item === "boolean" ? (item ? "Yes" : "No") : JSON.stringify(item)}</dd>
    </div>)}
  </dl>;
}

function RuntimeOverview({ status, loading, onRetry }: { status?: BankStatus; loading: boolean; onRetry: () => void }) {
  if (!status) {
    if (loading) return <StatGroup className="mb-6"><div role="status" aria-label="Checking runtime configuration" className="contents">
      {[0, 1, 2, 3].map(i => <div key={i} className="space-y-3 bg-card p-5"><Skeleton className="h-3.5 w-28" /><Skeleton className="h-7 w-36" /><Skeleton className="h-3.5 w-24" /></div>)}</div></StatGroup>;
    return <Callout tone="warning" className="mb-6" title="Runtime status unavailable" action={<Button size="sm" onClick={onRetry}>Try again</Button>}>Configuration and budget could not be checked.</Callout>;
  }
  const { policy, budget } = status;
  const remaining = policy.daily_budget_eur > 0 ? Math.max(0, Math.min(1, budget.remaining_estimate_eur / policy.daily_budget_eur)) : 0;
  return <div className="mb-6 space-y-3">
    <StatGroup>
      <Stat label="Azure deployment" value={<span className="text-xl break-all">{policy.deployment || "Not configured"}</span>} caption="Model endpoint in use" />
      <Stat label="Processing scope" value={<span className="text-xl">{titleCase(policy.processing_scope)}</span>} caption={`Permitted: ${policy.allowed_processing_scope}`} />
      <Stat label="Data ceiling" value={<span className="text-xl">{titleCase(policy.max_data_class)}</span>} caption="Highest data class Ava may process" />
      <Stat label="Daily budget remaining" value={<span className="text-xl">{euro(budget.remaining_estimate_eur, 4)}</span>} caption={<>
        <span className="block">of {euro(policy.daily_budget_eur)} · estimate</span>
        <span className="mt-2 block h-1.5 rounded-full bg-chart-muted/30" role="meter" aria-label="Estimated daily budget remaining" aria-valuemin={0} aria-valuemax={Math.max(0, policy.daily_budget_eur)}
          aria-valuenow={Math.max(0, Math.min(policy.daily_budget_eur, budget.remaining_estimate_eur))} aria-valuetext={`${euro(budget.remaining_estimate_eur, 4)} remaining per agent/day UTC`}>
          <span className={cx("block h-1.5 rounded-full", remaining < 0.2 ? "bg-warning" : "bg-series")} style={{ width: `${remaining * 100}%` }} /></span></>} />
    </StatGroup>
    <details className="group rounded-xl border border-line bg-card px-5 py-3 text-caption shadow-card">
      <summary className={cx("flex cursor-pointer list-none items-center gap-2 rounded text-muted", focusRing)}><Info className="size-3.5" />Runtime, budget and policy details<ChevronDown className="ml-auto size-3.5 transition-transform group-open:rotate-180" /></summary>
      <div className="mt-3 flex flex-wrap gap-2">{Object.entries(status.frameworks).map(([name, version]) => <Badge key={name} tone={version ? "neutral" : "warning"}>{name}: {version ?? "missing"}</Badge>)}</div>
      <p className="mt-3 leading-relaxed text-muted">Per agent/day UTC · {budget.day_utc} · {budget.outstanding_holds} uncertain/in-flight budget holds. Estimates are not Azure invoices. OPA is not used for model controls. Configuration readiness does not prove Azure connectivity.</p>
    </details>
    {!!status.bank_tools_requiring_review?.length && <Callout tone="warning" title="Banking tools need independent security review">
      <p>Updated definitions remain blocked until a security approver reviews and approves them in MCP Servers &amp; Tools. This does not bypass approval.</p>
      <p className="mt-2 font-mono text-xs break-words">{status.bank_tools_requiring_review.join(" · ")}</p>
    </Callout>}
    {!status.ready && <Callout tone="warning" title={status.policy_error || "Configure Azure and install requirements-agents.txt before starting a task."}>
      See docs/live-agents.md. Processing geography must match the actual deployment, not just the resource region.
    </Callout>}
  </div>;
}

function WorkflowEmptyState() {
  return <div className="px-5 py-8 sm:py-12">
    <div className="mx-auto grid size-12 place-items-center rounded-full bg-accent-soft text-accent"><MessageSquare className="size-6" /></div>
    <h3 className="mt-5 text-center text-lg font-semibold text-fg">Your task, with a clear trail</h3>
    <p className="mx-auto mt-2 max-w-sm text-center text-sm leading-relaxed text-muted">Ask Ava a question or select a previous run. The workflow will show what was proposed and what actually executed.</p>
    <div className="mt-8 space-y-3">{[
      { icon: Sparkles, title: "Ava proposes", description: "Azure chooses a response or a tool for your purpose." },
      { icon: ShieldCheck, title: "Aegis authorizes", description: "Permissions and Mandate limits govern tool execution." },
      { icon: ReceiptText, title: "Tools return receipts", description: "Executed actions have results you can inspect." },
    ].map((step, i) => <div key={step.title} className="flex items-start gap-3 rounded-xl border border-line bg-inset p-3.5">
      <step.icon className="mt-0.5 size-4 shrink-0 text-accent" /><div><div className="text-sm font-medium text-fg"><span className="mr-2 font-mono text-xs text-muted">0{i + 1}</span>{step.title}</div><p className="mt-1 text-caption leading-relaxed text-muted">{step.description}</p></div></div>)}</div>
    <p className="mt-6 text-center text-caption text-muted">No model request is made until you submit a task.</p>
  </div>;
}

export function BankAssistant() {
  const { persona, personas, can, source, config, switchTo } = useSession();
  const queryClient = useQueryClient();
  const customer = can("customer") && persona?.username === "jan.devries";
  const [mode, setMode] = useState<BankMode>("inquiry");
  const [message, setMessage] = useState(BANK_TASKS.inquiry.example);
  const [consent, setConsent] = useState(false);
  const [runId, setRunId] = useState<string | null>(null);
  const [requestId, setRequestId] = useState(() => crypto.randomUUID());
  const [allHistory, setAllHistory] = useState(false);
  const [coordinator, setCoordinator] = useState("");
  const [securityTest, setSecurityTest] = useState(false);
  const pairs = useQuery({ queryKey: ["bank-runtime-pairs", persona?.username],
    queryFn: () => api<RuntimePairs>("/demo/api/walkthrough/pairs"), refetchInterval: 3000 });
  const pair = pairs.data?.items.find(item => item.coordinator_id === coordinator);
  const pairReady = !coordinator || !!(pair?.connected && pair.coordinator_status === "active" && pair.payments_status === "active");
  const pairModeAllowed = !coordinator || mode === "inquiry" || mode === "transfer";
  const status = useQuery({ queryKey: ["live-agent-status", persona?.username, coordinator],
    queryFn: () => api<BankStatus>("/demo/api/agent/status", { query: { coordinator_id: coordinator || undefined } }), refetchInterval: 4000 });
  const history = useQuery({ queryKey: ["live-agent-history", persona?.username],
    queryFn: () => api<BankRun[]>("/demo/api/agent/runs"), refetchInterval: 2000 });
  const selected = useQuery({ queryKey: ["live-agent-run", persona?.username, runId],
    queryFn: () => api<BankRun>(`/demo/api/agent/runs/${runId}`), enabled: !!runId, refetchInterval: 1000 });
  const run = selected.data;
  const openRun = history.data?.find(item => item.subject === persona?.username && OPEN_BANK_STATUSES.includes(item.status));
  useEffect(() => { setRunId(null); setConsent(false); setSecurityTest(false); setAllHistory(false); setRequestId(crypto.randomUUID()); }, [persona?.username]);
  useEffect(() => { if (!runId && openRun) setRunId(openRun.id); }, [runId, openRun]);
  const start = useMutation({ retry: false, mutationFn: () => post<BankRun>("/demo/api/agent/runs", {
    request_id: requestId, mode, message, confirm_synthetic_external_call: true,
    coordinator_id: coordinator || null, walkthrough_case: securityTest ? "delegation_widening" : "normal",
    auto_resume: !!coordinator,
  }), onSuccess: item => { setRunId(item.id); setConsent(false); setRequestId(crypto.randomUUID()); queryClient.invalidateQueries(); } });
  const proceed = useMutation({ retry: false, mutationFn: (action: string) =>
    post<BankRun>(`/demo/api/agent/runs/${runId}/continue`, { action }),
    onSuccess: () => queryClient.invalidateQueries() });
  const error = start.error ?? proceed.error ?? selected.error ?? history.error ?? status.error;
  const busy = !!openRun || start.isPending;
  const canStart = customer && consent && pairReady && pairModeAllowed && (securityTest ? !!coordinator : !!status.data?.ready)
    && !busy && !history.isPending && !history.isError && message.trim().length >= 3;
  const canContinue = customer && run?.subject === persona?.username && run.resumable;
  const stats = run ? bankRunStats(run.events) : null;
  const highlights = run?.events.filter(event => bankReceipt(event) !== null) ?? [];
  const recent = history.data ?? [];
  const disabledReason = !customer ? "Only Jan's synthetic customer account can start a task. Staff can inspect runs."
    : history.isPending ? "Checking for an existing task…"
    : history.isError ? "Task history is unavailable. Wait for it to reconnect before starting a task."
    : openRun ? "Finish or cancel your open task before starting another."
    : !pairReady ? "The selected agent pair must be approved, connected and active."
    : !pairModeAllowed ? "This pair supports inquiries and transfers only. Choose default Ava for document/address tasks."
    : securityTest && !coordinator ? "Choose a registered pair for the bounded security test."
    : !securityTest && !status.data?.ready ? "The runtime must be ready before you can start."
    : !consent ? "Confirm synthetic data and paid Azure inference to continue."
    : message.trim().length < 3 ? "Enter a request of at least 3 characters." : null;

  return <>
    <PageHeader title="Bank assistant" subtitle="Ava plans the task. Aegis governs execution. You stay in control."
      actions={status.isPending ? <Badge icon={Clock3}>Checking configuration</Badge> : status.data?.ready
        ? <Badge tone="good">Runtime configured</Badge> : <Badge tone="warning" icon={TriangleAlert}>Setup needed</Badge>} />

    <Card className="mb-6">
      <div className="flex flex-wrap items-start gap-4 p-5">
        <div className="grid size-10 shrink-0 place-items-center rounded-full bg-accent-soft text-accent"><Bot className="size-5" /></div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5"><h2 className="text-lg font-semibold text-fg">{customer ? `Hi ${persona?.name.split(" ")[0] || "Jan"}, I'm Ava` : "Meet Ava, your banking assistant"}</h2>
            <Badge tone="accent">Synthetic bank</Badge><Badge tone="warning">Paid Azure requests</Badge></div>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted">Check an account, verify a document, or review a change. Only use synthetic demo data; no real money moves.</p>
          <p className="mt-1 text-caption leading-relaxed text-muted">Ava: LangGraph + Azure tool calling · KYC: Microsoft Agent Framework · Banking data: persistent synthetic sandbox. Document checks are synthetic, not genuine KYC.
            {source === "dev" ? " Sign-in uses passwordless development personas, not enterprise IAM." : source === "sso" ? " You are signed in with SSO." : ""}</p>
        </div>
        {!customer && config?.dev_login && personas.some(item => item.username === "jan.devries" && item.status === "active")
          && <Button icon={ArrowRight} onClick={() => switchTo("jan.devries")}>Act as Jan</Button>}
      </div>
    </Card>

    <RuntimeOverview status={status.data} loading={status.isPending} onRetry={() => void status.refetch()} />

    {error && <Callout tone="critical" className="mb-6" title="The request could not be completed">
      <p className="break-words">{error.message}</p><p className="mt-2 text-caption">No automatic action retry. Review the run and any receipts before submitting a new write.</p>
    </Callout>}

    <SandboxAccount enabled={customer} />

    <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.15fr)]">
      <div className="min-w-0 space-y-6">
        <Card title="Start a customer task" action={<span className="text-caption text-muted">01 · Request</span>}>
          <form className="p-5" onSubmit={event => { event.preventDefault(); if (canStart) start.mutate(); }}>
            <fieldset disabled={busy} className="mb-5 space-y-3">
              <Field label="Executing agent pair" hint="Pair transfers resume automatically after independent approval.">
                <Select
                  label="Executing agent pair"
                  value={coordinator}
                  className="w-full"
                  onChange={(value) => {
                    setCoordinator(value);
                    setSecurityTest(false);
                    setConsent(false);
                    setRequestId(crypto.randomUUID());
                    start.reset();
                  }}
                  options={[
                    { value: "", label: "Default Ava / Payments (also supports KYC)" },
                    ...(pairs.data?.items ?? []).map((item) => ({ value: item.coordinator_id, label: `${item.name} · ${item.connected ? item.coordinator_status : "not connected"}` })),
                  ]}
                />
              </Field>
              <p className="text-caption text-muted">
                Register, independently approve and connect pairs in <Link to="/walkthrough" className={linkClass}>Security Walkthrough</Link>.
              </p>
              <label className={cx("flex cursor-pointer items-start gap-2 rounded text-caption", wrapFocus)}>
                <input
                  type="checkbox"
                  checked={securityTest}
                  disabled={!coordinator || !customer}
                  className="mt-0.5 size-4 shrink-0 accent-accent"
                  onChange={(event) => {
                    const enabled = event.target.checked;
                    setSecurityTest(enabled);
                    setConsent(false);
                    setMode("transfer");
                    setMessage(enabled ? DELEGATION_TEST_PROMPT : BANK_TASKS.transfer.example);
                    setRequestId(crypto.randomUUID());
                  }}
                />
                <span>Enable bounded permission-widening security test</span>
              </label>
              {securityTest && (
                <Callout tone="warning" title="Security test mode">
                  This request describes the selected test. The explicit test mode submits a real forbidden delegation to the token service; Azure does not interpret the prompt.
                  Expect DLG-004, a linked alert and no bank call. Normal prompts never silently enable this test.
                </Callout>
              )}
            </fieldset>
            <fieldset className="min-w-0" disabled={busy || securityTest}>
              <legend className="text-sm font-medium text-fg">What would you like to do?</legend>
              <p className="mt-1 text-caption text-muted">Your purpose limits the Mandate and the available tools.</p>
              <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {(Object.keys(BANK_TASKS) as BankMode[]).map(value => {
                  const task = BANK_TASKS[value];
                  const Icon = TASK_ICONS[value];
                  return <label key={value} className={cx("relative flex cursor-pointer items-start gap-2.5 rounded-xl border p-3 transition-colors", wrapFocus,
                    mode === value ? "border-accent bg-accent-soft" : "border-line-strong bg-card hover:bg-hover", busy && "cursor-not-allowed opacity-60")}>
                    <input className="sr-only" type="radio" name="bank-purpose" value={value} checked={mode === value}
                      onChange={() => { setMode(value); setMessage(task.example); setConsent(false); }} />
                    <Icon className={cx("mt-0.5 size-4 shrink-0", mode === value ? "text-accent" : "text-muted")} />
                    <span className="min-w-0 pr-4"><span className="block text-sm font-semibold text-fg">{task.label}</span><span className="mt-0.5 block text-caption leading-relaxed text-muted">{task.description}</span></span>
                    {mode === value && <CheckCircle2 className="absolute top-2.5 right-2.5 size-3.5 text-accent" aria-hidden />}
                  </label>;
                })}
              </div>
            </fieldset>
            <div className="mt-5 flex items-center justify-between gap-2"><label htmlFor="bank-request" className="text-sm font-medium text-fg">Your request</label>
              <Button type="button" variant="link" disabled={busy} onClick={() => setMessage(securityTest ? DELEGATION_TEST_PROMPT : BANK_TASKS[mode].example)}>Use example</Button></div>
            <Textarea id="bank-request" rows={4} maxLength={1500} value={message} onChange={event => setMessage(event.target.value)} disabled={busy}
              aria-describedby="bank-request-hint" placeholder="Tell Ava what you need…" className="mt-2 min-h-28 resize-y disabled:opacity-60" />
            <div id="bank-request-hint" className="mt-1.5 flex justify-between gap-2 text-caption text-muted"><span>Synthetic data only. Never paste real customer details.</span><span className="tabular shrink-0">{message.length} / 1,500</span></div>
            <label className={cx("my-4 flex cursor-pointer items-start gap-3 rounded-xl border border-line bg-inset p-3.5 text-sm leading-relaxed", wrapFocus)}>
              <input type="checkbox" checked={consent} disabled={busy || !customer} onChange={event => setConsent(event.target.checked)} className="mt-0.5 size-4 shrink-0 accent-accent" />
              <span>{securityTest ? "I authorize this synthetic security test. It makes no Azure request and cannot execute a banking action." : <>I am using synthetic data and authorize <span className="font-semibold text-fg">paid Azure inference</span> for this task.</>}</span>
            </label>
            <Button type="submit" variant="primary" className="w-full" icon={Send} loading={start.isPending} disabled={!canStart}>{securityTest ? "Run permission-widening test" : "Ask Ava"}</Button>
            <p aria-live="polite" className={cx("text-caption leading-relaxed text-muted", disabledReason && "mt-2.5")}>{disabledReason}</p>
            {openRun && openRun.id !== runId && <button type="button" className={cx(linkClass, "mt-2 text-caption")} onClick={() => setRunId(openRun.id)}>View your open task <ArrowRight className="size-3" /></button>}
          </form>
        </Card>

        <Card title={<span className="inline-flex items-center gap-2"><History className="size-4 text-muted" />Recent runs</span>} className="overflow-hidden" action={<span className="text-caption text-muted">{recent.length} recorded</span>}>
          {history.isPending ? <SkeletonRows rows={3} cols={2} />
            : history.isError && !recent.length ? <ErrorState title="Run history is temporarily unavailable" error={history.error} onRetry={() => void history.refetch()} />
            : !recent.length ? <EmptyState icon={History} title="No tasks yet">Your live-agent history and verified tool receipts will appear here.</EmptyState>
            : <div className="p-2">
              <div className={cx("space-y-1", allHistory && "max-h-80 overflow-y-auto")}>
                {(allHistory ? recent : recent.slice(0, 5)).map(item => {
                  const Icon = TASK_ICONS[item.mode] ?? MessageSquare;
                  return <button key={item.id} type="button" aria-pressed={runId === item.id}
                    onClick={() => { setRunId(item.id); start.reset(); proceed.reset(); }}
                    className={cx("flex w-full items-start gap-3 rounded-xl border px-3 py-3 text-left transition-colors", focusRing,
                      runId === item.id ? "border-accent bg-accent-soft" : "border-transparent hover:bg-hover")}>
                    <Icon className={cx("mt-1 size-4 shrink-0", runId === item.id ? "text-accent" : "text-muted")} />
                    <span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><span className="text-sm font-medium text-fg">{BANK_TASKS[item.mode]?.label ?? item.mode}</span><RunStatus status={item.status} /></span>
                      <span className="mt-1 block truncate text-caption text-muted">{item.subject} <span className="mx-1">·</span><span className="font-mono">{item.id.slice(0, 8)}</span></span></span>
                    <ChevronRight className="mt-1 size-4 shrink-0 text-faint" aria-hidden />
                  </button>;
                })}
              </div>
              {recent.length > 5 && <button type="button" onClick={() => setAllHistory(value => !value)} className={cx("mt-1 w-full rounded-lg py-2 text-caption font-medium text-accent hover:bg-hover", focusRing)}>{allHistory ? "Show fewer runs" : `Show all ${recent.length} runs`}</button>}
            </div>}
        </Card>
      </div>

      <Card className="min-w-0 overflow-hidden" title={<span className="inline-flex items-center gap-2"><ReceiptText className="size-4 text-muted" />Live workflow &amp; receipts</span>}
        action={run ? <span className="font-mono text-xs text-muted" title={run.id}>{run.id.slice(0, 8)}</span> : <span className="text-caption text-muted">02 · Results</span>}>
        {runId && selected.isPending ? <div className="space-y-3 p-5" role="status" aria-label="Loading the selected workflow"><Skeleton className="h-6 w-32" /><Skeleton className="h-16 w-full" /><Skeleton className="h-24 w-full" /></div>
          : runId && selected.isError && !run ? <ErrorState title="This workflow is unavailable" error={selected.error} onRetry={() => void selected.refetch()} />
          : !run ? <WorkflowEmptyState /> : <div className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3"><RunStatus status={run.status} />
              <span className="text-caption text-muted">{BANK_TASKS[run.mode]?.label ?? run.mode}{!customer ? ` · ${run.subject}` : ""}</span></div>
            {stats && <StatGroup columns={3} className="mt-4">
              <Stat label="Tool receipts" value={<span className="text-2xl">{stats.receipts}</span>} />
              <Stat label="Model calls" value={<span className="text-2xl">{stats.modelCalls}</span>} />
              <Stat label={stats.partialEstimate ? "Partial estimate" : "Task estimate"} value={<span className="text-2xl break-words">{stats.estimatedCost === null ? "—" : euro(stats.estimatedCost, 6)}</span>} />
            </StatGroup>}

            {lacksChangeReceipt(run) && <div className="mt-5" role="status"><Callout tone="warning" title="No verified change receipt">
              This historical run is finished, but it has no successful transfer or address-change receipt. A model message asking “please confirm” is not a pending action, so there is no confirmation button for this run. Check the stored account and Activity before submitting another change.
            </Callout></div>}

            {run.status === "confirmation_required" && <Callout tone="warning" icon={CircleHelp} className="mt-5" title="Review before execution">
              <p className="mt-1 text-sm font-medium text-fg">{titleCase(run.pending.name || "Proposed action")}</p>
              <ProposedArguments value={run.pending.arguments} />
              <p className="mb-2 text-caption font-medium text-warning-ink">Confirm using the button below, not by submitting another request or typing “yes”.</p>
              <p className="mb-3 text-caption leading-relaxed">This proposed action has not executed. Confirmation authorizes these exact stored arguments, not a rewritten model request.</p>
              {canContinue && <Button icon={CheckCircle2} variant="primary" className="h-auto min-h-9 w-full py-2 whitespace-normal" loading={proceed.isPending} onClick={() => proceed.mutate("confirm")}>Confirm this synthetic action</Button>}
              {!run.resumable && <p className="text-caption text-warning-ink">This stored run cannot resume. Check receipts before starting a new task.</p>}
              {!customer && <p className="text-caption">Only the initiating customer can confirm this action.</p>}
            </Callout>}
            {run.status === "approval_required" && <Callout tone="warning" icon={ShieldCheck} className="mt-5" title="Separate risk approval required">
              <p className="text-caption leading-relaxed">Customer confirmation is not risk approval. A risk approver must review the matching request in Approvals.{run.auto_resume ? " This confirmed action resumes automatically once while its Mandate is valid." : " Then Jan can resume while the Mandate is still valid."}</p>
              {run.pending.approval_id && <p className="mt-3 font-mono text-xs break-all text-warning-ink">{run.pending.approval_id}</p>}
              {source === "dev" && <p className="mt-2 text-caption">For the demo: switch to Sanne Bakker to approve, then return to Jan.</p>}
              <div className="mt-3 flex flex-wrap items-center gap-3">{canContinue && !run.auto_resume && <Button icon={ArrowRight} className="h-auto min-h-9 py-2 whitespace-normal" loading={proceed.isPending} onClick={() => proceed.mutate("resume_approval")}>Resume after risk approval</Button>}
                {!customer && <Link className={linkClass} to="/approvals">Open Approvals <ArrowUpRight className="size-3.5" /></Link>}</div>
              {!run.resumable && <p className="mt-2 text-caption text-warning-ink">This stored run cannot resume. Review the receipts before a new payment.</p>}
            </Callout>}

            {run.reply && (run.status === "completed"
              ? <div className="mt-5 rounded-xl border border-line bg-inset p-4">
                <div className="mb-2 flex items-center gap-2 text-caption font-semibold text-muted"><MessageSquare className="size-4 text-accent" />Ava's response</div>
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap text-fg">{run.reply}</p>
                <p className="mt-3 text-caption text-muted">Use the tool receipts below to verify any execution claim.</p>
              </div>
              : <Callout tone="warning" icon={Info} className="mt-5" title="Workflow update">
                <p className="text-sm leading-relaxed break-words whitespace-pre-wrap text-fg">{run.reply}</p>
              </Callout>)}
            {highlights.length > 0 && <div className="mt-5 space-y-3"><h3 className="flex items-center gap-2 text-sm font-semibold text-fg"><BadgeCheck className="size-4 text-good-ink" />Verified results</h3>
              <div className="grid gap-3 sm:grid-cols-2">{highlights.map((event, index) => <ReceiptHighlight key={`${run.id}-${index}`} event={event} />)}</div>
            </div>}

            <div className="mt-6 flex items-center justify-between gap-2"><h3 className="text-sm font-semibold text-fg">Recorded steps</h3><span className="text-caption text-muted">{run.events.length} events</span></div>
            {run.events.length > 0 && <ol className="mt-4" aria-label="Recorded workflow steps">{run.events.map((event, index) => <WorkflowEvent key={`${run.id}-${index}`} event={event} index={index} last={index === run.events.length - 1} />)}</ol>}
            {run.status === "running" && <div role="status" className="mt-4 flex items-center gap-2 rounded-lg bg-inset p-3 text-caption text-muted"><Spinner />Waiting for the next recorded step…</div>}
            {run.status !== "running" && run.events.length === 0 && <p className="mt-3 text-sm text-muted">No model or tool steps were recorded for this run.</p>}
            <div className="mt-5 flex flex-wrap items-center gap-3">
              {customer && run.subject === persona?.username && OPEN_BANK_STATUSES.includes(run.status) && <Button icon={X} variant="ghost" loading={proceed.isPending} onClick={() => proceed.mutate("cancel")}>Cancel run</Button>}
              {!customer && run.root_id && <Link className={linkClass} to={`/lineage/${run.root_id}`}>Open lineage <ArrowUpRight className="size-3.5" /></Link>}
              {!customer && <Link className={linkClass} to="/usage">Usage &amp; cost <ArrowUpRight className="size-3.5" /></Link>}
            </div>
            <RunGovernanceProof run={run} />
            <div className="mt-5 flex items-start gap-2 border-t border-line pt-4 text-caption leading-relaxed text-muted"><LockKeyhole className="mt-0.5 size-3.5 shrink-0" />
              <p>Model prose is not evidence of execution. Successful actions have verified receipts. No automatic write retries. History persists in the configured database; pending tasks cannot resume after a server restart.</p></div>
          </div>}
      </Card>
    </div>
  </>;
}
