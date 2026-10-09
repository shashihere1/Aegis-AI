import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowRight, ArrowUpRight, BadgeCheck, Bot, CheckCircle2, ChevronDown, ChevronRight,
  CircleHelp, Clock3, FileCheck2, Globe2, History, Info, LockKeyhole, MapPin,
  MessageSquare, ReceiptText, Send, ShieldCheck, Sparkles, TriangleAlert, Wallet, X, type LucideIcon,
} from "lucide-react";
import { api, post } from "../lib/api";
import {
  BANK_TASKS, OPEN_BANK_STATUSES, bankReceipt, bankRunStats, bankStatusLabel, eventEstimate, record,
  type BankEvent, type BankMode, type BankRun, type BankStatus,
} from "../lib/bank-assistant";
import { euro, titleCase } from "../lib/format";
import { useSession } from "../lib/session";
import { Button, Card, cx, EmptyState, JsonBlock, PageHeader, Pill, Spinner } from "../components/ui";

const TASK_ICONS: Record<BankMode, LucideIcon> = {
  inquiry: Wallet, documents: FileCheck2, address: MapPin, transfer: ArrowUpRight,
};

function RunStatus({ status }: { status: string }) {
  if (status === "running") return <Pill tone="info" icon={Clock3}>{bankStatusLabel(status)}</Pill>;
  if (status === "completed") return <Pill tone="good" icon={CheckCircle2}>{bankStatusLabel(status)}</Pill>;
  if (["confirmation_required", "approval_required"].includes(status)) return <Pill tone="warning" icon={CircleHelp}>{bankStatusLabel(status)}</Pill>;
  if (["failed", "denied", "blocked"].includes(status)) return <Pill tone="critical" icon={TriangleAlert}>{bankStatusLabel(status)}</Pill>;
  return <Pill icon={X}>{bankStatusLabel(status)}</Pill>;
}

function DataDetails({ title, value }: { title: string; value: unknown }) {
  return <details className="group mt-3 rounded-lg border border-line bg-inset">
    <summary className="flex cursor-pointer list-none items-center gap-2 rounded-lg px-3 py-2.5 text-xs font-medium text-muted outline-none focus-visible:ring-2 focus-visible:ring-accent">
      <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" />{title}
    </summary>
    <div className="px-3 pb-3"><JsonBlock value={value} /></div>
  </details>;
}

function ReceiptHighlight({ event }: { event: BankEvent }) {
  const receipt = bankReceipt(event);
  if (!receipt) return null;
  const Icon = TASK_ICONS[event.label === "get_balance" ? "inquiry" : event.label === "verify_document" ? "documents" : event.label === "update_address" ? "address" : "transfer"];
  return <div className="min-w-0 rounded-xl border border-accent/30 bg-accent-soft p-4">
    <div className="flex items-center gap-2 text-xs font-medium text-accent"><Icon className="size-4" />{receipt.title}</div>
    <div className={cx("mt-2 break-words font-semibold tracking-tight", receipt.money ? "text-2xl tabular" : "text-base")}>{receipt.money ? euro(receipt.value as number) : receipt.value}</div>
    {receipt.detail && <div className="mt-1 break-all font-mono text-xs text-muted">{receipt.detail}</div>}
    <div className="mt-3 flex items-center gap-1.5 text-[11px] text-accent"><BadgeCheck className="size-3.5" />Verified tool result · synthetic bank</div>
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
      {!last && <span className="absolute top-8 bottom-[-4px] w-px bg-line" />}
      <span className={cx("relative grid size-8 place-items-center rounded-full border",
        verified ? "border-accent/30 bg-accent-soft text-accent" : model ? "border-series/30 bg-series/10 text-info-ink"
          : caution ? "border-warning/30 bg-warning/10 text-warning-ink" : "border-line-strong bg-inset text-muted")}><Icon className="size-4" /></span>
    </div>
    <div className="min-w-0 flex-1 rounded-xl border border-line p-3.5">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1"><span className="font-mono text-[10px] text-faint">{String(index + 1).padStart(2, "0")}</span>
        <h3 className="min-w-0 break-words text-sm font-medium">{label}</h3>{verified && <span className="text-[11px] font-medium text-accent">Verified receipt</span>}</div>
      {model && <p className="mt-1 text-xs text-muted">Model output guides the workflow; it is not proof of a banking action.</p>}
      {event.kind === "proposal" && <p className="mt-1 text-xs text-muted">Proposed tool arguments, not an execution receipt.</p>}
      {event.runtime && <p className="mt-1 text-xs text-muted">Executed through <span className="text-accent">{event.runtime}</span></p>}
      {event.usage && <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted tabular">
        <span>{event.usage.prompt_tokens.toLocaleString()} input / {event.usage.completion_tokens.toLocaleString()} output tokens</span>
        <span>{estimate === null ? "Estimate unavailable" : `${euro(estimate, 6)} estimated`}</span></div>}
      {event.arguments !== undefined && <DataDetails title="Inspect proposed arguments" value={event.arguments} />}
      {event.result !== undefined && <DataDetails title={verified ? "Inspect full receipt" : "Inspect result data"} value={event.result} />}
      {event.metadata && Object.keys(event.metadata).length > 0 && <DataDetails title="Request and trace details" value={event.metadata} />}
      {event.approval_id && <p className="mt-2 break-all font-mono text-xs text-warning-ink">Approval: {event.approval_id}</p>}
    </div>
  </li>;
}

function ProposedArguments({ value }: { value: unknown }) {
  const data = record(value);
  if (!data || !Object.keys(data).length) return <JsonBlock value={value ?? {}} />;
  return <dl className="my-3 divide-y divide-line rounded-lg border border-line bg-inset px-3">
    {Object.entries(data).map(([key, item]) => <div key={key} className="grid gap-1 py-2.5 sm:grid-cols-[110px_minmax(0,1fr)] sm:gap-3">
      <dt className="text-xs text-muted">{titleCase(key)}</dt><dd className="min-w-0 break-words text-sm font-medium">
        {key === "amount" && typeof item === "number" ? euro(item) : typeof item === "string" ? item : typeof item === "boolean" ? (item ? "Yes" : "No") : JSON.stringify(item)}</dd>
    </div>)}
  </dl>;
}

function RuntimeOverview({ status, loading }: { status?: BankStatus; loading: boolean }) {
  if (!status) return <div className="flex items-center gap-2 border-t border-line px-5 py-4 text-sm text-muted">
    {loading ? <><Spinner />Checking runtime configuration…</> : <><TriangleAlert className="size-4" />Runtime status unavailable</>}</div>;
  const { policy, budget } = status;
  const remaining = policy.daily_budget_eur > 0 ? Math.max(0, Math.min(1, budget.remaining_estimate_eur / policy.daily_budget_eur)) : 0;
  return <>
    <div className="grid gap-4 border-t border-line bg-inset/40 px-5 py-4 sm:grid-cols-2 2xl:grid-cols-4">
      <div className="min-w-0"><div className="flex items-center gap-1.5 text-[11px] font-medium text-muted"><Bot className="size-3.5" />Azure deployment</div><div className="mt-1 break-all text-sm font-semibold">{policy.deployment || "Not configured"}</div></div>
      <div><div className="flex items-center gap-1.5 text-[11px] font-medium text-muted"><Globe2 className="size-3.5" />Processing scope</div><div className="mt-1 text-sm font-semibold">{titleCase(policy.processing_scope)} <span className="font-normal text-muted">/ permitted: {policy.allowed_processing_scope}</span></div></div>
      <div><div className="flex items-center gap-1.5 text-[11px] font-medium text-muted"><LockKeyhole className="size-3.5" />Data ceiling</div><div className="mt-1 text-sm font-semibold">{titleCase(policy.max_data_class)}</div></div>
      <div><div className="flex items-center justify-between gap-2 text-[11px] font-medium text-muted"><span>Daily budget remaining</span><span>Estimate</span></div>
        <div className="mt-1 text-sm font-semibold tabular">{euro(budget.remaining_estimate_eur, 4)} <span className="font-normal text-muted">/ {euro(policy.daily_budget_eur)}</span></div>
        <div className="mt-2 h-1 rounded-full bg-line-strong" role="meter" aria-label="Estimated daily budget remaining" aria-valuemin={0} aria-valuemax={Math.max(0, policy.daily_budget_eur)}
          aria-valuenow={Math.max(0, Math.min(policy.daily_budget_eur, budget.remaining_estimate_eur))} aria-valuetext={`${euro(budget.remaining_estimate_eur, 4)} remaining per agent/day UTC`}>
          <div className={cx("h-1 rounded-full", remaining < 0.2 ? "bg-warning" : "bg-accent")} style={{ width: `${remaining * 100}%` }} /></div>
      </div>
    </div>
    <details className="group border-t border-line px-5 py-3 text-xs">
      <summary className="flex cursor-pointer list-none items-center gap-2 text-muted outline-none focus-visible:ring-2 focus-visible:ring-accent"><Info className="size-3.5" />Runtime, budget and policy details<ChevronDown className="ml-auto size-3.5 transition-transform group-open:rotate-180" /></summary>
      <div className="mt-3 flex flex-wrap gap-2">{Object.entries(status.frameworks).map(([name, version]) => <Pill key={name} tone={version ? "neutral" : "warning"}>{name}: {version ?? "missing"}</Pill>)}</div>
      <p className="mt-3 leading-relaxed text-muted">Per agent/day UTC · {budget.day_utc} · {budget.outstanding_holds} uncertain/in-flight budget holds. Estimates are not Azure invoices. OPA is not used for model controls. Configuration readiness does not prove Azure connectivity.</p>
    </details>
    {!status.ready && <div className="flex items-start gap-2 border-t border-warning/25 bg-warning/8 px-5 py-3 text-sm text-warning-ink"><TriangleAlert className="mt-0.5 size-4 shrink-0" />
      <div>{status.policy_error || "Configure Azure and install requirements-agents.txt before starting a task."}<p className="mt-1 text-xs">See docs/live-agents.md. Processing geography must match the actual deployment, not just the resource region.</p></div></div>}
  </>;
}

function WorkflowEmptyState() {
  return <div className="px-5 py-8 sm:py-12">
    <div className="mx-auto grid size-16 place-items-center rounded-2xl border border-accent/25 bg-accent-soft text-accent"><MessageSquare className="size-7" /></div>
    <h3 className="mt-5 text-center text-lg font-semibold">Your task, with a clear trail</h3>
    <p className="mx-auto mt-2 max-w-sm text-center text-sm leading-relaxed text-muted">Ask Ava a question or select a previous run. The workflow will show what was proposed and what actually executed.</p>
    <div className="mt-8 space-y-3">{[
      { icon: Sparkles, title: "Ava proposes", description: "Azure chooses a response or a tool for your purpose." },
      { icon: ShieldCheck, title: "Aegis authorizes", description: "Permissions and Mandate limits govern tool execution." },
      { icon: ReceiptText, title: "Tools return receipts", description: "Executed actions have results you can inspect." },
    ].map((step, i) => <div key={step.title} className="flex items-start gap-3 rounded-xl border border-line bg-inset/60 p-3.5">
      <step.icon className="mt-0.5 size-4 shrink-0 text-accent" /><div><div className="text-sm font-medium"><span className="mr-2 text-faint">0{i + 1}</span>{step.title}</div><p className="mt-1 text-xs leading-relaxed text-muted">{step.description}</p></div></div>)}</div>
    <p className="mt-6 text-center text-xs text-faint">No model request is made until you submit a task.</p>
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
  const status = useQuery({ queryKey: ["live-agent-status", persona?.username],
    queryFn: () => api<BankStatus>("/demo/api/agent/status"), refetchInterval: 4000 });
  const history = useQuery({ queryKey: ["live-agent-history", persona?.username],
    queryFn: () => api<BankRun[]>("/demo/api/agent/runs"), refetchInterval: 2000 });
  const selected = useQuery({ queryKey: ["live-agent-run", persona?.username, runId],
    queryFn: () => api<BankRun>(`/demo/api/agent/runs/${runId}`), enabled: !!runId, refetchInterval: 1000 });
  const run = selected.data;
  const openRun = history.data?.find(item => item.subject === persona?.username && OPEN_BANK_STATUSES.includes(item.status));
  useEffect(() => { setRunId(null); setConsent(false); setAllHistory(false); setRequestId(crypto.randomUUID()); }, [persona?.username]);
  useEffect(() => { if (!runId && openRun) setRunId(openRun.id); }, [runId, openRun]);
  const start = useMutation({ retry: false, mutationFn: () => post<BankRun>("/demo/api/agent/runs", {
    request_id: requestId, mode, message, confirm_synthetic_external_call: true,
  }), onSuccess: item => { setRunId(item.id); setConsent(false); setRequestId(crypto.randomUUID()); queryClient.invalidateQueries(); } });
  const proceed = useMutation({ retry: false, mutationFn: (action: string) =>
    post<BankRun>(`/demo/api/agent/runs/${runId}/continue`, { action }),
    onSuccess: () => queryClient.invalidateQueries() });
  const error = start.error ?? proceed.error ?? selected.error ?? history.error ?? status.error;
  const busy = !!openRun || start.isPending;
  const canStart = customer && consent && !!status.data?.ready && !busy && !history.isPending && !history.isError && message.trim().length >= 3;
  const canContinue = customer && run?.subject === persona?.username && run.resumable;
  const stats = run ? bankRunStats(run.events) : null;
  const highlights = run?.events.filter(event => bankReceipt(event) !== null) ?? [];
  const recent = history.data ?? [];
  const disabledReason = !customer ? "Only Jan's synthetic customer account can start a task. Staff can inspect runs."
    : history.isPending ? "Checking for an existing task…"
    : history.isError ? "Task history is unavailable. Wait for it to reconnect before starting a task."
    : openRun ? "Finish or cancel your open task before starting another."
    : !status.data?.ready ? "The runtime must be ready before you can start."
    : !consent ? "Confirm synthetic data and paid Azure inference to continue."
    : message.trim().length < 3 ? "Enter a request of at least 3 characters." : null;

  return <>
    <PageHeader icon={MessageSquare} title="Bank Assistant" subtitle="Ava plans the task. Aegis governs execution. You stay in control."
      actions={status.isPending ? <Pill icon={Clock3}>Checking configuration</Pill> : status.data?.ready
        ? <Pill tone="good" icon={CheckCircle2}>Runtime configured</Pill> : <Pill tone="warning" icon={TriangleAlert}>Setup needed</Pill>} />

    <Card className="mb-6 overflow-hidden">
      <div className="flex flex-wrap items-start gap-4 p-5">
        <div className="grid size-12 shrink-0 place-items-center rounded-2xl border border-accent/25 bg-accent-soft"><Bot className="size-6 text-accent" /></div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5"><h2 className="text-lg font-semibold">{customer ? `Hi ${persona?.name.split(" ")[0] || "Jan"}, I'm Ava` : "Meet Ava, your banking assistant"}</h2>
            <Pill tone="accent">Synthetic bank</Pill><Pill tone="warning">Paid Azure requests</Pill></div>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted">Check an account, verify a document, or review a change. Only use synthetic demo data; no real money moves.</p>
          <p className="mt-1 text-xs leading-relaxed text-faint">Ava: LangGraph + Azure tool calling · KYC: Microsoft Agent Framework · Banking data: local fixtures.
            {source === "dev" ? " Sign-in uses passwordless development personas, not enterprise IAM." : source === "sso" ? " You are signed in with SSO." : ""}</p>
        </div>
        {!customer && config?.dev_login && personas.some(item => item.username === "jan.devries" && item.status === "active")
          && <Button icon={ArrowRight} onClick={() => switchTo("jan.devries")}>Act as Jan</Button>}
      </div>
      <RuntimeOverview status={status.data} loading={status.isPending} />
    </Card>

    {error && <div role="alert" className="mb-5 flex items-start gap-3 rounded-xl border border-critical/30 bg-critical/8 p-4">
      <TriangleAlert className="mt-0.5 size-4 shrink-0 text-critical-ink" />
      <div className="min-w-0"><div className="text-sm font-semibold text-critical-ink">The request could not be completed</div>
        <p className="mt-1 break-words text-sm text-muted">{error.message}</p><p className="mt-2 text-xs text-muted">No automatic action retry. Review the run and any receipts before submitting a new write.</p></div>
    </div>}

    <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.15fr)]">
      <div className="min-w-0 space-y-5">
        <Card title="Start a customer task" action={<span className="text-xs text-muted">01 · Request</span>}>
          <form className="p-5" onSubmit={event => { event.preventDefault(); if (canStart) start.mutate(); }}>
            <fieldset className="min-w-0" disabled={busy}>
              <legend className="text-sm font-medium">What would you like to do?</legend>
              <p className="mt-1 text-xs text-muted">Your purpose limits the Mandate and the available tools.</p>
              <div className="mt-3 grid grid-cols-1 gap-2 min-[440px]:grid-cols-2">
                {(Object.keys(BANK_TASKS) as BankMode[]).map(value => {
                  const task = BANK_TASKS[value];
                  const Icon = TASK_ICONS[value];
                  return <label key={value} className={cx("relative flex cursor-pointer items-start gap-2.5 rounded-xl border p-3 transition focus-within:ring-2 focus-within:ring-accent",
                    mode === value ? "border-accent/50 bg-accent-soft" : "border-line-strong bg-inset hover:border-accent/30 hover:bg-hover", busy && "cursor-not-allowed opacity-60")}>
                    <input className="sr-only" type="radio" name="bank-purpose" value={value} checked={mode === value}
                      onChange={() => { setMode(value); setMessage(task.example); setConsent(false); }} />
                    <Icon className={cx("mt-0.5 size-4 shrink-0", mode === value ? "text-accent" : "text-muted")} />
                    <span className="min-w-0 pr-3"><span className="block text-xs font-semibold">{task.label}</span><span className="mt-1 block text-[11px] leading-relaxed text-muted">{task.description}</span></span>
                    {mode === value && <CheckCircle2 className="absolute top-2 right-2 size-3 text-accent" />}
                  </label>;
                })}
              </div>
            </fieldset>
            <div className="mt-5 flex items-center justify-between gap-2"><label htmlFor="bank-request" className="text-sm font-medium">Your request</label>
              <button type="button" disabled={busy} onClick={() => setMessage(BANK_TASKS[mode].example)}
                className="rounded text-xs font-medium text-accent outline-none hover:underline focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-45">Use example</button></div>
            <textarea id="bank-request" rows={4} maxLength={1500} value={message} onChange={event => setMessage(event.target.value)} disabled={busy}
              aria-describedby="bank-request-hint" placeholder="Tell Ava what you need…"
              className="mt-2 min-h-28 w-full resize-y rounded-xl border border-line-strong bg-inset p-3 text-sm leading-relaxed outline-none placeholder:text-faint focus:border-accent focus:ring-2 focus:ring-accent/15 disabled:opacity-60" />
            <div id="bank-request-hint" className="mt-1 flex justify-between gap-2 text-[11px] text-muted"><span>Synthetic data only. Never paste real customer details.</span><span className="shrink-0 tabular">{message.length} / 1,500</span></div>
            <label className="my-4 flex cursor-pointer items-start gap-3 rounded-xl border border-line bg-inset/50 p-3.5 text-xs leading-relaxed focus-within:ring-2 focus-within:ring-accent">
              <input type="checkbox" checked={consent} disabled={busy || !customer} onChange={event => setConsent(event.target.checked)} className="mt-0.5 size-4 shrink-0 accent-accent" />
              <span>I am using synthetic data and authorize <span className="font-semibold text-fg">paid Azure inference</span> for this task.</span>
            </label>
            <Button type="submit" variant="primary" className="w-full" icon={Send} loading={start.isPending} disabled={!canStart}>Ask Ava</Button>
            {disabledReason && <p className="mt-2.5 text-xs leading-relaxed text-muted">{disabledReason}</p>}
            {openRun && openRun.id !== runId && <button type="button" className="mt-2 rounded text-xs font-medium text-accent focus-visible:ring-2 focus-visible:ring-accent" onClick={() => setRunId(openRun.id)}>View your open task <ArrowRight className="ml-1 inline size-3" /></button>}
          </form>
        </Card>

        <Card title={<span className="inline-flex items-center gap-2"><History className="size-4 text-muted" />Recent runs</span>} action={<span className="text-xs text-muted">{recent.length} recorded</span>}>
          {history.isPending ? <div className="flex items-center gap-2 p-5 text-sm text-muted"><Spinner />Loading run history…</div>
            : history.isError && !recent.length ? <div className="p-5 text-sm text-muted">Run history is temporarily unavailable.</div>
            : !recent.length ? <EmptyState icon={History} title="No tasks yet">Your live-agent history will appear here. Scripted Studio scenes are tracked separately.</EmptyState>
            : <div className="p-2">
              <div className={cx("space-y-1", allHistory && "max-h-80 overflow-y-auto")}>
                {(allHistory ? recent : recent.slice(0, 5)).map(item => {
                  const Icon = TASK_ICONS[item.mode] ?? MessageSquare;
                  return <button key={item.id} type="button" aria-pressed={runId === item.id}
                    onClick={() => { setRunId(item.id); start.reset(); proceed.reset(); }}
                    className={cx("flex w-full items-start gap-3 rounded-xl border px-3 py-3 text-left outline-none transition focus-visible:ring-2 focus-visible:ring-accent",
                      runId === item.id ? "border-accent/30 bg-accent-soft" : "border-transparent hover:bg-hover")}>
                    <Icon className={cx("mt-1 size-4 shrink-0", runId === item.id ? "text-accent" : "text-muted")} />
                    <span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><span className="text-sm font-medium">{BANK_TASKS[item.mode]?.label ?? item.mode}</span><RunStatus status={item.status} /></span>
                      <span className="mt-1 block truncate text-[11px] text-muted">{item.subject} <span className="mx-1">·</span><span className="font-mono">{item.id.slice(0, 8)}</span></span></span>
                    <ChevronRight className="mt-1 size-4 shrink-0 text-faint" />
                  </button>;
                })}
              </div>
              {recent.length > 5 && <button type="button" onClick={() => setAllHistory(value => !value)} className="mt-1 w-full rounded-lg py-2 text-xs font-medium text-accent outline-none hover:bg-hover focus-visible:ring-2 focus-visible:ring-accent">{allHistory ? "Show fewer runs" : `Show all ${recent.length} runs`}</button>}
            </div>}
        </Card>
      </div>

      <Card className="min-w-0 overflow-hidden" title={<span className="inline-flex items-center gap-2"><ReceiptText className="size-4 text-accent" />Live workflow & receipts</span>}
        action={run ? <span className="font-mono text-xs text-faint" title={run.id}>{run.id.slice(0, 8)}</span> : <span className="text-xs text-muted">02 · Results</span>}>
        {runId && selected.isPending ? <div className="flex items-center justify-center gap-2 p-12 text-sm text-muted"><Spinner />Loading the selected workflow…</div>
          : runId && selected.isError && !run ? <EmptyState icon={TriangleAlert} title="This workflow is unavailable">The run could not be loaded. Select another run or wait for the connection to recover.</EmptyState>
          : !run ? <WorkflowEmptyState /> : <div className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3"><RunStatus status={run.status} />
              <span className="text-xs text-muted">{BANK_TASKS[run.mode]?.label ?? run.mode}{!customer ? ` · ${run.subject}` : ""}</span></div>
            {stats && <div className="mt-4 grid grid-cols-3 gap-2 rounded-xl border border-line bg-inset p-3">
              <div><div className="text-[10px] text-muted">Tool receipts</div><div className="mt-1 text-sm font-semibold tabular">{stats.receipts}</div></div>
              <div><div className="text-[10px] text-muted">Model calls</div><div className="mt-1 text-sm font-semibold tabular">{stats.modelCalls}</div></div>
              <div><div className="text-[10px] text-muted">{stats.partialEstimate ? "Partial estimate" : "Task estimate"}</div><div className="mt-1 break-words text-sm font-semibold tabular">{stats.estimatedCost === null ? "—" : euro(stats.estimatedCost, 6)}</div></div>
            </div>}

            {run.status === "confirmation_required" && <div className="mt-5 rounded-xl border border-warning/40 bg-warning/5 p-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-warning-ink"><CircleHelp className="size-4" />Review before execution</div>
              <p className="mt-2 text-sm font-medium">{titleCase(run.pending.name || "Proposed action")}</p>
              <ProposedArguments value={run.pending.arguments} />
              <p className="mb-3 text-xs leading-relaxed text-muted">This proposed action has not executed. Confirmation authorizes these exact stored arguments, not a rewritten model request.</p>
              {canContinue && <Button icon={CheckCircle2} variant="primary" className="h-auto min-h-9 whitespace-normal py-2" loading={proceed.isPending} onClick={() => proceed.mutate("confirm")}>Confirm this synthetic action</Button>}
              {!run.resumable && <p className="text-xs text-warning-ink">This stored run cannot resume. Check receipts before starting a new task.</p>}
              {!customer && <p className="text-xs text-muted">Only the initiating customer can confirm this action.</p>}
            </div>}
            {run.status === "approval_required" && <div className="mt-5 rounded-xl border border-warning/40 bg-warning/5 p-4">
              <div className="flex items-center gap-2 text-sm font-semibold text-warning-ink"><ShieldCheck className="size-4" />Separate risk approval required</div>
              <p className="mt-2 text-xs leading-relaxed text-muted">Customer confirmation is not risk approval. A risk approver must review the matching request in Approvals. Then Jan can resume while the Mandate is still valid.</p>
              {run.pending.approval_id && <p className="mt-3 break-all font-mono text-xs text-warning-ink">{run.pending.approval_id}</p>}
              {source === "dev" && <p className="mt-2 text-xs text-muted">For the demo: switch to Sanne Bakker to approve, then return to Jan.</p>}
              <div className="mt-3 flex flex-wrap gap-3">{canContinue && <Button icon={ArrowRight} className="h-auto min-h-9 whitespace-normal py-2" loading={proceed.isPending} onClick={() => proceed.mutate("resume_approval")}>Resume after risk approval</Button>}
                {!customer && <Link className="inline-flex items-center gap-1 text-sm font-medium text-accent" to="/approvals">Open Approvals <ArrowUpRight className="size-3.5" /></Link>}</div>
              {!run.resumable && <p className="mt-2 text-xs text-warning-ink">This stored run cannot resume. Review the receipts before a new payment.</p>}
            </div>}

            {run.reply && <div className={cx("mt-5 rounded-xl border p-4", run.status === "completed" ? "border-line bg-inset/60" : "border-warning/25 bg-warning/5")}>
              <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-muted">{run.status === "completed" ? <MessageSquare className="size-4 text-accent" /> : <Info className="size-4 text-warning-ink" />}
                {run.status === "completed" ? "Ava's response" : "Workflow update"}</div>
              <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{run.reply}</p>
              {run.status === "completed" && <p className="mt-3 text-[11px] text-faint">Use the tool receipts below to verify any execution claim.</p>}
            </div>}
            {highlights.length > 0 && <div className="mt-5 space-y-3"><h3 className="flex items-center gap-2 text-xs font-semibold tracking-wide text-muted uppercase"><BadgeCheck className="size-3.5 text-accent" />Verified results</h3>
              <div className="grid gap-3 sm:grid-cols-2">{highlights.map((event, index) => <ReceiptHighlight key={`${run.id}-${index}`} event={event} />)}</div>
            </div>}

            <div className="mt-6 flex items-center justify-between gap-2"><h3 className="text-xs font-semibold tracking-wide text-muted uppercase">Recorded steps</h3><span className="text-xs text-faint">{run.events.length} events</span></div>
            {run.events.length > 0 && <ol className="mt-4" aria-label="Recorded workflow steps">{run.events.map((event, index) => <WorkflowEvent key={`${run.id}-${index}`} event={event} index={index} last={index === run.events.length - 1} />)}</ol>}
            {run.status === "running" && <div role="status" className="mt-4 flex items-center gap-2 rounded-lg bg-inset p-3 text-xs text-muted"><Spinner />Waiting for the next recorded step…</div>}
            {run.status !== "running" && run.events.length === 0 && <p className="mt-3 text-sm text-muted">No model or tool steps were recorded for this run.</p>}
            <div className="mt-5 flex flex-wrap items-center gap-3">
              {customer && run.subject === persona?.username && OPEN_BANK_STATUSES.includes(run.status) && <Button icon={X} variant="ghost" loading={proceed.isPending} onClick={() => proceed.mutate("cancel")}>Cancel run</Button>}
              {!customer && run.root_id && <Link className="inline-flex items-center gap-1 text-xs font-medium text-accent" to={`/lineage/${run.root_id}`}>Open lineage <ArrowUpRight className="size-3.5" /></Link>}
              {!customer && <Link className="inline-flex items-center gap-1 text-xs font-medium text-accent" to="/usage">Usage & cost <ArrowUpRight className="size-3.5" /></Link>}
            </div>
            <div className="mt-5 flex items-start gap-2 border-t border-line pt-4 text-[11px] leading-relaxed text-muted"><LockKeyhole className="mt-0.5 size-3.5 shrink-0" />
              <p>Model prose is not evidence of execution. Successful actions have verified receipts. No automatic write retries. History persists in the configured database; pending tasks cannot resume after a server restart.</p></div>
          </div>}
      </Card>
    </div>
  </>;
}
