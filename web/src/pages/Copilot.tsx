import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot } from "lucide-react";
import { api } from "../lib/api";
import { useSession } from "../lib/session";
import { Button, Callout, Card, Drawer, EmptyState, ErrorState, Field, JsonBlock, PageHeader, Skeleton, SkeletonRows, StatusPill, Textarea, cx, focusRing } from "../components/ui";

type Evidence = { ref: string; kind: string; id: string; href: string; facts: Record<string, unknown> };
type Run = {
  id: string; subject: string; question: string; status: string; root_id?: string; error?: string;
  cleanup_warning?: string; note?: string; mandate_completed?: boolean;
  answer?: { statements: { text: string; citations: string[] }[]; unknowns: string[] };
  sources?: Evidence[]; queries?: unknown[];
  model_calls?: { usage: { prompt_tokens?: number; completion_tokens?: number }; metadata: Record<string, string> }[];
};
type Status = {
  ready: boolean; error?: string; agent_id: string; deployment: string;
  budget: { remaining_estimate_eur: number; outstanding_holds: number; note: string };
};

const PRESETS = ["Why was Ava blocked in the last 24 hours?", "Which agents acted for jan.devries in the last week?", "What alerts were raised in the last 24 hours?"];

function Source({ source }: { source: Evidence }) {
  return <details className="rounded-lg border border-line bg-inset p-3" id={`source-${source.ref}`}>
    <summary className={cx("cursor-pointer rounded break-all text-sm font-medium text-accent", focusRing)}>{source.ref}</summary>
    <div className="mt-3 space-y-2">
      <JsonBlock value={source.facts} />
      <Link className={cx("inline-block rounded text-sm text-accent hover:underline", focusRing)} to={source.href}>Open source in console →</Link>
      <p className="text-caption text-muted">Redacted source excerpt. Raw prompts, arguments and detection payloads are excluded.</p>
    </div>
  </details>;
}

function Content({ username }: { username: string }) {
  const queryClient = useQueryClient();
  const [question, setQuestion] = useState(PRESETS[0]);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Run | null>(null);
  const [params] = useSearchParams();
  const ref = params.get("evidence") ?? "";
  const status = useQuery({ queryKey: ["copilot-status", username], queryFn: () => api<Status>("/demo/api/copilot/status") });
  const history = useQuery({ queryKey: ["copilot-history", username], queryFn: () => api<Run[]>("/demo/api/copilot/runs"),
    refetchInterval: query => busy || query.state.data?.some(run => run.status === "running") ? 2000 : false });
  const evidence = useQuery({ queryKey: ["copilot-source", username, ref], enabled: /^[a-z]+:[A-Za-z0-9_-]{1,64}$/.test(ref),
    queryFn: () => api<Evidence>(`/demo/api/copilot/evidence/${ref.replace(":", "/")}`) });
  const run = selected ? history.data?.find(r => r.id === selected.id) ?? selected : history.data?.[0];

  async function ask() {
    if (busy || !consent || !question.trim()) return;
    setBusy(true); setError(""); setSelected(null);
    const requestId = crypto.randomUUID();
    try {
      // Disable automatic authentication/request replay for a paid POST. The server also deduplicates this UUID.
      const result = await api<Run>("/demo/api/copilot/ask", { method: "POST", body: {
        request_id: requestId, question: question.trim(), confirm_synthetic_external_call: true,
      } }, true);
      setSelected(result);
    } catch (err) {
      setError(`${err instanceof Error ? err.message : "Request failed."} No automatic retry. Check recent investigations before submitting again.`);
    } finally {
      setBusy(false);
      void queryClient.invalidateQueries({ queryKey: ["copilot-history", username] });
      void queryClient.invalidateQueries({ queryKey: ["copilot-status", username] });
    }
  }

  return <div className="space-y-6">
    <Card title="Read-only investigation · real Azure requests">
      <div className="space-y-3 p-5">
        <p className="text-sm text-muted">Ask about recorded decisions, alerts, traces, Mandates, policies, approvals and usage. This is not the Bank Assistant and cannot transfer money, change policy or suspend agents.</p>
        <p className="text-sm text-muted">Synthetic demo records only. Azure processing uses the configured deployment and geography. Do not enter real customer data or secrets.</p>
        {status.isLoading && <Skeleton className="h-4 w-full max-w-lg" />}
        {status.data && <p className="text-caption text-muted">Deployment: {status.data.deployment || "not configured"} · <Link className={cx("rounded text-accent hover:underline", focusRing)} to={`/agents/${status.data.agent_id}`}>{status.data.agent_id}</Link> · Remaining estimate €{status.data.budget.remaining_estimate_eur.toFixed(4)} · {status.data.budget.outstanding_holds} uncertain/in-flight holds. Estimates are not Azure invoices.</p>}
        {status.isError && !status.data && <Callout tone="critical" title="Couldn't load the runtime status" action={<Button size="sm" onClick={() => void status.refetch()}>Try again</Button>}>{status.error.message}</Callout>}
        {status.data?.error && <div role="alert"><Callout tone="warning" title="Copilot isn't ready">{status.data.error}</Callout></div>}
        <Field label="Investigation question"><Textarea id="investigation-question" value={question} maxLength={1500} onChange={e => setQuestion(e.target.value)} /></Field>
        <div className="flex flex-wrap gap-2" role="group" aria-label="Example questions">
          {PRESETS.map(q =>
            <button key={q} type="button" disabled={busy} className={cx("rounded-lg border border-line-strong bg-card px-2.5 py-1 text-left text-caption text-muted transition-colors hover:bg-hover hover:text-fg disabled:pointer-events-none disabled:opacity-45", focusRing)} onClick={() => setQuestion(q)}>{q}</button>)}
        </div>
        <label className="flex cursor-pointer items-start gap-2.5 text-sm text-fg"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} className={cx("mt-0.5 size-4 shrink-0 accent-accent", focusRing)} />I am using synthetic data and authorize paid Azure inference for this investigation.</label>
        <Button variant="primary" icon={Bot} loading={busy} disabled={!consent || !status.data?.ready || question.trim().length < 5} onClick={() => void ask()}>Investigate</Button>
        {busy && <p role="status" className="text-caption text-muted">Retrieving evidence through Aegis. Up to three read calls and one cited answer; no automatic retries.</p>}
        {error && <Callout tone="critical" title="The investigation could not be completed">{error}</Callout>}
      </div>
    </Card>
    {ref && evidence.isLoading && <Card title="Referenced source"><div className="p-5" role="status" aria-label="Loading source"><Skeleton className="h-16 w-full" /></div></Card>}
    {evidence.data && <Card title="Referenced source"><div className="p-5"><Source source={evidence.data} /></div></Card>}
    {ref && evidence.isError && <Callout tone="critical" title="Could not load this source" action={<Button size="sm" onClick={() => void evidence.refetch()}>Try again</Button>}>{evidence.error.message}</Callout>}
    {run && <Card title={<span className="flex flex-wrap items-center gap-2"><StatusPill status={run.status} /><span className="font-mono text-xs font-normal text-muted">{run.id.slice(0, 8)}</span></span>}>
      <div className="space-y-4 p-5">
        <p className="text-sm font-medium text-fg">{run.question}</p>
        {run.error && <div role="alert"><Callout tone="warning">{run.error}</Callout></div>}
        {run.cleanup_warning && <div role="alert"><Callout tone="warning">{run.cleanup_warning}</Callout></div>}
        {run.answer?.statements.map((statement, i) => <div key={i} className="space-y-2">
          <p className="text-sm leading-relaxed whitespace-pre-wrap">{statement.text}</p>
          <div className="flex flex-wrap gap-2">{statement.citations.map(citation => <a key={citation} href={`#source-${citation}`} className={cx("rounded border border-line px-2 py-1 font-mono text-xs text-accent hover:bg-hover", focusRing)}>{citation}</a>)}</div>
        </div>)}
        {!!run.answer?.unknowns.length && <Callout tone="warning" title="Unknown or incomplete evidence">{run.answer.unknowns.map((item, i) => <p key={i} className="mb-1 last:mb-0">{item}</p>)}</Callout>}
        {run.sources?.map(source => <Source key={source.ref} source={source} />)}
        {!!run.model_calls?.length && <p className="text-caption text-muted">{run.model_calls.length} Azure calls · {run.model_calls.reduce((sum, call) => sum + (call.usage.prompt_tokens ?? 0) + (call.usage.completion_tokens ?? 0), 0)} tokens · estimated €{run.model_calls.reduce((sum, call) => sum + Number(call.metadata["x-aegis-llm-estimated-cost-eur"] ?? 0), 0).toFixed(6)}</p>}
        {run.root_id && <Link className={cx("inline-block rounded text-sm text-accent hover:underline", focusRing)} to={`/lineage/${run.root_id}`}>Copilot's own governed activity →</Link>}
        {!!run.queries?.length && <details><summary className={cx("cursor-pointer rounded text-caption text-muted", focusRing)}>Queries and coverage limits</summary><div className="mt-2"><JsonBlock value={run.queries} /></div></details>}
        <p className="text-caption text-muted">{run.note ?? "No accepted answer yet."} History is stored in the configured database. Interrupted investigations are not resumed.</p>
      </div>
    </Card>}
    <Card title="Your recent investigations" className="overflow-hidden">
      {history.isLoading ? <SkeletonRows rows={3} cols={2} />
        : history.isError && !history.data ? <ErrorState title="Couldn't load your investigations" error={history.error} onRetry={() => void history.refetch()} />
        : !history.data?.length ? <EmptyState icon={Bot} title="No investigations yet">Ask a question above to start one.</EmptyState>
        : <ul className="space-y-2 p-3">
          {history.data.map(item => <li key={item.id}><button type="button" className={cx("block w-full rounded-lg bg-inset p-3 text-left transition-colors hover:bg-hover", focusRing)} aria-pressed={run?.id === item.id} onClick={() => setSelected(item)}>
            <div className="flex flex-wrap items-center gap-2"><StatusPill status={item.status} /><span className="font-mono text-caption text-muted">{item.id.slice(0, 8)}</span></div><div className="mt-1.5 truncate text-sm text-fg">{item.question}</div>
          </button></li>)}
        </ul>}
    </Card>
  </div>;
}

export function CopilotPanel() {
  const { persona, can } = useSession();
  if (!persona || !can("soc-analyst", "auditor")) return <Callout tone="info">Investigation requires a SOC analyst or auditor. In development, choose Mark Jansen or Eva Visser.</Callout>;
  // Remount on persona changes: never leave the previous investigator's answer in a new user's view.
  return <Content key={persona.username} username={persona.username} />;
}

export function Copilot() {
  return <><PageHeader title="Investigation copilot" subtitle="Evidence-grounded explanations of recorded agent activity" /><CopilotPanel /></>;
}

export function CopilotLauncher() {
  const [open, setOpen] = useState(false);
  return <>
    <button aria-label="Open investigation Copilot" onClick={() => setOpen(true)} className={cx("fixed right-5 bottom-5 z-30 flex h-11 items-center gap-2 rounded-full border border-line-strong bg-card pr-4 pl-3 text-sm font-medium text-fg shadow-overlay transition-colors hover:bg-hover", focusRing)}><span className="grid size-7 place-items-center rounded-full bg-fg text-page"><Bot className="size-4" /></span><span className="hidden sm:inline">Copilot</span></button>
    <Drawer open={open} onClose={() => setOpen(false)} title="Investigation Copilot">
      <div className="mb-4"><Link className={cx("rounded text-sm font-medium text-accent hover:underline", focusRing)} to="/copilot" onClick={() => setOpen(false)}>Open full investigation screen →</Link></div>
      {open && <CopilotPanel />}
    </Drawer>
  </>;
}
