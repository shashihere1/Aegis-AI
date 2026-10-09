import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, ShieldCheck, X } from "lucide-react";
import { api } from "../lib/api";
import { useSession } from "../lib/session";
import { Button, Card, Drawer, JsonBlock, PageHeader } from "../components/ui";

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

function Source({ source }: { source: Evidence }) {
  return <details className="rounded-lg border border-line bg-inset p-3" id={`source-${source.ref}`}>
    <summary className="cursor-pointer break-all text-sm font-medium text-accent">{source.ref}</summary>
    <div className="mt-3 space-y-2">
      <JsonBlock value={source.facts} />
      <Link className="text-sm text-accent hover:underline" to={source.href}>Open source in console →</Link>
      <p className="text-xs text-faint">Redacted source excerpt. Raw prompts, arguments and detection payloads are excluded.</p>
    </div>
  </details>;
}

function Content({ username }: { username: string }) {
  const queryClient = useQueryClient();
  const [question, setQuestion] = useState("Why was Ava blocked in the last 24 hours?");
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

  return <div className="space-y-5">
    <Card className="space-y-3 p-5">
      <div className="flex items-center gap-2 font-semibold"><ShieldCheck className="size-4 text-accent" />Read-only investigation · real Azure requests</div>
      <p className="text-sm text-muted">Ask about recorded decisions, alerts, traces, Mandates, policies, approvals and usage. This is not the Bank Assistant and cannot transfer money, change policy or suspend agents.</p>
      <p className="text-sm text-muted">Synthetic demo records only. Azure processing uses the configured deployment and geography. Do not enter real customer data or secrets.</p>
      {status.data && <p className="text-xs text-muted">Deployment: {status.data.deployment || "not configured"} · <Link className="text-accent" to={`/agents/${status.data.agent_id}`}>{status.data.agent_id}</Link> · Remaining estimate €{status.data.budget.remaining_estimate_eur.toFixed(4)} · {status.data.budget.outstanding_holds} uncertain/in-flight holds. Estimates are not Azure invoices.</p>}
      {(status.error || status.data?.error) && <p role="alert" className="text-sm text-warning-ink">{status.data?.error ?? String(status.error)}</p>}
      <label className="block text-sm font-medium" htmlFor="investigation-question">Investigation question</label>
      <textarea id="investigation-question" value={question} maxLength={1500} onChange={e => setQuestion(e.target.value)}
        className="min-h-28 w-full rounded-xl border border-line-strong bg-inset p-3 text-sm" />
      <div className="flex flex-wrap gap-2">
        {["Why was Ava blocked in the last 24 hours?", "Which agents acted for jan.devries in the last week?", "What alerts were raised in the last 24 hours?"].map(q =>
          <button key={q} disabled={busy} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-fg" onClick={() => setQuestion(q)}>{q}</button>)}
      </div>
      <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} className="mt-1" />I am using synthetic data and authorize paid Azure inference for this investigation.</label>
      <Button variant="primary" icon={Bot} loading={busy} disabled={!consent || !status.data?.ready || question.trim().length < 5} onClick={() => void ask()}>Investigate</Button>
      {busy && <p className="text-xs text-muted">Retrieving evidence through Aegis. Up to three read calls and one cited answer; no automatic retries.</p>}
      {error && <p role="alert" className="text-sm text-critical-ink">{error}</p>}
    </Card>
    {evidence.data && <Card className="space-y-3 p-5" title="Referenced source"><Source source={evidence.data} /></Card>}
    {ref && evidence.error && <p role="alert" className="text-sm text-critical-ink">Could not load this source: {String(evidence.error)}</p>}
    {run && <Card className="space-y-4 p-5" title={`${run.status} · ${run.id.slice(0, 8)}`}>
      <p className="text-sm font-medium">{run.question}</p>
      {run.error && <p role="alert" className="text-sm text-warning-ink">{run.error}</p>}
      {run.cleanup_warning && <p role="alert" className="text-sm text-warning-ink">{run.cleanup_warning}</p>}
      {run.answer?.statements.map((statement, i) => <div key={i} className="space-y-2">
        <p className="whitespace-pre-wrap text-sm leading-relaxed">{statement.text}</p>
        <div className="flex flex-wrap gap-2">{statement.citations.map(citation => <a key={citation} href={`#source-${citation}`} className="rounded border border-line px-2 py-1 font-mono text-xs text-accent">{citation}</a>)}</div>
      </div>)}
      {!!run.answer?.unknowns.length && <div className="rounded-xl border border-line p-3"><div className="mb-2 text-xs font-semibold text-warning-ink">Unknown or incomplete evidence</div>{run.answer.unknowns.map((item, i) => <p key={i} className="mb-1 text-sm text-muted">{item}</p>)}</div>}
      {run.sources?.map(source => <Source key={source.ref} source={source} />)}
      {!!run.model_calls?.length && <p className="text-xs text-muted">{run.model_calls.length} Azure calls · {run.model_calls.reduce((sum, call) => sum + (call.usage.prompt_tokens ?? 0) + (call.usage.completion_tokens ?? 0), 0)} tokens · estimated €{run.model_calls.reduce((sum, call) => sum + Number(call.metadata["x-aegis-llm-estimated-cost-eur"] ?? 0), 0).toFixed(6)}</p>}
      {run.root_id && <Link className="text-sm text-accent" to={`/lineage/${run.root_id}`}>Copilot's own governed activity →</Link>}
      {!!run.queries?.length && <details><summary className="cursor-pointer text-xs text-muted">Queries and coverage limits</summary><JsonBlock value={run.queries} /></details>}
      <p className="text-xs text-faint">{run.note ?? "No accepted answer yet."} History is stored in the configured database. Interrupted investigations are not resumed.</p>
    </Card>}
    <Card className="space-y-2 p-5" title="Your recent investigations">
      {history.error && <p role="alert" className="text-sm text-critical-ink">{String(history.error)}</p>}
      {!history.data?.length && <p className="text-sm text-muted">No investigations yet.</p>}
      {history.data?.map(item => <button key={item.id} className="block w-full rounded-lg bg-inset p-3 text-left hover:bg-hover" onClick={() => setSelected(item)}>
        <div className="text-xs text-muted">{item.status} · {item.id.slice(0, 8)}</div><div className="truncate text-sm">{item.question}</div>
      </button>)}
    </Card>
  </div>;
}

export function CopilotPanel() {
  const { persona, can } = useSession();
  if (!persona || !can("soc-analyst", "auditor")) return <p className="text-sm text-muted">Investigation requires a SOC analyst or auditor. In development, choose Mark Jansen or Eva Visser.</p>;
  // Remount on persona changes: never leave the previous investigator's answer in a new user's view.
  return <Content key={persona.username} username={persona.username} />;
}

export function Copilot() {
  return <><PageHeader icon={Bot} title="Investigation Copilot" subtitle="Evidence-grounded explanations of recorded agent activity" /><CopilotPanel /></>;
}

export function CopilotLauncher() {
  const [open, setOpen] = useState(false);
  return <>
    <button aria-label="Open investigation Copilot" onClick={() => setOpen(true)} className="fixed right-6 bottom-6 z-40 grid size-14 place-items-center rounded-2xl bg-accent-strong text-white shadow-xl"><Bot className="size-6" /></button>
    <Drawer open={open} onClose={() => setOpen(false)} title="Investigation Copilot">
      <div className="mb-3 flex justify-between"><Link className="text-sm text-accent" to="/copilot" onClick={() => setOpen(false)}>Open full investigation screen →</Link><button aria-label="Close Copilot" onClick={() => setOpen(false)}><X className="size-4" /></button></div>
      {open && <CopilotPanel />}
    </Drawer>
  </>;
}
