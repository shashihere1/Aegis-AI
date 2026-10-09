import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MessageSquare } from "lucide-react";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { Button, Card, PageHeader, Pill } from "../components/ui";

type Mode = "inquiry" | "documents" | "address" | "transfer";
type Event = { kind: string; label: string; arguments?: unknown; result?: unknown; runtime?: string;
  usage?: { prompt_tokens: number; completion_tokens: number }; metadata?: Record<string, string>; approval_id?: string };
type Run = { id: string; subject: string; mode: Mode; status: string; reply: string; events: Event[]; root_id: string | null;
  pending: { name?: string; arguments?: unknown; approval_id?: string }; resumable: boolean };
type Status = { ready: boolean; azure_configured: boolean; frameworks: Record<string, string | null>; policy_error: string | null;
  policy: { deployment: string; processing_scope: string; allowed_processing_scope: string; max_data_class: string; daily_budget_eur: number };
  budget: { remaining_estimate_eur: number; used_or_reserved_eur: number; outstanding_holds: number; day_utc: string } };
const OPEN = ["running", "confirmation_required", "approval_required"];
const EXAMPLES: Record<Mode, string> = {
  inquiry: "What is my account balance?",
  documents: "Verify my passport D-77 and explain the result.",
  address: "Verify my passport D-77, then change my address to Keizersgracht 401, 1016 EK Amsterdam.",
  transfer: "Transfer EUR 25,000 to the demo landlord as a new beneficiary, reference Rent.",
};

export function BankAssistant() {
  const { persona, can, switchTo } = useSession();
  const queryClient = useQueryClient();
  const customer = can("customer") && persona?.username === "jan.devries";
  const [mode, setMode] = useState<Mode>("inquiry");
  const [message, setMessage] = useState(EXAMPLES.inquiry);
  const [consent, setConsent] = useState(false);
  const [runId, setRunId] = useState<string | null>(null);
  const [requestId, setRequestId] = useState(() => crypto.randomUUID());
  const status = useQuery({ queryKey: ["live-agent-status", persona?.username],
    queryFn: () => api<Status>("/demo/api/agent/status"), refetchInterval: 4000 });
  const history = useQuery({ queryKey: ["live-agent-history", persona?.username],
    queryFn: () => api<Run[]>("/demo/api/agent/runs"), refetchInterval: 2000 });
  const selected = useQuery({ queryKey: ["live-agent-run", persona?.username, runId],
    queryFn: () => api<Run>(`/demo/api/agent/runs/${runId}`), enabled: !!runId, refetchInterval: 1000 });
  const run = selected.data;
  const openRun = history.data?.find(r => r.subject === persona?.username && OPEN.includes(r.status));
  useEffect(() => { setRunId(null); setConsent(false); setRequestId(crypto.randomUUID()); }, [persona?.username]);
  useEffect(() => { if (!runId && openRun) setRunId(openRun.id); }, [runId, openRun]);
  const start = useMutation({ retry: false, mutationFn: () => post<Run>("/demo/api/agent/runs", {
    request_id: requestId, mode, message, confirm_synthetic_external_call: true,
  }), onSuccess: r => { setRunId(r.id); setRequestId(crypto.randomUUID()); queryClient.invalidateQueries(); } });
  const proceed = useMutation({ retry: false, mutationFn: (action: string) =>
    post<Run>(`/demo/api/agent/runs/${runId}/continue`, { action }),
    onSuccess: () => queryClient.invalidateQueries() });
  const error = start.error ?? proceed.error ?? selected.error ?? history.error ?? status.error;
  const fieldClass = "w-full rounded-lg border border-line-strong bg-inset p-3 text-sm";

  return <>
    <PageHeader icon={MessageSquare} title="Bank Assistant" subtitle="Ava uses LangGraph and Azure tool calling. KYC runs Microsoft Agent Framework. Aegis authorizes execution." />
    <Card className="mb-5 p-4 text-sm">
      <Pill tone="warning">Synthetic bank · Real Azure requests</Pill>
      <p className="mt-2 text-muted">Only synthetic demo data. Azure requests incur charges. No real money moves; customer and banking data are local fixtures. The persona system is passwordless development identity, not enterprise IAM.</p>
      {!customer && <Button className="mt-3" onClick={() => switchTo("jan.devries")}>Act as Jan — synthetic customer</Button>}
    </Card>
    {status.data && <Card className="mb-5 p-4 text-sm">
      <div className="flex flex-wrap gap-4">
        <span>Deployment: <strong>{status.data.policy.deployment || "not configured"}</strong></span>
        <span>Processing: {status.data.policy.processing_scope} / permitted: {status.data.policy.allowed_processing_scope}</span>
        <span>Data ceiling: {status.data.policy.max_data_class}</span>
        <span>Remaining estimate: €{status.data.budget.remaining_estimate_eur.toFixed(4)} / €{status.data.policy.daily_budget_eur} per agent/day UTC</span>
      </div>
      <p className="mt-2 text-xs text-muted">{Object.entries(status.data.frameworks).map(([n, v]) => `${n}: ${v ?? "missing"}`).join(" · ")} · {status.data.budget.outstanding_holds} uncertain/in-flight budget holds. Estimates are not Azure invoices. OPA is not used for model controls.</p>
      {!status.data.ready && <p className="mt-3 text-warning-ink">{status.data.policy_error || "Configure Azure and install requirements-agents.txt."} See docs/live-agents.md. Processing geography must describe the actual deployment, not just the resource region.</p>}
    </Card>}
    {error && <p role="alert" className="mb-4 text-sm text-critical-ink">{error.message}</p>}
    <div className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
      <div className="space-y-5">
        <Card title="Start a customer task" className="p-5">
          <label className="mb-2 block text-sm">Purpose (limits the Mandate and visible tools)
            <select value={mode} onChange={e => { const next = e.target.value as Mode; setMode(next); setMessage(EXAMPLES[next]); }}
              disabled={!!openRun || start.isPending} className={`${fieldClass} mt-2`}>
              <option value="inquiry">Account inquiry</option><option value="documents">Document verification</option>
              <option value="address">Address change</option><option value="transfer">Transfer</option>
            </select>
          </label>
          <label className="block text-sm">Request (synthetic data only)
            <textarea rows={5} maxLength={1500} value={message} onChange={e => setMessage(e.target.value)}
              disabled={!!openRun || start.isPending} className={`${fieldClass} mt-2`} />
          </label>
          <label className="my-4 flex gap-2 text-sm"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />
            I am using synthetic data and authorize paid Azure inference for this task.</label>
          <Button loading={start.isPending} disabled={!customer || !consent || !status.data?.ready || !!openRun || message.trim().length < 3}
            onClick={() => start.mutate()}>Ask Ava</Button>
          {openRun && <p className="mt-3 text-xs text-muted">Finish or cancel the open task before starting another.</p>}
        </Card>
        <Card title="Recent runs" className="p-4">
          <div className="space-y-2">{history.data?.map(r => <button key={r.id} className="block w-full rounded-lg bg-inset p-3 text-left text-sm"
            onClick={() => { setRunId(r.id); start.reset(); proceed.reset(); }}>
            {r.mode} · {r.status}<span className="block text-xs text-muted">{r.subject} · {r.id.slice(0, 8)}</span>
          </button>)}</div>
          {!history.data?.length && <p className="text-sm text-muted">No live-agent runs yet. Scripted Studio scenes are tracked separately.</p>}
        </Card>
      </div>
      <Card title="Live workflow and verified receipts" className="p-5">
        {!run && <p className="text-sm text-muted">Start a task or select a run. Verified results below come from tools, not the model's assertions.</p>}
        {run && <>
          <div className="mb-4 flex flex-wrap items-center gap-3"><Pill>{run.status}</Pill>
            {!customer && run.root_id && <Link className="text-sm text-accent" to={`/lineage/${run.root_id}`}>Open lineage</Link>}
            {!customer && <Link className="text-sm text-accent" to="/usage">Usage & cost</Link>}
          </div>
          {run.events.map((e, i) => <div key={i} className="mb-3 rounded-xl border border-line p-3 text-sm">
            <div className="font-medium">{i + 1}. {e.kind === "tool" ? "Verified result: " : ""}{e.label}</div>
            {e.runtime && <div className="text-xs text-accent">Runtime: {e.runtime}</div>}
            {e.usage && <div className="mt-1 text-xs text-muted">Tokens: {e.usage.prompt_tokens} in / {e.usage.completion_tokens} out · estimated €{e.metadata?.["x-aegis-llm-estimated-cost-eur"]}</div>}
            {(e.result !== undefined || e.arguments !== undefined) && <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words text-xs">{JSON.stringify(e.result ?? e.arguments, null, 2)}</pre>}
            {e.approval_id && <p className="mt-1 font-mono text-xs">Approval: {e.approval_id}</p>}
          </div>)}
          {run.status === "confirmation_required" && <div className="my-4 rounded-xl border border-warning/50 p-4 text-sm">
            <h3 className="font-semibold">Review before execution: {run.pending.name}</h3>
            <pre className="my-3 whitespace-pre-wrap break-words text-xs">{JSON.stringify(run.pending.arguments, null, 2)}</pre>
            <p className="mb-3 text-muted">Nothing in this proposal has executed yet. Confirmation approves these exact stored arguments.</p>
            {customer && <Button loading={proceed.isPending} onClick={() => proceed.mutate("confirm")}>Confirm this synthetic action</Button>}
          </div>}
          {run.status === "approval_required" && <div className="my-4 rounded-xl border border-warning/50 p-4 text-sm">
            <p>Aegis also requires separate risk approval. Switch to Sanne Bakker, approve the matching request in Approvals, then return to Jan and resume. The Mandate must still be valid.</p>
            <div className="mt-3 flex gap-3">{customer && <Button loading={proceed.isPending} onClick={() => proceed.mutate("resume_approval")}>Resume after risk approval</Button>}
              {!customer && <Link className="text-accent" to="/approvals">Open Approvals</Link>}</div>
          </div>}
          {run.reply && <p className="my-4 whitespace-pre-wrap text-sm">{run.reply}</p>}
          {customer && OPEN.includes(run.status) && <Button loading={proceed.isPending} onClick={() => proceed.mutate("cancel")}>Cancel run</Button>}
          <p className="mt-4 text-xs text-muted">Model prose is not evidence of execution. Successful actions have verified receipts. No automatic write retries. History persists in the configured database; pending tasks cannot resume after a server restart.</p>
        </>}
      </Card>
    </div>
  </>;
}
