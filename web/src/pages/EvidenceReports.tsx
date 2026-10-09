import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Download, FileCheck2, ShieldCheck } from "lucide-react";
import { api, downloadFile, post } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import type { AgentPage, EvidenceReport, EvidenceSchedule, EvidenceSummary } from "../lib/types";
import { Button, Card, Chip, Drawer, JsonBlock, Select, TextInput } from "../components/ui";

const frameworks = [
  { value: "all", label: "All mapped frameworks" },
  { value: "eu-ai-act", label: "EU AI Act" }, { value: "dora", label: "DORA" },
  { value: "gdpr", label: "GDPR" }, { value: "iso-42001", label: "ISO/IEC 42001 (indicative)" },
  { value: "nist-ai-rmf", label: "NIST AI RMF 1.0" },
];

export function EvidenceReports() {
  const { can } = useSession();
  const auditor = can("auditor");
  const toast = useToast();
  const client = useQueryClient();
  const [from, setFrom] = useState(() => new Date(Date.now() - 6 * 86400000).toISOString().slice(0, 10));
  const [to, setTo] = useState(() => new Date().toISOString().slice(0, 10));
  const [agent, setAgent] = useState("");
  const [root, setRoot] = useState("");
  const [framework, setFramework] = useState("all");
  const [interval, setInterval] = useState("24");
  const [busy, setBusy] = useState<string | null>(null);
  const [review, setReview] = useState<EvidenceReport | null>(null);
  const [note, setNote] = useState("");
  const scope = { from, to, agent_id: agent || null, root_id: root.trim() || null, framework };
  const agents = useQuery({ queryKey: ["evidence-agents"], queryFn: () => api<AgentPage>("/v1/agents", { query: { limit: 200 } }), enabled: auditor });
  const summary = useQuery({ queryKey: ["evidence-scoped-summary", scope], queryFn: () => api<EvidenceSummary>("/v1/evidence/summary", { query: scope }), enabled: auditor && !!from && !!to && from <= to, refetchInterval: 10000 });
  const reports = useQuery({ queryKey: ["evidence-reports"], queryFn: () => api<EvidenceReport[]>("/v1/evidence/reports"), enabled: auditor, refetchInterval: 10000 });
  const schedules = useQuery({ queryKey: ["evidence-schedules"], queryFn: () => api<EvidenceSchedule[]>("/v1/evidence/schedules"), enabled: auditor, refetchInterval: 10000 });
  const preview = summary.data;

  async function download(id: string) {
    const { blob, filename } = await downloadFile(`/v1/evidence/reports/${id}/download`);
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url; link.download = filename;
    document.body.appendChild(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  async function act(key: string, action: () => Promise<unknown>) {
    setBusy(key);
    try {
      await action();
      await Promise.all([client.invalidateQueries({ queryKey: ["evidence-reports"] }), client.invalidateQueries({ queryKey: ["evidence-schedules"] }), client.invalidateQueries({ queryKey: ["evidence-scoped-summary"] }), client.invalidateQueries({ queryKey: ["ledger"] })]);
    } catch (error) {
      toast("error", "Evidence action failed", error instanceof Error ? error.message : String(error));
    } finally { setBusy(null); }
  }

  if (!auditor) return <Card className="mb-4 p-5"><p className="text-warning-ink">Switch to Eva Visser (Auditor) for regulatory evidence, report history and schedules.</p></Card>;

  return <>
    <Card title="Compliance evidence & signed reports" className="mb-4">
      <div className="space-y-4 p-5">
        <p className="text-sm text-muted">Select activity dates and an optional agent or task. Related current inventory and active policy context are labelled separately. Unrelated ledger payloads stay out of the ZIP; signed inclusion proofs preserve verification.</p>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className="text-sm">From (UTC, inclusive)<TextInput type="date" value={from} onChange={e => setFrom(e.target.value)} /></label>
          <label className="text-sm">To (UTC, inclusive)<TextInput type="date" value={to} onChange={e => setTo(e.target.value)} /></label>
          <label className="text-sm">Agent scope<Select label="Evidence agent" value={agent} onChange={setAgent} options={[{ value: "", label: "All agents" }, ...(agents.data?.items ?? []).map(a => ({ value: a.id, label: a.name }))]} className="w-full" /></label>
          <label className="text-sm">Task root (optional)<TextInput value={root} onChange={e => setRoot(e.target.value)} placeholder="mdt_…" maxLength={40} /></label>
        </div>
        <Select label="Evidence framework" value={framework} onChange={setFramework} options={frameworks} />
        <p className="text-xs text-faint">Framework selection changes control mapping, not the underlying activity scope. Exports may contain confidential selected arguments and policy inputs. Evidence coverage is not legal compliance.</p>
        {summary.isError && <p role="alert" className="text-critical-ink">{summary.error.message}</p>}
        {from > to && <p role="alert" className="text-critical-ink">From must be on or before To.</p>}
        {preview && <>
          <p className="text-sm">{preview.counts.decisions} decisions · {preview.counts.approvals} approvals · {preview.counts.alerts} alerts · {preview.counts.ledger} disclosed ledger entries / {preview.integrity.entries} source entries</p>
          <p className="break-all font-mono text-xs text-muted">Evidence key: {preview.evidence_key.fingerprint} · {preview.evidence_key.mode}</p>
          <p className="text-sm text-muted">{preview.executive_summary}</p>
        </>}
        <Button icon={Download} variant="primary" loading={busy === "generate"} disabled={!!busy || summary.isFetching || summary.isError || !preview?.integrity.ok || from > to} onClick={() => act("generate", async () => {
          const result = await post<EvidenceReport>("/v1/evidence/reports", scope);
          await download(result.id);
          toast("success", "Signed report saved and downloaded", "Open report.html; verify_pack.py checks signatures and inclusion proofs. No Azure call was made.");
        })}>Generate & download scoped report</Button>
      </div>
    </Card>
    {preview && <Card title="Control coverage — evidence, not compliance verdicts" className="mb-4">
      <div className="grid gap-3 p-5 md:grid-cols-2">
        {preview.coverage.map(control => <div key={control.id} className="rounded-lg border border-line p-4">
          <div className="flex flex-wrap items-center gap-2"><strong>{control.id}</strong><Chip>{control.status.replaceAll("_", " ")}</Chip><span className="text-xs text-faint">{control.observed_records} records</span></div>
          <p className="mt-2 text-sm font-medium">{control.title}</p><p className="mt-1 text-xs text-muted">{control.limitations}</p>
          <details className="mt-2 text-xs"><summary className="cursor-pointer text-muted">Evidence queries & record citations</summary><div className="mt-2"><JsonBlock value={control.sources} /></div></details>
          <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs">{control.references.map(reference => <a key={reference.framework} href={reference.source_url} target="_blank" rel="noreferrer" className="text-accent underline">{reference.name}: {reference.reference}</a>)}</div>
        </div>)}
      </div>
    </Card>}
    <Card title="Automatic generation" className="mb-4">
      <div className="space-y-3 p-5">
        <p className="text-sm text-muted">Schedules use a rolling UTC interval, with the agent/task/framework scope above. The first report runs on the next worker pass. Missed intervals catch up after restart. Reports are stored in this database; no email or regulatory submission is sent.</p>
        <div className="flex flex-wrap gap-3">
          <Select label="Evidence schedule interval" value={interval} onChange={setInterval} options={[{ value: "1", label: "Hourly" }, { value: "24", label: "Daily" }, { value: "168", label: "Weekly" }]} />
          <Button icon={CalendarClock} loading={busy === "schedule"} disabled={!!busy || !preview?.automation.enabled || !preview?.automation.persistent_key || !preview.integrity.ok || summary.isError} onClick={() => act("schedule", async () => {
            await post("/v1/evidence/schedules", { name: `${framework} · ${agent || "all agents"} · ${interval}h`, interval_hours: Number(interval), scope: { agent_id: agent || null, root_id: root.trim() || null, framework } });
            toast("success", "Automatic report schedule created", `Worker checks every ${preview?.automation.check_seconds} seconds. No fixed dates are used.`);
          })}>Create schedule</Button>
          <Button disabled={!!busy} onClick={() => act("due", async () => { const result = await post<EvidenceReport[]>("/v1/evidence/schedules/run"); toast("success", "Due schedules checked", `${result.length} report slots processed.`); })}>Run due schedules now</Button>
        </div>
        {preview && (!preview.automation.enabled || !preview.automation.persistent_key) && <p className="text-warning-ink">Scheduling requires an enabled worker, persistent database and persistent evidence key.</p>}
        {schedules.isError && <p className="text-critical-ink">{schedules.error.message}</p>}
        {(schedules.data ?? []).map(schedule => <div key={schedule.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-line p-3 text-sm">
          <span className="flex-1">{schedule.name} · {schedule.enabled ? "Enabled" : "Paused"} · next {new Date(schedule.next_run_at).toLocaleString()}</span>
          <Button disabled={!!busy} onClick={() => act(schedule.id, () => api(`/v1/evidence/schedules/${schedule.id}`, { method: "PATCH", body: { enabled: !schedule.enabled } }))}>{schedule.enabled ? "Pause" : "Resume"}</Button>
        </div>)}
        {!schedules.data?.length && <p className="text-xs text-faint">No schedules yet. Nothing is automatically exported until you create one.</p>}
      </div>
    </Card>
    <Card title="Saved report history" className="mb-4"><div className="space-y-3 p-5">
      <p className="text-xs text-muted">Signed ZIPs and metadata persist across restarts. An auditor review is an additional ledger event; it does not rewrite the signed artifact.</p>
      {reports.isError && <p className="text-critical-ink">{reports.error.message}</p>}
      {(reports.data ?? []).map(report => <div key={report.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-line p-3">
        <FileCheck2 className="size-5 text-accent" /><div className="min-w-0 flex-1"><div className="text-sm">{new Date(report.generated_at).toLocaleString()} · {report.schedule_id ? "Scheduled" : "On demand"} · {report.status}</div><p className="font-mono text-xs text-faint">{report.id} · {report.error_code || report.sha256.slice(0, 16)}</p>{report.reviewed_by && <p className="text-xs text-good-ink">Reviewed by {report.reviewed_by}</p>}</div>
        <Button disabled={!!busy || report.status !== "ready"} icon={Download} onClick={() => act(report.id, () => download(report.id))}>Download</Button>
        <Button icon={ShieldCheck} disabled={report.status !== "ready"} onClick={() => { setReview(report); setNote(""); }}>Inspect / review</Button>
      </div>)}
      {!reports.data?.length && <p className="text-sm text-faint">Generate a report or create a schedule to begin.</p>}
    </div></Card>
    <Drawer open={!!review} onClose={() => setReview(null)} title="Auditor evidence review">
      {review && <div className="space-y-4"><p className="text-xs text-muted">SHA-256 {review.sha256}</p><JsonBlock value={review.summary} />
        {review.reviewed_by ? <p>Reviewed by {review.reviewed_by}: {review.review_note}</p> : <><TextInput value={note} onChange={e => setNote(e.target.value)} maxLength={2000} placeholder="Review observations (at least 10 characters)" /><Button disabled={!!busy || note.trim().length < 10} onClick={() => act("review", async () => { await post(`/v1/evidence/reports/${review.id}/review`, { note: note.trim() }); setReview(null); toast("success", "Auditor review recorded", "The signed ZIP is unchanged; the review is linked to its SHA-256 in the audit ledger."); })}>Record auditor review</Button></>}
      </div>}
    </Drawer>
  </>;
}
