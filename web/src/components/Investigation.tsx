import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import { clock } from "../lib/format";
import { Button, Field, JsonBlock, Select, TextInput } from "./ui";

interface Case {
  status: string; assigned_to: string | null;
  events: { id: string; actor: string; ts: string; detail: Record<string, unknown> }[];
  decisions: { id: string; action: string; decision: string; trace_id: string | null; root_id: string | null; policy_version: string }[];
}
const TRANSITIONS: Record<string, string[]> = {
  new: ["triage", "investigating", "false_positive"], triage: ["investigating", "resolved", "false_positive"],
  investigating: ["triage", "resolved", "false_positive"], resolved: ["investigating"], false_positive: ["investigating"],
};
export function Investigation({ alertId, onUpdate }: { alertId: string; onUpdate: (status: string) => void }) {
  const { personas, can } = useSession();
  const toast = useToast(); const qc = useQueryClient();
  const [note, setNote] = useState(""); const [assignee, setAssignee] = useState<string | null>(null);
  const [decision, setDecision] = useState("");
  const details = useQuery({ queryKey: ["case", alertId], queryFn: () => api<Case>(`/v1/alerts/${alertId}/case`), enabled: can("soc-analyst", "auditor", "admin"), refetchInterval: 5000 });
  const act = useMutation({
    mutationFn: (status?: string) => api<{ status: string }>(`/v1/alerts/${alertId}/case`, { method: "PATCH", body: { ...(status ? { status } : {}), ...(note.trim() ? { note: note.trim() } : {}), ...(assignee !== null ? { assigned_to: assignee || null } : {}), ...(decision ? { decision_id: decision } : {}) } }),
    onSuccess: result => { setNote(""); setAssignee(null); setDecision(""); onUpdate(result.status); qc.invalidateQueries({ queryKey: ["case", alertId] }); qc.invalidateQueries({ queryKey: ["alerts"] }); toast("success", "Investigation update audited"); },
    onError: (e: Error) => toast("error", "Investigation update refused", e.message),
  });
  if (!can("soc-analyst", "auditor", "admin")) return <p className="text-sm text-faint">Switch to Mark (SOC) or Eva (auditor) to view investigation history.</p>;
  if (!details.data) return <p className="text-sm text-faint">{details.error?.message ?? "Loading investigation..."}</p>;
  const c = details.data;
  return <div className="space-y-3">
    <h3 className="text-sm font-semibold">SOC investigation · {c.status}</h3>
    <p className="text-xs text-muted">Assigned to {c.assigned_to ?? "no analyst"}. Every update records the analyst, time, and evidence in the audit ledger.</p>
    {can("soc-analyst") && <>
      <Select label="Assign analyst" value={assignee ?? c.assigned_to ?? ""} onChange={setAssignee} options={[{ value: "", label: "Unassigned" }, ...personas.filter(p => p.status === "active" && p.roles.includes("soc-analyst")).map(p => ({ value: p.username, label: p.name }))]} />
      <Field label="Investigation / resolution note"><TextInput value={note} onChange={e => setNote(e.target.value)} /></Field>
      <Select label="Link decision evidence (optional)" value={decision} onChange={setDecision} options={[{ value: "", label: "No decision link" }, ...c.decisions.map(d => ({ value: d.id, label: `${d.action}: ${d.decision} (${d.id})` }))]} />
      <div className="flex flex-wrap gap-2">
        <Button loading={act.isPending} disabled={!note.trim() && assignee === null && !decision} onClick={() => act.mutate(undefined)}>Save note / assignment</Button>
        {(TRANSITIONS[c.status] ?? []).map(st => <Button key={st} disabled={act.isPending || (["resolved", "false_positive"].includes(st) && note.trim().length < 3)} onClick={() => act.mutate(st)}>{st.replaceAll("_", " ")}</Button>)}
      </div>
    </>}
    <ol className="space-y-3">{c.events.map(e => <li key={e.id} className="rounded-lg border border-line p-3">
      <p className="mb-1 text-xs text-muted">{e.actor} · {clock(e.ts)}</p><JsonBlock value={e.detail} />
      {typeof e.detail.root_id === "string" && <Link className="mt-2 inline-block text-xs text-accent" to={`/lineage/${e.detail.root_id}`}>Open linked task and execution trace</Link>}
    </li>)}</ol>
    {decision && c.decisions.find(d => d.id === decision)?.root_id && <Link className="text-sm text-accent" to={`/lineage/${c.decisions.find(d => d.id === decision)!.root_id}`}>Preview selected decision's task and trace</Link>}
    <p className="text-xs text-faint">Resolving a case does not automatically resume a suspended agent.</p>
  </div>;
}
