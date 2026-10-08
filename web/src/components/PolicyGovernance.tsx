import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import type { Policies } from "../lib/types";
import { Button, Card, Field, JsonBlock, Select, TextInput } from "./ui";

interface ReplayReport {
  evaluated: number; skipped: number; changed: number; generated_at: string;
  transitions: Record<string, number>; limitations: string;
  review?: { outcome: string; actor: string; justification: string; at: string };
  results: { decision_id: string; action: string; before: string; after: string; changed: boolean; changed_fields?: string[]; before_obligations?: unknown[]; after_obligations?: unknown[] }[];
}
interface Version {
  id: string; name: string; status: string; author: string; approver: string | null;
  configuration: Record<string, unknown>; content_hash: string; justification: string;
  simulation: Partial<ReplayReport>;
}

export function PolicyGovernance({ policy }: { policy: Policies }) {
  const { persona, can } = useSession();
  const toast = useToast();
  const qc = useQueryClient();
  const versions = useQuery({ queryKey: ["policy-versions"], queryFn: () => api<{ active_version: string; versions: Version[] }>("/v1/policies/versions"), refetchInterval: 5000 });
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("Lower payment approval threshold");
  const [threshold, setThreshold] = useState("2000");
  const [reason, setReason] = useState("");
  const current = versions.data?.versions.find(v => v.id === selected);
  const act = useMutation({
    mutationFn: ({ path, body }: { path: string; body?: unknown }) => post<Version>(path, body ?? {}),
    onSuccess: (result, vars) => {
      if (vars.path === "/v1/policies/versions") setSelected(result.id);
      qc.invalidateQueries({ queryKey: ["policy-versions"] });
      qc.invalidateQueries({ queryKey: ["policies"] });
      toast("success", "Policy action recorded");
    },
    onError: (e: Error) => toast("error", "Policy action refused", e.message),
  });
  const report = current?.simulation;
  const payments = (policy.data.thresholds as { payments?: { hitl_amount_eur?: number } })?.payments;
  const busy = act.isPending;
  const writable = policy.engine === "python";
  const action = (verb: string, extra: Record<string, unknown> = {}) => act.mutate({ path: `/v1/policies/${current?.id}/${verb}`, body: extra });
  return <Card title="Governed policy changes" className="mb-5">
    <div className="space-y-5 p-5">
      <p className="text-sm text-muted">Active payment threshold: <strong className="text-fg">EUR {payments?.hitl_amount_eur?.toLocaleString()}</strong>. Runtime: {policy.engine}. This workflow changes supported configuration, not arbitrary Rego source.</p>
      <p className="text-xs text-faint">Author: Priya. Independent approver: Fatima. Switch personas in the header. Local personas are passwordless development identities.</p>
      {can("policy-author") && writable && <div className="grid gap-3 md:grid-cols-2">
        <Field label="Policy name"><TextInput value={name} onChange={e => setName(e.target.value)} /></Field>
        <Field label="Payment approval threshold (EUR)"><TextInput type="number" min={0} max={1000000} value={threshold} onChange={e => setThreshold(e.target.value)} /></Field>
        <Field label="Justification (also used for review / activation)"><TextInput value={reason} onChange={e => setReason(e.target.value)} /></Field>
        <Button loading={busy} disabled={name.trim().length < 3 || reason.trim().length < 5 || !threshold.trim() || !Number.isFinite(Number(threshold)) || Number(threshold) < 0 || Number(threshold) > 1000000} onClick={() => act.mutate({ path: "/v1/policies/versions", body: { name, justification: reason, configuration: { ...policy.data, thresholds: { payments: { hitl_amount_eur: Number(threshold) } } } } })}>Save immutable draft</Button>
      </div>}
      <Select label="Version to review" value={selected} onChange={setSelected} options={[{ value: "", label: "Select a policy version" }, ...(versions.data?.versions ?? []).map(v => ({ value: v.id, label: `${v.name} - ${v.status} (${v.id})` }))]} />
      {current && <div className="space-y-3">
        <p className="text-sm">{current.status} · author {current.author} · approver {current.approver ?? "not yet approved"}</p>
        <p className="text-sm text-muted">Proposal: {current.justification}</p>
        {report?.review && <p className="text-sm text-muted">Review: {report.review.outcome} by {report.review.actor} — {report.review.justification}</p>}
        <JsonBlock value={current.configuration} />
        {can("policy-approver") && <Field label="Review / activation justification"><TextInput value={reason} onChange={e => setReason(e.target.value)} /></Field>}
        <div className="flex flex-wrap gap-2">
          {["draft", "submitted"].includes(current.status) && <Button roles={["policy-author", "policy-approver"]} disabled={busy || !writable} onClick={() => action("replay", { limit: 200 })}>Replay last 200 decisions</Button>}
          {current.status === "draft" && current.author === persona?.username && <Button disabled={busy || !report?.generated_at} onClick={() => action("submit")}>Submit for separate approval</Button>}
          {current.status === "submitted" && <Button roles={["policy-approver"]} disabled={busy || current.author === persona?.username || reason.trim().length < 5} onClick={() => action("approve", { justification: reason })}>Approve</Button>}
          {current.status === "submitted" && <Button variant="danger" roles={["policy-approver"]} disabled={busy || current.author === persona?.username || reason.trim().length < 5} onClick={() => action("reject", { justification: reason })}>Reject with justification</Button>}
          {["approved", "superseded"].includes(current.status) && <Button roles={["policy-approver"]} disabled={busy || current.author === persona?.username || reason.trim().length < 5} onClick={() => action(current.status === "approved" ? "activate" : "rollback", { justification: reason, expected_active_version: versions.data?.active_version })}>{current.status === "approved" ? "Activate" : "Roll back to this version"}</Button>}
        </div>
        {report?.generated_at && <div className="space-y-2 rounded-lg border border-line p-4">
          <p>Replay: {report.evaluated} evaluated · {report.changed} changed · {report.skipped} skipped</p>
          <JsonBlock value={report.transitions} />
          <p className="text-xs text-faint">{report.limitations}</p>
          {report.evaluated === 0 && <p className="text-warning-ink">No compatible traffic to replay. Run a Studio transfer first for meaningful evidence.</p>}
          <ul className="max-h-60 space-y-2 overflow-auto text-xs">{report.results?.filter(r => r.changed).map(r => <li key={r.decision_id}>
            {r.action}: {r.before} → {r.after} ({r.decision_id})
            {r.changed_fields && <span className="ml-2 text-muted">Changed: {r.changed_fields.join(", ")}</span>}
            {r.changed_fields?.includes("obligations") && <JsonBlock value={{ before: r.before_obligations, after: r.after_obligations }} />}
          </li>)}</ul>
        </div>}
        <p className="break-all font-mono text-xs text-faint">Configuration hash: {current.content_hash}</p>
      </div>}
    </div>
  </Card>;
}
