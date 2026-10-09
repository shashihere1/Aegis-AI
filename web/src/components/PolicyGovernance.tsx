import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import type { Policies, PolicyDiff, RulesCheck } from "../lib/types";
import { Button, Card, Field, JsonBlock, Select, TextInput } from "./ui";

interface ReplayReport {
  evaluated: number; skipped: number; changed: number; more_permissive?: number; rules_changed?: boolean; generated_at: string;
  transitions: Record<string, number>; limitations: string;
  review?: { outcome: string; actor: string; justification: string; at: string };
  results: { decision_id: string; action: string; before: string; after: string; changed: boolean; more_permissive?: boolean; changed_fields?: string[]; before_obligations?: unknown[]; after_obligations?: unknown[] }[];
}
interface Security { required: boolean; rules_changed: boolean; more_permissive: number; approver: string | null; justification: string; at: string | null }
interface Version {
  id: string; name: string; status: string; author: string; approver: string | null;
  configuration: Record<string, unknown>; content_hash: string; justification: string;
  simulation: Partial<ReplayReport>;
  rules: { origin: string; base_version: string | null; bundle_hash: string; modules: string[]; cases: number; checks: RulesCheck; security: Security } | null;
}
interface ActiveRules { modules: Record<string, string>; cases: unknown[] }
interface Repository { differs: boolean; files: { file: string; status: string; added_lines: number; removed_lines: number }[] }
type RulesMode = "keep" | "edit" | "import";

function CheckReport({ checks }: { checks: RulesCheck }) {
  if (checks.skipped) return <p className="text-xs text-faint">Automatic checks: not needed ({checks.skipped}).</p>;
  if (checks.passed === undefined) return <p className="text-xs text-faint">Automatic checks: not recorded for this version.</p>;
  return <div className="space-y-1 text-sm">
    <p className={checks.passed ? "text-good-ink" : "text-critical-ink"}>
      Automatic checks {checks.passed ? "passed" : "failed"}{checks.cases ? ` · test cases ${checks.cases.passed}/${checks.cases.total}` : ""}
    </p>
    {checks.problems?.map((p) => <p key={p} className="text-critical-ink">• {p}</p>)}
    {checks.cases?.failed.map((f) => <p key={f.name} className="font-mono text-xs text-critical-ink">{f.name}: {f.problem}</p>)}
  </div>;
}

function DiffView({ diff }: { diff: PolicyDiff }) {
  const changed = diff.rules.filter((f) => f.status !== "unchanged");
  return <div className="space-y-3 rounded-lg border border-line p-4">
    <p className="text-sm font-semibold">What activating this version changes (compared with {diff.against})</p>
    {!changed.length && !diff.configuration.length && <p className="text-sm text-muted">Nothing: same rules and configuration.</p>}
    {diff.configuration.map((c) => <p key={c.path} className="font-mono text-xs">{c.path}: {JSON.stringify(c.before)} → {JSON.stringify(c.after)}</p>)}
    {diff.cases.changed && <p className="text-xs text-muted">Test cases changed: {diff.cases.before} → {diff.cases.after}</p>}
    {changed.map((f) => <div key={f.file}>
      <p className="mb-1 text-xs text-muted">{f.file} · {f.status} · +{f.added_lines} −{f.removed_lines}</p>
      <pre className="max-h-80 overflow-auto rounded-lg bg-inset p-3 font-mono text-xs leading-relaxed">
        {f.diff.split("\n").map((line, i) => <div key={i} className={line.startsWith("+") && !line.startsWith("+++") ? "text-good-ink" : line.startsWith("-") && !line.startsWith("---") ? "text-critical-ink" : line.startsWith("@@") ? "text-info-ink" : "text-muted"}>{line || " "}</div>)}
      </pre>
    </div>)}
  </div>;
}

export function PolicyGovernance({ policy }: { policy: Policies }) {
  const { persona, can } = useSession();
  const toast = useToast();
  const qc = useQueryClient();
  const versions = useQuery({ queryKey: ["policy-versions"], queryFn: () => api<{ active_version: string; versions: Version[] }>("/v1/policies/versions"), refetchInterval: 5000 });
  const repository = useQuery({ queryKey: ["policy-repository"], queryFn: () => api<Repository>("/v1/policies/repository"), refetchInterval: 15000 });
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("Lower payment approval threshold");
  const [threshold, setThreshold] = useState("2000");
  const [reason, setReason] = useState("");
  const [mode, setMode] = useState<RulesMode>("keep");
  const [edits, setEdits] = useState<Record<string, string> | null>(null);
  const [file, setFile] = useState("");
  const [casesText, setCasesText] = useState<string | null>(null);
  const [failedChecks, setFailedChecks] = useState<RulesCheck | null>(null);
  const activeId = versions.data?.active_version;
  const activeRules = useQuery({ queryKey: ["policy-rules", activeId], queryFn: () => api<ActiveRules>(`/v1/policies/${activeId}/rules`), enabled: mode === "edit" && !!activeId });
  const diff = useQuery({ queryKey: ["policy-diff", selected, activeId], queryFn: () => api<PolicyDiff>(`/v1/policies/${selected}/diff`), enabled: !!selected });
  const current = versions.data?.versions.find((v) => v.id === selected);
  const rulesEditable = policy.editing === "configuration-and-rules";

  const act = useMutation({
    mutationFn: ({ path, body }: { path: string; body?: unknown }) => post<Version>(path, body ?? {}),
    onSuccess: (result, vars) => {
      if (vars.path === "/v1/policies/versions") {
        setSelected(result.id);
        setFailedChecks(null);
      }
      qc.invalidateQueries({ queryKey: ["policy-versions"] });
      qc.invalidateQueries({ queryKey: ["policies"] });
      qc.invalidateQueries({ queryKey: ["policy-diff"] });
      toast("success", "Policy action recorded");
    },
    onError: (e: Error, vars) => {
      const checks = e instanceof ApiError ? (e.detail as { checks?: RulesCheck } | undefined)?.checks : undefined;
      if (vars.path === "/v1/policies/versions" && checks) setFailedChecks(checks);
      toast("error", "Policy action refused", e.message);
    },
  });
  const report = current?.simulation;
  const security = current?.rules?.security;
  const payments = (policy.data.thresholds as { payments?: { hitl_amount_eur?: number } })?.payments;
  const busy = act.isPending;
  const mine = current?.author === persona?.username;
  const action = (verb: string, extra: Record<string, unknown> = {}) => act.mutate({ path: `/v1/policies/${current?.id}/${verb}`, body: extra });
  const modules = edits ?? activeRules.data?.modules ?? {};
  const editingFile = file || Object.keys(modules)[0] || "";
  let casesError = "";
  if (mode === "edit" && casesText !== null) {
    try {
      if (!Array.isArray(JSON.parse(casesText))) casesError = "Test cases must be a JSON list";
    } catch {
      casesError = "Test cases are not valid JSON";
    }
  }

  const saveDraft = () => {
    const configuration = { ...policy.data, thresholds: { payments: { hitl_amount_eur: Number(threshold) } } };
    const rules = mode === "edit" ? { modules, ...(casesText !== null ? { cases: JSON.parse(casesText) } : {}) } : undefined;
    act.mutate({ path: "/v1/policies/versions", body: { name, justification: reason, configuration, ...(rules ? { rules } : {}), ...(mode === "import" ? { import_repository: true } : {}) } });
  };
  const invalidDraft = name.trim().length < 3 || reason.trim().length < 5 || !threshold.trim() || !Number.isFinite(Number(threshold)) || Number(threshold) < 0 || Number(threshold) > 1000000 || (mode === "edit" && (!Object.keys(modules).length || !!casesError));

  return <Card title="Governed policy changes" className="mb-5">
    <div className="space-y-5 p-5">
      <p className="text-sm text-muted">Active payment threshold: <strong className="text-fg">EUR {payments?.hitl_amount_eur?.toLocaleString()}</strong>. Runtime: {policy.engine}. {rulesEditable ? "Versions can change the configuration and the Rego rules; the engine runs the approved Rego from the database, never the files on disk." : "The python engine mirrors the repository rules, so versions change configuration only (set AEGIS_POLICY_ENGINE=rego or opa to govern the Rego too)."}</p>
      <p className="text-xs text-faint">Author: Priya. Policy approver: Fatima. A rule change, or a change that loosens a replayed decision, also needs a security sign-off from a second person (Lars). Switch personas in the header.</p>
      {repository.data?.differs && <p className="rounded-lg border border-line bg-inset p-3 text-sm text-warning-ink">The Rego in the repository differs from the running policy ({repository.data.files.filter((f) => f.status !== "unchanged").map((f) => `${f.file} +${f.added_lines} −${f.removed_lines}`).join(", ")}). It changes nothing until it is imported as a draft and approved.</p>}
      {policy.engine === "opa" && <Button roles={["policy-approver", "security-approver", "admin"]} disabled={busy || reason.trim().length < 5} onClick={() => act.mutate({ path: "/v1/policies/opa/sync", body: { justification: reason } })}>Push the approved policy to OPA</Button>}
      {can("policy-author") && <div className="space-y-3">
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Policy name"><TextInput value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Payment approval threshold (EUR)"><TextInput type="number" min={0} max={1000000} value={threshold} onChange={(e) => setThreshold(e.target.value)} /></Field>
          <Field label="Justification (also used for review / activation)"><TextInput value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
          <Select label="Rules" value={mode} onChange={(v) => { setMode(v as RulesMode); setFailedChecks(null); }} options={[
            { value: "keep", label: "Keep the active rules" },
            ...(rulesEditable ? [{ value: "edit", label: "Edit the rules" }, { value: "import", label: "Import the rules from the repository" }] : []),
          ]} />
        </div>
        {mode === "edit" && <div className="space-y-2">
          {Object.keys(modules).length > 1 && <Select label="File" value={editingFile} onChange={setFile} options={Object.keys(modules).map((f) => ({ value: f, label: f }))} />}
          <Field label={`Rego · ${editingFile}`} hint="Checked before the draft is saved: it must compile, keep data.aegis.tool_call.decision, use no network or non-deterministic functions, and pass every test case.">
            <textarea spellCheck={false} value={modules[editingFile] ?? ""} onChange={(e) => setEdits({ ...modules, [editingFile]: e.target.value })} className="h-80 w-full rounded-lg border border-line-strong bg-inset p-3 font-mono text-xs outline-none focus:border-accent" />
          </Field>
          {casesText === null
            ? <Button disabled={!activeRules.data} onClick={() => setCasesText(JSON.stringify(activeRules.data?.cases ?? [], null, 1))}>Also edit the test cases</Button>
            : <Field label="Test cases (JSON)" hint={casesError || "Each case: name, input, decision, rules, match (exact | include), optional obligations. Change a case when you change that behaviour on purpose."}>
                <textarea spellCheck={false} value={casesText} onChange={(e) => setCasesText(e.target.value)} className="h-60 w-full rounded-lg border border-line-strong bg-inset p-3 font-mono text-xs outline-none focus:border-accent" />
              </Field>}
          {edits && <Button onClick={() => { setEdits(null); setCasesText(null); }}>Discard my edits</Button>}
        </div>}
        <Button loading={busy} disabled={invalidDraft} onClick={saveDraft}>Save immutable draft</Button>
        {failedChecks && <div className="rounded-lg border border-line p-4"><CheckReport checks={failedChecks} /></div>}
      </div>}
      <Select label="Version to review" value={selected} onChange={setSelected} options={[{ value: "", label: "Select a policy version" }, ...(versions.data?.versions ?? []).map((v) => ({ value: v.id, label: `${v.name} - ${v.status} (${v.id})` }))]} />
      {current && <div className="space-y-3">
        <p className="text-sm">{current.status} · author {current.author} · approver {current.approver ?? "not yet approved"}</p>
        <p className="text-sm text-muted">Proposal: {current.justification}</p>
        {report?.review && <p className="text-sm text-muted">Review: {report.review.outcome} by {report.review.actor} — {report.review.justification}</p>}
        {current.rules && <div className="space-y-1 rounded-lg border border-line p-4 text-sm">
          <p>Rules: {current.rules.origin} · {current.rules.modules.join(", ")} · {current.rules.cases} test cases</p>
          <CheckReport checks={current.rules.checks} />
          {security?.required
            ? <p className={security.approver ? "text-good-ink" : "text-warning-ink"}>Security sign-off required ({[security.rules_changed && "the rules change", security.more_permissive > 0 && `${security.more_permissive} replayed decisions become more permissive`].filter(Boolean).join("; ")}): {security.approver ? `signed off by ${security.approver} — ${security.justification}` : "not yet given"}</p>
            : <p className="text-xs text-faint">No security sign-off needed: same rules, and no replayed decision becomes more permissive.</p>}
        </div>}
        {!current.rules && <p className="text-sm text-warning-ink">This version's Rego was never recorded, so it cannot be activated.</p>}
        {diff.data && current.status !== "active" && <DiffView diff={diff.data} />}
        <JsonBlock value={current.configuration} />
        {(can("policy-approver") || can("security-approver")) && <Field label="Review / activation justification"><TextInput value={reason} onChange={(e) => setReason(e.target.value)} /></Field>}
        <div className="flex flex-wrap gap-2">
          {["draft", "submitted"].includes(current.status) && <Button roles={["policy-author", "policy-approver"]} disabled={busy} onClick={() => action("replay", { limit: 200 })}>Replay last 200 decisions</Button>}
          {current.status === "draft" && mine && <Button disabled={busy || !report?.generated_at} onClick={() => action("submit")}>Submit for separate approval</Button>}
          {current.status === "submitted" && <Button roles={["policy-approver"]} disabled={busy || mine || reason.trim().length < 5} onClick={() => action("approve", { justification: reason })}>Approve</Button>}
          {security?.required && !security.approver && ["submitted", "approved"].includes(current.status) && <Button roles={["security-approver"]} disabled={busy || mine || reason.trim().length < 5} onClick={() => action("security-approve", { justification: reason })}>Security sign-off</Button>}
          {current.status === "submitted" && <Button variant="danger" roles={["policy-approver", "security-approver"]} disabled={busy || mine || reason.trim().length < 5} onClick={() => action("reject", { justification: reason })}>Reject with justification</Button>}
          {["approved", "superseded"].includes(current.status) && <Button roles={["policy-approver"]} disabled={busy || mine || reason.trim().length < 5} title={current.status === "approved" && security?.required && !security.approver ? "Needs the security sign-off first" : undefined} onClick={() => action(current.status === "approved" ? "activate" : "rollback", { justification: reason, expected_active_version: versions.data?.active_version })}>{current.status === "approved" ? "Activate" : "Roll back to this version"}</Button>}
        </div>
        {report?.generated_at && <div className="space-y-2 rounded-lg border border-line p-4">
          <p>Replay: {report.evaluated} evaluated · {report.changed} changed · {report.skipped} skipped{report.more_permissive ? <strong className="text-warning-ink"> · {report.more_permissive} more permissive</strong> : null}</p>
          <JsonBlock value={report.transitions} />
          <p className="text-xs text-faint">{report.limitations}</p>
          {report.evaluated === 0 && <p className="text-warning-ink">No compatible traffic to replay. Run a Bank Assistant transfer first for meaningful evidence.</p>}
          <ul className="max-h-60 space-y-2 overflow-auto text-xs">{report.results?.filter((r) => r.changed).map((r) => <li key={r.decision_id} className={r.more_permissive ? "text-warning-ink" : undefined}>
            {r.action}: {r.before} → {r.after} ({r.decision_id}){r.more_permissive ? " · more permissive" : ""}
            {r.changed_fields && <span className="ml-2 text-muted">Changed: {r.changed_fields.join(", ")}</span>}
            {r.changed_fields?.includes("obligations") && <JsonBlock value={{ before: r.before_obligations, after: r.after_obligations }} />}
          </li>)}</ul>
        </div>}
        <p className="break-all font-mono text-xs text-faint">Configuration hash: {current.content_hash}{current.rules ? ` · rules hash: ${current.rules.bundle_hash}` : ""}</p>
      </div>}
    </div>
  </Card>;
}
