import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Download, ShieldCheck } from "lucide-react";
import { api, downloadFile, post } from "../lib/api";
import { titleCase } from "../lib/format";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import type { AgentPage, EvidenceReport, EvidenceSchedule, EvidenceSummary } from "../lib/types";
import {
  Badge,
  Button,
  Callout,
  Card,
  Chip,
  Drawer,
  EmptyState,
  ErrorState,
  Field,
  JsonBlock,
  Select,
  Skeleton,
  SkeletonRows,
  Stat,
  StatGroup,
  TBody,
  THead,
  Table,
  Td,
  Textarea,
  TextInput,
  Th,
  Tr,
  cx,
  focusRing,
} from "../components/ui";

const frameworks = [
  { value: "all", label: "All mapped frameworks" },
  { value: "eu-ai-act", label: "EU AI Act" },
  { value: "dora", label: "DORA" },
  { value: "gdpr", label: "GDPR" },
  { value: "iso-42001", label: "ISO/IEC 42001 (indicative)" },
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
  const summary = useQuery({
    queryKey: ["evidence-scoped-summary", scope],
    queryFn: () => api<EvidenceSummary>("/v1/evidence/summary", { query: scope }),
    enabled: auditor && !!from && !!to && from <= to,
    refetchInterval: 10000,
  });
  const reports = useQuery({ queryKey: ["evidence-reports"], queryFn: () => api<EvidenceReport[]>("/v1/evidence/reports"), enabled: auditor, refetchInterval: 10000 });
  const schedules = useQuery({ queryKey: ["evidence-schedules"], queryFn: () => api<EvidenceSchedule[]>("/v1/evidence/schedules"), enabled: auditor, refetchInterval: 10000 });
  const preview = summary.data;
  const badRange = from > to;

  async function download(id: string) {
    const { blob, filename } = await downloadFile(`/v1/evidence/reports/${id}/download`);
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  async function act(key: string, action: () => Promise<unknown>) {
    setBusy(key);
    try {
      await action();
      await Promise.all([
        client.invalidateQueries({ queryKey: ["evidence-reports"] }),
        client.invalidateQueries({ queryKey: ["evidence-schedules"] }),
        client.invalidateQueries({ queryKey: ["evidence-scoped-summary"] }),
        client.invalidateQueries({ queryKey: ["ledger"] }),
      ]);
    } catch (error) {
      toast("error", "Evidence action failed", error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  }

  if (!auditor)
    return (
      <Callout tone="warning" className="mb-6">
        Switch to Eva Visser (Auditor) for regulatory evidence, report history and schedules.
      </Callout>
    );

  return (
    <>
      <Card title="Compliance evidence and signed reports" className="mb-6">
        <div className="space-y-4 p-5">
          <p className="text-sm text-muted">
            Select activity dates and an optional agent or task. Related current inventory and active policy context are labelled separately. Unrelated ledger payloads stay out of the ZIP;
            signed inclusion proofs preserve verification.
          </p>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <Field label="From (UTC, inclusive)">
              <TextInput type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
            </Field>
            <Field label="To (UTC, inclusive)">
              <TextInput type="date" value={to} onChange={(e) => setTo(e.target.value)} />
            </Field>
            <Field label="Agent scope" hint={agents.isError ? "Agent list unavailable; scoping to one agent is disabled." : undefined}>
              <Select
                label="Agent scope"
                value={agent}
                onChange={setAgent}
                options={[{ value: "", label: agents.isLoading ? "Loading agents…" : "All agents" }, ...(agents.data?.items ?? []).map((a) => ({ value: a.id, label: a.name }))]}
                className="w-full"
              />
            </Field>
            <Field label="Task root (optional)">
              <TextInput value={root} onChange={(e) => setRoot(e.target.value)} placeholder="mdt_…" maxLength={40} className="font-mono" />
            </Field>
          </div>
          <Field label="Framework" hint="Framework selection changes control mapping, not the underlying activity scope. Exports may contain confidential selected arguments and policy inputs. Evidence coverage is not legal compliance.">
            <Select label="Evidence framework" value={framework} onChange={setFramework} options={frameworks} />
          </Field>
          {badRange && (
            <p role="alert" className="text-sm text-critical-ink">
              From must be on or before To.
            </p>
          )}
          {summary.isError && <ErrorState title="Couldn't load the evidence preview" error={summary.error} onRetry={() => void summary.refetch()} />}
          {summary.isLoading && (
            <div role="status" aria-label="Loading preview" className="space-y-2">
              <Skeleton className="h-4 w-80 max-w-full" />
              <Skeleton className="h-4 w-64 max-w-full" />
            </div>
          )}
          {preview && (
            <div className="space-y-3">
              <StatGroup columns={4}>
                <Stat label="Decisions" value={preview.counts.decisions.toLocaleString()} caption="In scope" />
                <Stat label="Approvals" value={preview.counts.approvals.toLocaleString()} caption="In scope" />
                <Stat label="Alerts" value={preview.counts.alerts.toLocaleString()} caption="In scope" />
                <Stat label="Ledger entries" value={preview.counts.ledger.toLocaleString()} caption={`Disclosed of ${preview.integrity.entries.toLocaleString()} source entries`} />
              </StatGroup>
              <p className="font-mono text-xs break-all text-muted">
                Evidence key: {preview.evidence_key.fingerprint} · {preview.evidence_key.mode}
              </p>
              <p className="text-sm text-muted">{preview.executive_summary}</p>
            </div>
          )}
          <Button
            icon={Download}
            variant="primary"
            loading={busy === "generate"}
            disabled={!!busy || summary.isFetching || summary.isError || !preview?.integrity.ok || badRange}
            onClick={() =>
              act("generate", async () => {
                const result = await post<EvidenceReport>("/v1/evidence/reports", scope);
                await download(result.id);
                toast("success", "Signed report saved and downloaded", "Open report.html; verify_pack.py checks signatures and inclusion proofs. No Azure call was made.");
              })
            }
          >
            Generate and download scoped report
          </Button>
        </div>
      </Card>

      {preview && (
        <Card title="Control coverage" description="Evidence, not compliance verdicts" className="mb-6">
          <div className="grid gap-3 p-5 md:grid-cols-2">
            {preview.coverage.map((control) => (
              <div key={control.id} className="rounded-lg border border-line p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <strong className="text-fg">{control.id}</strong>
                  <Chip>{control.status.replaceAll("_", " ")}</Chip>
                  <span className="text-caption text-muted">{control.observed_records} records</span>
                </div>
                <p className="mt-2 text-sm font-medium text-fg">{control.title}</p>
                <p className="mt-1 text-xs text-muted">{control.limitations}</p>
                <details className="mt-2 text-xs">
                  <summary className={cx("cursor-pointer rounded text-muted", focusRing)}>Evidence queries and record citations</summary>
                  <div className="mt-2">
                    <JsonBlock value={control.sources} />
                  </div>
                </details>
                <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs">
                  {control.references.map((reference) => (
                    <a key={reference.framework} href={reference.source_url} target="_blank" rel="noreferrer" className={cx("rounded text-accent underline", focusRing)}>
                      {reference.name}: {reference.reference}
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card title="Automatic generation" className="mb-6 overflow-hidden">
        <div className="space-y-4 p-5">
          <p className="text-sm text-muted">
            Schedules use a rolling UTC interval, with the agent/task/framework scope above. The first report runs on the next worker pass. Missed intervals catch up after restart. Reports are
            stored in this database; no email or regulatory submission is sent.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <Select label="Evidence schedule interval" value={interval} onChange={setInterval} options={[{ value: "1", label: "Hourly" }, { value: "24", label: "Daily" }, { value: "168", label: "Weekly" }]} />
            <Button
              icon={CalendarClock}
              loading={busy === "schedule"}
              disabled={!!busy || !preview?.automation.enabled || !preview?.automation.persistent_key || !preview.integrity.ok || summary.isError}
              onClick={() =>
                act("schedule", async () => {
                  await post("/v1/evidence/schedules", {
                    name: `${framework} · ${agent || "all agents"} · ${interval}h`,
                    interval_hours: Number(interval),
                    scope: { agent_id: agent || null, root_id: root.trim() || null, framework },
                  });
                  toast("success", "Automatic report schedule created", `Worker checks every ${preview?.automation.check_seconds} seconds. No fixed dates are used.`);
                })
              }
            >
              Create schedule
            </Button>
            <Button
              disabled={!!busy}
              onClick={() =>
                act("due", async () => {
                  const result = await post<EvidenceReport[]>("/v1/evidence/schedules/run");
                  toast("success", "Due schedules checked", `${result.length} report slots processed.`);
                })
              }
            >
              Run due schedules now
            </Button>
          </div>
          {preview && (!preview.automation.enabled || !preview.automation.persistent_key) && (
            <Callout tone="warning">Scheduling requires an enabled worker, persistent database and persistent evidence key.</Callout>
          )}
        </div>
        <div className="border-t border-line">
          {schedules.isLoading ? (
            <SkeletonRows rows={2} cols={4} />
          ) : schedules.isError ? (
            <ErrorState title="Couldn't load schedules" error={schedules.error} onRetry={() => void schedules.refetch()} />
          ) : !schedules.data?.length ? (
            <EmptyState icon={CalendarClock} title="No schedules yet">
              Nothing is automatically exported until you create one.
            </EmptyState>
          ) : (
            <Table>
              <THead>
                <Th>Schedule</Th>
                <Th>Status</Th>
                <Th>Next run</Th>
                <Th>
                  <span className="sr-only">Actions</span>
                </Th>
              </THead>
              <TBody>
                {schedules.data.map((schedule) => (
                  <Tr key={schedule.id}>
                    <Td className="font-medium">{schedule.name}</Td>
                    <Td>
                      <Badge tone={schedule.enabled ? "good" : "neutral"}>{schedule.enabled ? "Enabled" : "Paused"}</Badge>
                    </Td>
                    <Td className="text-muted">{new Date(schedule.next_run_at).toLocaleString()}</Td>
                    <Td className="text-right">
                      <Button size="sm" disabled={!!busy} onClick={() => act(schedule.id, () => api(`/v1/evidence/schedules/${schedule.id}`, { method: "PATCH", body: { enabled: !schedule.enabled } }))}>
                        {schedule.enabled ? "Pause" : "Resume"}
                      </Button>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </div>
      </Card>

      <Card title="Saved report history" description="Signed ZIPs and metadata persist across restarts. An auditor review is an additional ledger event; it does not rewrite the signed artifact." className="mb-6 overflow-hidden">
        {reports.isLoading ? (
          <SkeletonRows rows={3} cols={5} />
        ) : reports.isError ? (
          <ErrorState title="Couldn't load saved reports" error={reports.error} onRetry={() => void reports.refetch()} />
        ) : !reports.data?.length ? (
          <EmptyState icon={ShieldCheck} title="No saved reports yet">
            Generate a report or create a schedule to begin.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <Th>Generated</Th>
              <Th>Source</Th>
              <Th>Status</Th>
              <Th>Report</Th>
              <Th>Review</Th>
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            </THead>
            <TBody>
              {reports.data.map((report) => (
                <Tr key={report.id}>
                  <Td className="whitespace-nowrap">{new Date(report.generated_at).toLocaleString()}</Td>
                  <Td className="text-muted">{report.schedule_id ? "Scheduled" : "On demand"}</Td>
                  <Td>
                    <Badge tone={report.status === "ready" ? "good" : report.error_code ? "critical" : "neutral"}>{titleCase(report.status)}</Badge>
                  </Td>
                  <Td className="font-mono text-xs text-muted">
                    {report.id} · {report.error_code || report.sha256.slice(0, 16)}
                  </Td>
                  <Td className={report.reviewed_by ? "text-good-ink" : "text-muted"}>{report.reviewed_by ? `Reviewed by ${report.reviewed_by}` : "Not reviewed"}</Td>
                  <Td>
                    <div className="flex justify-end gap-2">
                      <Button size="sm" disabled={!!busy || report.status !== "ready"} icon={Download} onClick={() => act(report.id, () => download(report.id))}>
                        Download
                      </Button>
                      <Button
                        size="sm"
                        icon={ShieldCheck}
                        disabled={report.status !== "ready"}
                        onClick={() => {
                          setReview(report);
                          setNote("");
                        }}
                      >
                        Inspect / review
                      </Button>
                    </div>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      <Drawer open={!!review} onClose={() => setReview(null)} title="Auditor evidence review">
        {review && (
          <div className="space-y-4">
            <p className="font-mono text-xs break-all text-muted">SHA-256 {review.sha256}</p>
            <JsonBlock value={review.summary} />
            {review.reviewed_by ? (
              <p className="text-sm text-fg">
                Reviewed by {review.reviewed_by}: {review.review_note}
              </p>
            ) : (
              <>
                <Field label="Review observations" hint="At least 10 characters. Recorded in the audit ledger.">
                  <Textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} rows={4} placeholder="What did you check, and what did you find?" />
                </Field>
                <Button
                  variant="primary"
                  disabled={!!busy || note.trim().length < 10}
                  onClick={() =>
                    act("review", async () => {
                      await post(`/v1/evidence/reports/${review.id}/review`, { note: note.trim() });
                      setReview(null);
                      toast("success", "Auditor review recorded", "The signed ZIP is unchanged; the review is linked to its SHA-256 in the audit ledger.");
                    })
                  }
                >
                  Record auditor review
                </Button>
              </>
            )}
          </div>
        )}
      </Drawer>
    </>
  );
}
