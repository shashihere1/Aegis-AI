import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { EyeOff, FlaskConical, ScanSearch, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { api, post } from "../lib/api";
import { useAlerts } from "../lib/queries";
import { timeAgo } from "../lib/format";
import type { GuardScan } from "../lib/types";
import { Badge, Button, Callout, Card, Chip, EmptyState, ErrorState, Field, Meter, PageHeader, SkeletonRows, Stat, StatGroup, Textarea, cx, focusRing } from "../components/ui";

export function PromptInjection() {
  const alertsQuery = useAlerts();
  const alerts = alertsQuery.data ?? [];
  const detections = alerts.filter((a) => a.rule_id === "DET-01");
  const blocked = alerts.filter((a) => a.rule_id === "DET-02");
  const samples = useQuery({ queryKey: ["samples"], queryFn: () => api<{ poisoned_document: string; passport: string }>("/demo/api/samples") });
  const [text, setText] = useState("");
  const scan = useMutation({ mutationFn: (t: string) => post<GuardScan>("/v1/guard/scan", { text: t }) });
  const loaded = !!alertsQuery.data;

  return (
    <>
      <PageHeader title="Prompt injection" subtitle="Hidden instructions found in tool output, documents and prompts, and what Aegis did about them." />

      <StatGroup columns={3} className="mb-8">
        <Stat label="Injections detected" tone="serious" value={loaded ? detections.length : "—"} caption="All time" />
        <Stat label="Exfiltration blocked" tone="critical" value={loaded ? blocked.length : "—"} caption="IFC-001 lethal-trifecta breaker" />
        <Stat label="Enforcement" value="Deterministic" caption="Detection only adds a signal; policy blocks" />
      </StatGroup>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card title="Detections" className="overflow-hidden">
          {alertsQuery.isLoading ? (
            <SkeletonRows rows={3} cols={3} />
          ) : alertsQuery.isError ? (
            <ErrorState title="Couldn't load detections" error={alertsQuery.error} onRetry={() => void alertsQuery.refetch()} />
          ) : !detections.length ? (
            <EmptyState icon={ShieldAlert} title="No injections detected yet">
              The synthetic D-99 rental contract contains a hidden exfiltration instruction. Scan it below, or ask Bank Assistant to read it.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-line">
              {detections.map((a) => {
                const findings = (a.evidence.findings as { rule: string; snippet: string; weight: number }[]) ?? [];
                const followUp = blocked.find((b) => b.agent_id === a.agent_id);
                return (
                  <li key={a.id} className="space-y-3 px-5 py-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm text-fg">{String(a.evidence.tool ?? "")}</span>
                      <span className="text-sm text-muted">→ {a.agent_name ?? a.agent_id}</span>
                      <span className="ml-auto text-caption text-muted">{timeAgo(a.ts)}</span>
                    </div>
                    <Meter label="Injection score" value={Math.round(Number(a.evidence.score ?? 0) * 100)} max={100} />
                    <div className="space-y-1.5">
                      {findings.map((f, i) => (
                        <div key={i} className="rounded-lg border border-line bg-inset px-3 py-2 text-sm">
                          <span className="mr-2 font-mono text-xs text-serious-ink">{f.rule}</span>
                          <mark className="rounded bg-serious/20 px-1 text-fg">{f.snippet}</mark>
                        </div>
                      ))}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="warning">Task tainted: external egress now blocked</Badge>
                      {followUp && <Badge tone="critical">Follow-up exfiltration denied · agent suspended</Badge>}
                      {typeof a.evidence.mandate_id === "string" && (
                        <Link to="/lineage" className={cx("rounded text-sm text-accent hover:underline", focusRing)}>
                          View lineage →
                        </Link>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card
          title="Scan playground"
          action={
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" disabled={!samples.data} onClick={() => setText(samples.data?.poisoned_document ?? "")}>
                Poisoned contract
              </Button>
              <Button variant="ghost" size="sm" disabled={!samples.data} onClick={() => setText(samples.data?.passport ?? "")}>
                Passport scan
              </Button>
            </div>
          }
        >
          <div className="space-y-4 p-5">
            {samples.isError && (
              <Callout tone="warning" title="Sample texts unavailable">
                {samples.error instanceof Error ? samples.error.message : "The sample documents could not be loaded."} You can still paste your own text.
              </Callout>
            )}
            <Field label="Text to scan">
              <Textarea value={text} onChange={(e) => setText(e.target.value)} rows={8} placeholder="Paste any text: a document, a web page, a tool description…" className="font-mono" />
            </Field>
            <Button variant="primary" icon={ScanSearch} disabled={!text.trim()} loading={scan.isPending} onClick={() => scan.mutate(text)}>
              Scan with the Guard
            </Button>
            {scan.isError && (
              <Callout tone="critical" title="The scan failed">
                {scan.error instanceof Error ? scan.error.message : "Aegis could not scan this text. Try again."}
              </Callout>
            )}
            {scan.data && (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  {scan.data.injection ? (
                    <Badge tone="critical" icon={ShieldX}>
                      Injection detected
                    </Badge>
                  ) : (
                    <Badge tone="good" icon={ShieldCheck}>
                      No injection pattern
                    </Badge>
                  )}
                  <span className="text-sm text-muted">score {(scan.data.score * 100).toFixed(0)} / 100</span>
                </div>
                {scan.data.findings.map((f, i) => (
                  <div key={i} className="rounded-lg border border-line bg-inset px-3 py-2 text-sm">
                    <span className="mr-2 font-mono text-xs text-serious-ink">{f.rule}</span>
                    <mark className="rounded bg-serious/20 px-1 text-fg">{f.snippet}</mark>
                  </div>
                ))}
                <div>
                  <div className="mb-2 flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                    <EyeOff className="size-4 text-muted" /> PII found: {scan.data.pii_count}
                    <span className="flex flex-wrap gap-1">
                      {scan.data.pii.map((p, i) => (
                        <Chip key={i}>{p.entity}</Chip>
                      ))}
                    </span>
                  </div>
                  <pre className="max-h-56 overflow-auto rounded-lg border border-line bg-inset p-3 font-mono text-xs whitespace-pre-wrap text-muted">{scan.data.redacted}</pre>
                </div>
              </div>
            )}
            {!scan.data && (
              <p className="flex items-start gap-2 text-caption text-muted">
                <FlaskConical className="mt-0.5 size-3.5 shrink-0" /> Uses the same heuristics and PII recognizers the Gateway applies to every untrusted tool output (BSN 11-proof, IBAN mod-97, e-mail, phone).
              </p>
            )}
          </div>
        </Card>
      </div>
    </>
  );
}
