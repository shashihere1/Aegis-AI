import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { EyeOff, FlaskConical, ScanSearch, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { api, post } from "../lib/api";
import { useAlerts } from "../lib/queries";
import { timeAgo } from "../lib/format";
import type { GuardScan } from "../lib/types";
import { Button, Card, Chip, EmptyState, Kpi, Meter, PageHeader, Pill } from "../components/ui";

export function PromptInjection() {
  const alerts = useAlerts().data ?? [];
  const detections = alerts.filter((a) => a.rule_id === "DET-01");
  const blocked = alerts.filter((a) => a.rule_id === "DET-02");
  const samples = useQuery({ queryKey: ["samples"], queryFn: () => api<{ poisoned_document: string; passport: string }>("/demo/api/samples") });
  const [text, setText] = useState("");
  const scan = useMutation({ mutationFn: (t: string) => post<GuardScan>("/v1/guard/scan", { text: t }) });

  return (
    <>
      <PageHeader icon={ShieldAlert} title="Prompt Injection" subtitle="Hidden instructions found in tool output, documents and prompts, and what Aegis did about them" />
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Kpi icon={ShieldAlert} tone="serious" label="Injections detected" value={detections.length} />
        <Kpi icon={ShieldX} tone="critical" label="Exfiltration blocked" value={blocked.length} hint="IFC-001 lethal-trifecta breaker" />
        <Kpi icon={ShieldCheck} label="Enforcement" value="Deterministic" hint="Detection only adds a signal; policy blocks" />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <Card title="Detections">
          {!detections.length ? (
            <EmptyState icon={ShieldAlert} title="No injections detected yet">
              Run scene S4 from Demo Studio: a rental contract hides an instruction to e-mail customer records outside the bank.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-line">
              {detections.map((a) => {
                const findings = (a.evidence.findings as { rule: string; snippet: string; weight: number }[]) ?? [];
                const followUp = blocked.find((b) => b.agent_id === a.agent_id);
                return (
                  <li key={a.id} className="space-y-3 px-5 py-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm">{String(a.evidence.tool ?? "")}</span>
                      <span className="text-sm text-muted">→ {a.agent_name ?? a.agent_id}</span>
                      <span className="ml-auto text-xs text-faint">{timeAgo(a.ts)}</span>
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
                    <div className="flex flex-wrap gap-2">
                      <Pill tone="warning">Task tainted: external egress now blocked</Pill>
                      {followUp && <Pill tone="critical">Follow-up exfiltration denied · agent suspended</Pill>}
                      {typeof a.evidence.mandate_id === "string" && (
                        <Link to="/lineage" className="text-sm text-accent hover:underline">
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
              <Button variant="ghost" onClick={() => setText(samples.data?.poisoned_document ?? "")}>
                Poisoned contract
              </Button>
              <Button variant="ghost" onClick={() => setText(samples.data?.passport ?? "")}>
                Passport scan
              </Button>
            </div>
          }
        >
          <div className="space-y-4 p-5">
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={8}
              placeholder="Paste any text: a document, a web page, a tool description…"
              className="w-full rounded-lg border border-line-strong bg-inset p-3 font-mono text-sm outline-none focus:border-accent"
            />
            <Button variant="primary" icon={ScanSearch} disabled={!text.trim()} loading={scan.isPending} onClick={() => scan.mutate(text)}>
              Scan with the Guard
            </Button>
            {scan.data && (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  {scan.data.injection ? (
                    <Pill tone="critical" icon={ShieldX}>
                      Injection detected
                    </Pill>
                  ) : (
                    <Pill tone="good" icon={ShieldCheck}>
                      No injection pattern
                    </Pill>
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
                  <div className="mb-2 flex items-center gap-2 text-sm font-medium">
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
              <p className="flex items-start gap-2 text-xs text-faint">
                <FlaskConical className="mt-0.5 size-3.5 shrink-0" /> Uses the same heuristics and PII recognizers the Gateway applies to every untrusted tool output (BSN 11-proof, IBAN mod-97, e-mail, phone).
              </p>
            )}
          </div>
        </Card>
      </div>
    </>
  );
}
