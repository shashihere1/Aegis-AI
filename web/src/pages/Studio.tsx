import { Link } from "react-router";
import { AlertOctagon, Ban, CheckCircle2, FileArchive, Hourglass, Play, RotateCcw, Sparkles } from "lucide-react";
import { useRuns, useStudioStatus } from "../lib/queries";
import { SCENES, useResetDemo, useRunScene } from "../lib/scenes";
import { clock } from "../lib/format";
import type { StudioStep } from "../lib/types";
import { Button, Card, EmptyState, PageHeader, Pill, StatusPill, cx } from "../components/ui";

const STEP = {
  ok: { icon: CheckCircle2, color: "text-good-ink" },
  denied: { icon: Ban, color: "text-critical-ink" },
  waiting: { icon: Hourglass, color: "text-warning-ink" },
  alert: { icon: AlertOctagon, color: "text-serious-ink" },
};

const RUN_TONE = { completed: "good", contained: "accent", blocked: "critical", waiting: "warning", running: "info" } as const;

function Step({ s }: { s: StudioStep }) {
  const k = STEP[s.status] ?? STEP.ok;
  return (
    <li className="flex gap-3">
      <k.icon className={cx("mt-0.5 size-4 shrink-0", k.color)} />
      <div className="min-w-0">
        <div className="text-sm">{s.label}</div>
        {s.detail && <div className="text-xs break-words text-muted">{s.detail}</div>}
      </div>
    </li>
  );
}

export function Studio() {
  const runs = useRuns().data ?? [];
  const status = useStudioStatus().data;
  const run = useRunScene();
  const reset = useResetDemo();

  return (
    <>
      <PageHeader
        icon={Sparkles}
        title="Demo Studio"
        subtitle="Run the storyline against the live system. Every scene uses the real APIs; watch the other pages react."
        actions={
          <Button icon={RotateCcw} loading={reset.isPending} onClick={() => reset.mutate()}>
            Reset demo
          </Button>
        }
      />
      {status && (
        <Card className="mb-5 flex flex-wrap items-center gap-x-6 gap-y-2 p-4 text-sm">
          {Object.entries(status.agents).map(([key, a]) => (
            <Link key={key} to={`/agents/${a.id}`} className="flex items-center gap-2 hover:text-accent">
              <span className="text-muted">{key}</span> <StatusPill status={a.status} />
            </Link>
          ))}
          <span className="flex items-center gap-2">
            <span className="text-muted">KYC server</span>
            <Pill tone={status.kyc_variant === "v1" ? "good" : "critical"}>{status.kyc_variant === "v1" ? "original" : "changed (rug pull)"}</Pill>
          </span>
          <span className="flex items-center gap-2">
            <span className="text-muted">E-mails that left the bank</span>
            <span className="font-semibold">{status.emails_sent}</span>
          </span>
        </Card>
      )}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1.1fr_1fr]">
        <div className="space-y-4">
          {SCENES.map((scene) => (
            <Card key={scene.key} className="p-5">
              <div className="flex items-start gap-4">
                <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent">
                  <scene.icon className="size-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="rounded-md bg-inset px-1.5 py-0.5 font-mono text-xs text-muted">{scene.code}</span>
                    <h3 className="font-semibold">{scene.title}</h3>
                  </div>
                  <p className="mt-1.5 text-sm text-muted">{scene.story}</p>
                  <p className="mt-2 text-xs text-accent">Proves: {scene.proves}</p>
                  {scene.next && <p className="mt-1 text-xs text-faint">Then: {scene.next}</p>}
                </div>
                <Button variant="primary" icon={Play} loading={run.isPending && run.variables?.key === scene.key} disabled={run.isPending} onClick={() => run.mutate(scene)}>
                  Run
                </Button>
              </div>
            </Card>
          ))}
          <Card className="p-5">
            <div className="flex items-start gap-4">
              <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-accent-soft text-accent">
                <FileArchive className="size-5" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="rounded-md bg-inset px-1.5 py-0.5 font-mono text-xs text-muted">S8</span>
                  <h3 className="font-semibold">Prove it with an evidence pack</h3>
                </div>
                <p className="mt-1.5 text-sm text-muted">
                  Switch to Eva Visser (Auditor), verify the ledger and download a portable report of this demo's
                  agents, mandates, decisions, approvals and alerts.
                </p>
                <p className="mt-2 text-xs text-accent">Proves: audit trail · human oversight · offline verification</p>
              </div>
              <Link to="/evidence" className="rounded-lg border border-line-strong bg-inset px-4 py-2 text-sm font-medium hover:bg-hover">
                Open audit →
              </Link>
            </div>
          </Card>
        </div>
        <Card title="Run log" className="h-fit">
          {!runs.length ? (
            <EmptyState icon={Sparkles} title="No scenes run yet">
              Start with S2, then S3 (approve it as Sanne Bakker), then the S4 attack.
            </EmptyState>
          ) : (
            <ul className="divide-y divide-line">
              {runs.map((r) => (
                <li key={r.id} className="space-y-3 px-5 py-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-muted">{r.scene}</span>
                    <span className="font-medium">{r.title}</span>
                    <Pill tone={RUN_TONE[r.status]}>{r.status}</Pill>
                    <span className="ml-auto text-xs text-faint">{clock(r.started_at)}</span>
                  </div>
                  <ol className="space-y-2">
                    {r.steps.map((s, i) => (
                      <Step key={i} s={s} />
                    ))}
                  </ol>
                  <div className="flex flex-wrap gap-3 text-sm">
                    {r.links.root_id && (
                      <Link to={`/lineage/${r.links.root_id}`} className="text-accent hover:underline">
                        Lineage →
                      </Link>
                    )}
                    {r.links.approval_id && r.status === "waiting" && (
                      <Link to="/approvals" className="text-warning-ink hover:underline">
                        Open approval →
                      </Link>
                    )}
                    {r.links.alert_ids?.length ? (
                      <Link to="/alerts" className="text-critical-ink hover:underline">
                        {r.links.alert_ids.length} alerts →
                      </Link>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
