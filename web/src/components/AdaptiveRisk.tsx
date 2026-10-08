import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { Card, Meter, RiskPill } from "./ui";

interface Risk {
  score: number; tier: string;
  breakdown: { inherent: number; behavioural: number; posture: number; signals: { source?: string; reason: string; points: number }[] };
  baseline: { status: string; history_calls: number; observed_minutes: number; minimum_calls: number; minimum_minutes: number; median_calls_per_active_minute: number; robust_z_score: number | null; limitations: string };
}
export function AdaptiveRisk({ agentId }: { agentId: string }) {
  const risk = useQuery({ queryKey: ["adaptive-risk", agentId], queryFn: () => api<Risk>(`/v1/risk/${agentId}`), refetchInterval: 5000 });
  const r = risk.data;
  return <Card title="Adaptive risk from observed activity" className="xl:col-span-3">
    {!r ? <p className="p-5 text-muted">{risk.error?.message ?? "Calculating from recorded activity..."}</p> : <div className="grid gap-5 p-5 md:grid-cols-2">
      <div className="space-y-3">
        <p className="text-2xl font-semibold">{r.score} / 100 <RiskPill tier={r.tier} /></p>
        <Meter label="Inherent risk" value={r.breakdown.inherent} max={40} />
        <Meter label="Observed behaviour" value={r.breakdown.behavioural} max={40} />
        <Meter label="Identity / attestation posture" value={r.breakdown.posture} max={20} />
        <ul className="space-y-1 text-xs text-muted">{r.breakdown.signals.map((s, i) => <li key={i}>{s.reason}: +{s.points} {s.source && `(${s.source})`}</li>)}</ul>
      </div>
      <div className="space-y-2 text-sm text-muted">
        <p>Baseline: <strong className="text-fg">{r.baseline.status.replaceAll("_", " ")}</strong></p>
        <p>{r.baseline.history_calls} historical calls across {r.baseline.observed_minutes} completed active minutes.</p>
        <p>Needs at least {r.baseline.minimum_calls} calls across {r.baseline.minimum_minutes} completed minutes. No history is fabricated.</p>
        {r.baseline.status === "ready" && <p>Typical active minute: {r.baseline.median_calls_per_active_minute} calls. Current deviation: {r.baseline.robust_z_score} robust z-score.</p>}
        <p className="text-xs text-faint">{r.baseline.limitations} Effective enforcement never lowers an agent's existing risk tier.</p>
      </div>
    </div>}
  </Card>;
}
