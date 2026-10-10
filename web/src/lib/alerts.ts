import type { Alert } from "./types";

export const DETECTIONS: Record<string, string> = {
  "DET-01": "Prompt injection detected in tool output",
  "DET-02": "Exfiltration attempt blocked (lethal trifecta)",
  "DET-03": "Tool definition drift (possible rug pull)",
  "DET-04": "Burst of denied actions",
  "DET-05": "Revoked or expired mandate presented",
  "DET-07": "Unregistered agent activity",
  "DET-08": "Call-rate deviation from the observed baseline",
  "DET-09": "First-time tool use relative to recorded history",
  "DET-12": "Orphaned agent (owner left)",
  "DET-13": "Adaptive risk reached the critical tier",
  "DET-14": "Agent attestation overdue (owner has not re-confirmed)",
};

/**
 * What the playbook already did about an alert, in words. Not every response carries a blast radius
 * (an orphaned-agent alert records an owner reassignment instead), so read it defensively.
 */
export function responseSummary(alert: Alert): { text: string; tone: "critical" | "neutral" } | null {
  const act = alert.actions_taken[0];
  if (!act) return null;
  const radius = act.blast_radius;
  if (radius?.mandates) return { text: `Agent suspended · ${radius.mandates.length} mandate${radius.mandates.length === 1 ? "" : "s"} revoked`, tone: "critical" };
  if (act.action === "owner_reassigned") return { text: `Owner reassigned${act.to ? ` to ${act.to}` : ""}`, tone: "neutral" };
  return { text: act.action.replace(/_/g, " "), tone: "neutral" };
}
