import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { euro } from "./format";
import { APPROVAL_READERS, useAlerts, useFindings, useLedgerVerify, usePendingApprovals, useStats } from "./queries";
import { useSession } from "./session";
import type { AgentPage, EvidenceReport, Tool } from "./types";

// "Needs your attention": the role-aware action queue on the Overview. Every source only queries when the
// signed-in role may read it (no silent 403 polling), and reuses the page's query keys so caches are shared.

export interface AttentionItem {
  id: string;
  tone: "critical" | "warning" | "info";
  title: string;
  detail?: string;
  to: string;
  cta: string;
  /** ISO time the item expires (approvals), shown as a countdown. */
  expiresAt?: string;
}

interface PolicyVersion {
  id: string;
  name: string;
  status: string;
  author: string;
  rules: { security: { required: boolean; approver: string | null } } | null;
}

const RANK = { critical: 0, warning: 1, info: 2 } as const;

export function useAttention(): { items: AttentionItem[]; loading: boolean } {
  const { can, persona } = useSession();
  const me = persona?.username;
  const ledger = useLedgerVerify();
  const approvals = usePendingApprovals(can(...APPROVAL_READERS));
  const stats = useStats();
  const alerts = useAlerts();
  const findings = useFindings();
  const owner = can("agent-owner", "admin");
  const due = useQuery({
    queryKey: ["agents", "attestation", "due"],
    queryFn: () => api<AgentPage>("/v1/agents", { query: { attestation: "due", limit: 100 } }),
    refetchInterval: 10000,
    enabled: owner,
  });
  const orphaned = useQuery({
    queryKey: ["agents", "attestation", "orphaned"],
    queryFn: () => api<AgentPage>("/v1/agents", { query: { attestation: "orphaned", limit: 100 } }),
    refetchInterval: 10000,
    enabled: can("admin"),
  });
  const tools = useQuery({ queryKey: ["tools"], queryFn: () => api<Tool[]>("/v1/tools"), refetchInterval: 10000, enabled: can("security-approver") });
  const policies = useQuery({
    queryKey: ["policy-versions"],
    queryFn: () => api<{ active_version: string; versions: PolicyVersion[] }>("/v1/policies/versions"),
    refetchInterval: 10000,
    enabled: can("policy-approver", "security-approver", "policy-author"),
  });
  const reports = useQuery({ queryKey: ["evidence-reports"], queryFn: () => api<EvidenceReport[]>("/v1/evidence/reports"), refetchInterval: 15000, enabled: can("auditor") });

  const items: AttentionItem[] = [];

  if (ledger.data && !ledger.data.ok)
    items.push({
      id: "ledger",
      tone: "critical",
      title: "Evidence ledger integrity broken",
      detail: `The hash chain breaks at entry #${ledger.data.broken_at_seq}. Audit evidence after this point can't be trusted.`,
      to: "/evidence",
      cta: "Investigate",
    });

  if (can("soc-analyst", "admin")) {
    const untriaged = (alerts.data ?? []).filter((a) => a.status === "new");
    const urgent = untriaged.filter((a) => a.severity === "critical" || a.severity === "high");
    for (const a of urgent.slice(0, 3))
      items.push({
        id: `alert-${a.id}`,
        tone: a.severity === "critical" ? "critical" : "warning",
        title: `${a.rule_id} · ${a.title}`,
        detail: `${a.severity === "critical" ? "Critical" : "High"} · ${a.agent_name ?? "unknown agent"} · not yet triaged`,
        to: "/alerts",
        cta: "Triage",
      });
    const rest = untriaged.length - Math.min(3, urgent.length);
    if (rest > 0) items.push({ id: "alerts-rest", tone: "info", title: `${rest} more untriaged alert${rest === 1 ? "" : "s"}`, detail: "Medium and low severity detections", to: "/alerts", cta: "Open" });
    const open = (findings.data ?? []).filter((f) => f.status === "open").length;
    if (open)
      items.push({
        id: "shadow",
        tone: "warning",
        title: `${open} unregistered agent${open === 1 ? "" : "s"} detected`,
        detail: "Shadow AI seen at the gateway or identity provider. Claim it or quarantine it.",
        to: "/shadow",
        cta: "Resolve",
      });
  }

  if (approvals.data?.length) {
    const act = can("risk-approver");
    for (const a of [...approvals.data].sort((x, y) => x.expires_at.localeCompare(y.expires_at)).slice(0, 3)) {
      const amount = typeof a.arguments.amount === "number" ? euro(a.arguments.amount as number) : null;
      items.push({
        id: `approval-${a.id}`,
        tone: "warning",
        title: amount ? `${amount} ${a.tool} waiting for approval` : `${a.tool} waiting for approval`,
        detail: a.reasons[0]?.message ?? "High-impact action held for a human decision",
        to: "/approvals",
        cta: act ? "Review" : "View",
        expiresAt: a.expires_at,
      });
    }
  }

  const pendingAgents = stats.data?.by_status.pending_approval ?? 0;
  if (can("risk-approver") && pendingAgents)
    items.push({
      id: "agents-pending",
      tone: "info",
      title: `${pendingAgents} agent${pendingAgents === 1 ? "" : "s"} awaiting registration approval`,
      detail: "Approval provisions a governed identity for the agent",
      to: "/agents?status=pending_approval",
      cta: "Review",
    });

  if (owner) {
    const mine = (due.data?.items ?? []).filter((a) => can("admin") || a.owner === me);
    if (mine.length)
      items.push({
        id: "attestation",
        tone: "warning",
        title: `${mine.length} of ${can("admin") ? "the" : "your"} agents due for re-attestation`,
        detail: mine.slice(0, 3).map((a) => a.name).join(", "),
        to: "/attestation",
        cta: "Attest",
      });
  }
  const orphans = orphaned.data?.items.length ?? 0;
  if (orphans)
    items.push({ id: "orphaned", tone: "warning", title: `${orphans} orphaned agent${orphans === 1 ? "" : "s"}`, detail: "The owner has left the bank. Reassign ownership.", to: "/attestation", cta: "Reassign" });

  const toolQueue = (tools.data ?? []).filter((t) => t.status === "pending" || t.status === "quarantined");
  if (toolQueue.length)
    items.push({
      id: "tools",
      tone: toolQueue.some((t) => t.status === "quarantined") ? "warning" : "info",
      title: `${toolQueue.length} MCP tool${toolQueue.length === 1 ? "" : "s"} need a security review`,
      detail: `${toolQueue.filter((t) => t.status === "quarantined").length} quarantined · ${toolQueue.filter((t) => t.status === "pending").length} pending approval`,
      to: "/tools",
      cta: "Review",
    });

  for (const v of policies.data?.versions ?? []) {
    const security = v.rules?.security;
    if (can("policy-approver") && v.status === "submitted")
      items.push({ id: `policy-approve-${v.id}`, tone: "info", title: `Policy "${v.name}" submitted for approval`, detail: `Authored by ${v.author}`, to: "/policies", cta: "Review" });
    else if (can("policy-approver") && v.status === "approved")
      items.push({ id: `policy-activate-${v.id}`, tone: "info", title: `Policy "${v.name}" approved, not yet active`, detail: "Activate it to start enforcing", to: "/policies", cta: "Activate" });
    if (can("security-approver") && security?.required && !security.approver && ["submitted", "approved"].includes(v.status))
      items.push({ id: `policy-security-${v.id}`, tone: "warning", title: `Policy "${v.name}" needs a security sign-off`, detail: "The rule change loosens or rewrites enforcement", to: "/policies", cta: "Sign off" });
    if (can("policy-author") && v.status === "draft" && v.author === me)
      items.push({ id: `policy-draft-${v.id}`, tone: "info", title: `Your draft "${v.name}" is not submitted`, detail: "Simulate and submit it for approval", to: "/policies", cta: "Continue" });
  }

  const unreviewed = (reports.data ?? []).filter((r) => r.status === "ready" && !r.reviewed_at).length;
  if (unreviewed)
    items.push({ id: "reports", tone: "info", title: `${unreviewed} evidence report${unreviewed === 1 ? "" : "s"} awaiting auditor review`, to: "/evidence", cta: "Review" });

  items.sort((a, b) => RANK[a.tone] - RANK[b.tone] || (a.expiresAt ?? "~").localeCompare(b.expiresAt ?? "~"));
  const loading = ledger.isPending || alerts.isPending;
  return { items, loading };
}
