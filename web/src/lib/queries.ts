import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { AgentStats, Alert, Approval, DiscoveryStatus, Finding, IdentityStatus, LedgerVerify, SocSummary } from "./types";

// Shared, polled queries. Intervals are short because the console is the live view of the demo.

/** Roles the server lets read the approvals list (everyone else gets 403, so don't poll for them). */
export const APPROVAL_READERS = ["risk-approver", "soc-analyst", "auditor"];

/** Alert statuses that still need a human. */
export const UNRESOLVED = new Set(["new", "triage", "investigating"]);
export const isUnresolved = (a: Alert) => UNRESOLVED.has(a.status);

export const useStats = () => useQuery({ queryKey: ["stats"], queryFn: () => api<AgentStats>("/v1/agents/stats"), refetchInterval: 4000 });

export const useSummary = (minutes = 30) =>
  useQuery({
    queryKey: ["soc-summary", minutes],
    queryFn: () => api<SocSummary>("/v1/soc/summary", { query: { minutes } }),
    refetchInterval: minutes > 60 ? 10000 : 3000,
    placeholderData: keepPreviousData,
  });

export const usePendingApprovals = (enabled = true) =>
  useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: () => api<Approval[]>("/v1/approvals", { query: { status: "pending" } }),
    refetchInterval: 2500,
    enabled,
  });

export const useAlerts = () => useQuery({ queryKey: ["alerts"], queryFn: () => api<Alert[]>("/v1/alerts"), refetchInterval: 3000 });

export const useFindings = () => useQuery({ queryKey: ["findings"], queryFn: () => api<Finding[]>("/v1/discovery/findings"), refetchInterval: 5000 });

export const useLedgerVerify = () => useQuery({ queryKey: ["ledger-verify"], queryFn: () => api<LedgerVerify>("/v1/ledger/verify"), refetchInterval: 15000, staleTime: 5000 });

export const useDiscoveryStatus = () =>
  useQuery({ queryKey: ["discovery-status"], queryFn: () => api<DiscoveryStatus>("/v1/discovery/status"), refetchInterval: 10000 });

export function useIdentityStatus() {
  return useQuery({ queryKey: ["identity-status"], queryFn: () => api<IdentityStatus>("/v1/identity/status"), refetchInterval: 15000 });
}
