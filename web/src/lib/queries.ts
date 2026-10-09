import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { AgentStats, Alert, Approval, DiscoveryStatus, Finding, SocSummary, IdentityStatus } from "./types";

// Shared, polled queries. Intervals are short because the console is the live view of the demo.

export const useStats = () => useQuery({ queryKey: ["stats"], queryFn: () => api<AgentStats>("/v1/agents/stats"), refetchInterval: 4000 });

export const useSummary = () => useQuery({ queryKey: ["soc-summary"], queryFn: () => api<SocSummary>("/v1/soc/summary"), refetchInterval: 3000 });

export const usePendingApprovals = () =>
  useQuery({ queryKey: ["approvals", "pending"], queryFn: () => api<Approval[]>("/v1/approvals", { query: { status: "pending" } }), refetchInterval: 2500 });

export const useAlerts = () => useQuery({ queryKey: ["alerts"], queryFn: () => api<Alert[]>("/v1/alerts"), refetchInterval: 3000 });

export const useFindings = () => useQuery({ queryKey: ["findings"], queryFn: () => api<Finding[]>("/v1/discovery/findings"), refetchInterval: 5000 });

export const useDiscoveryStatus = () =>
  useQuery({ queryKey: ["discovery-status"], queryFn: () => api<DiscoveryStatus>("/v1/discovery/status"), refetchInterval: 10000 });


export function useIdentityStatus() {
  return useQuery({ queryKey: ["identity-status"], queryFn: () => api<IdentityStatus>("/v1/identity/status"), refetchInterval: 15000 });
}
