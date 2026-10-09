import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { AgentStats, Alert, Approval, Finding, SocSummary, StudioRun, StudioStatus, IdentityStatus } from "./types";

// Shared, polled queries. Intervals are short because the console is the live view of the demo.

export const useStats = () => useQuery({ queryKey: ["stats"], queryFn: () => api<AgentStats>("/v1/agents/stats"), refetchInterval: 4000 });

export const useSummary = () => useQuery({ queryKey: ["soc-summary"], queryFn: () => api<SocSummary>("/v1/soc/summary"), refetchInterval: 3000 });

export const usePendingApprovals = () =>
  useQuery({ queryKey: ["approvals", "pending"], queryFn: () => api<Approval[]>("/v1/approvals", { query: { status: "pending" } }), refetchInterval: 2500 });

export const useAlerts = () => useQuery({ queryKey: ["alerts"], queryFn: () => api<Alert[]>("/v1/alerts"), refetchInterval: 3000 });

export const useFindings = () => useQuery({ queryKey: ["findings"], queryFn: () => api<Finding[]>("/v1/discovery/findings"), refetchInterval: 5000 });

export const useRuns = () => useQuery({ queryKey: ["studio-runs"], queryFn: () => api<StudioRun[]>("/demo/api/runs"), refetchInterval: 1000 });

export const useStudioStatus = () => useQuery({ queryKey: ["studio-status"], queryFn: () => api<StudioStatus>("/demo/api/status"), refetchInterval: 2500 });

export function useIdentityStatus() {
  return useQuery({ queryKey: ["identity-status"], queryFn: () => api<IdentityStatus>("/v1/identity/status"), refetchInterval: 15000 });
}
