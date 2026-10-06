import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Ban, KeyRound, Sigma } from "lucide-react";
import { api, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { personLabel, timeAgo } from "../lib/format";
import type { Mandate } from "../lib/types";
import { Button, Card, Chip, Countdown, EmptyState, Loading, PageHeader, StatusPill, Tabs, Td, Th } from "../components/ui";

function ScopeChips({ scopes }: { scopes: string[] }) {
  return (
    <div className="flex max-w-md flex-wrap gap-1">
      {scopes.map((s) => (
        <Chip key={s} mono>
          {s.startsWith("a2a:") ? "delegate" : s}
        </Chip>
      ))}
    </div>
  );
}

export function AccessControl() {
  const [status, setStatus] = useState<"active" | "completed" | "revoked">("active");
  const toast = useToast();
  const queryClient = useQueryClient();
  const mandates = useQuery({ queryKey: ["mandates", status], queryFn: () => api<Mandate[]>("/v1/mandates", { query: { status } }), refetchInterval: 2000 });
  const revoke = useMutation({
    mutationFn: (id: string) => post<{ revoked: string[] }>(`/v1/mandates/${id}/revoke`),
    onSuccess: (r) => (toast("success", "Mandate revoked", `${r.revoked.length} mandates in the tree revoked; every Gateway replica rejects them on the next call.`), queryClient.invalidateQueries()),
    onError: (e: Error) => toast("error", "Revoke refused", e.message),
  });

  return (
    <>
      <PageHeader icon={KeyRound} title="Agent Access Control" subtitle="Just-in-time Mandates: task-scoped, purpose-bound and short-lived. No agent holds standing access." />
      <Card className="mb-5 flex flex-wrap items-center gap-3 p-4 text-sm">
        <Sigma className="size-5 text-accent" />
        <span className="text-muted">Effective permission</span>
        <Chip>agent capabilities</Chip>∩<Chip>initiating user's entitlements</Chip>∩<Chip>the task's purpose</Chip>
        <span className="text-muted">· delegation can only narrow it · default lifetime 5 min</span>
      </Card>
      <div className="mb-4">
        <Tabs value={status} onChange={setStatus} tabs={[{ value: "active", label: "Active" }, { value: "completed", label: "Completed" }, { value: "revoked", label: "Revoked" }]} />
      </div>
      <Card className="overflow-x-auto">
        {mandates.isLoading ? (
          <Loading />
        ) : !mandates.data?.length ? (
          <EmptyState icon={KeyRound} title={`No ${status} mandates`}>
            {status === "active" ? "Agents only hold access while a task is running. Run a scene to see Mandates appear and disappear." : undefined}
          </EmptyState>
        ) : (
          <table className="w-full">
            <thead className="border-b border-line bg-inset">
              <tr>
                <Th>Chain of accountability</Th>
                <Th>Intent</Th>
                <Th>Scope</Th>
                <Th>{status === "active" ? "Expires in" : "Issued"}</Th>
                <Th>Status</Th>
                <Th></Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {mandates.data.map((m) => (
                <tr key={m.id} className="hover:bg-hover">
                  <Td>
                    <div className="flex flex-wrap items-center gap-1.5 text-sm">
                      <span className="text-muted">{personLabel(m.subject)}</span>
                      {m.chain_names.map((n, i) => (
                        <span key={i} className="flex items-center gap-1.5">
                          <ArrowRight className="size-3.5 text-faint" />
                          <Link to={`/agents/${m.chain[i]}`} className={i === m.chain.length - 1 ? "font-medium hover:text-accent" : "text-muted hover:text-accent"}>
                            {n}
                          </Link>
                        </span>
                      ))}
                    </div>
                    <div className="mt-0.5 font-mono text-[11px] text-faint">
                      {m.id}
                      {m.depth ? ` · delegated, depth ${m.depth}` : " · root"}
                    </div>
                  </Td>
                  <Td className="max-w-64">
                    <div className="line-clamp-2 text-sm">{m.intent}</div>
                  </Td>
                  <Td>
                    <ScopeChips scopes={m.scopes} />
                  </Td>
                  <Td>{status === "active" ? <Countdown until={m.expires_at} /> : <span className="text-muted">{timeAgo(m.issued_at)}</span>}</Td>
                  <Td>
                    <StatusPill status={m.status} />
                    {m.revoked_reason && <div className="mt-1 max-w-56 truncate text-xs text-faint" title={m.revoked_reason}>{m.revoked_reason}</div>}
                  </Td>
                  <Td>
                    {status === "active" && (
                      <Button variant="danger" icon={Ban} roles={["soc-analyst", "risk-approver"]} loading={revoke.isPending && revoke.variables === m.id} onClick={() => revoke.mutate(m.id)}>
                        Revoke
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
