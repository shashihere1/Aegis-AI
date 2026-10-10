import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Ban, KeyRound, Sigma } from "lucide-react";
import { api, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { personLabel } from "../lib/format";
import type { Mandate } from "../lib/types";
import { Button, Callout, Card, Chip, Countdown, EmptyState, ErrorState, PageHeader, SkeletonRows, StatusPill, TBody, THead, Table, TableToolbar, Tabs, Td, Th, TimeAgo, Tr, cx, focusRing } from "../components/ui";

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
      <PageHeader title="Agent access control" subtitle="Just-in-time Mandates: task-scoped, purpose-bound and short-lived. No agent holds standing access." />
      <Callout tone="info" icon={Sigma} title="Effective permission" className="mb-6">
        <span className="flex flex-wrap items-center gap-2">
          <Chip>agent capabilities</Chip>∩<Chip>initiating user's entitlements</Chip>∩<Chip>the task's purpose</Chip>
          <span>· delegation can only narrow it · default lifetime 5 min</span>
        </span>
      </Callout>
      <TableToolbar end={mandates.data && <span className="tabular">{mandates.data.length} mandates</span>}>
        <Tabs
          label="Mandate status"
          value={status}
          onChange={setStatus}
          tabs={[
            { value: "active", label: "Active" },
            { value: "completed", label: "Completed" },
            { value: "revoked", label: "Revoked" },
          ]}
        />
      </TableToolbar>
      <Card className="overflow-hidden">
        {mandates.isLoading ? (
          <SkeletonRows cols={6} />
        ) : mandates.isError ? (
          <ErrorState title="Couldn't load mandates" error={mandates.error} onRetry={() => void mandates.refetch()} />
        ) : !mandates.data?.length ? (
          <EmptyState icon={KeyRound} title={`No ${status} mandates`}>
            {status === "active" ? "Agents only hold access while a task is running. Run a scene to see Mandates appear and disappear." : undefined}
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <Th>Chain of accountability</Th>
              <Th>Intent</Th>
              <Th>Scope</Th>
              <Th>{status === "active" ? "Expires in" : "Issued"}</Th>
              <Th>Status</Th>
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            </THead>
            <TBody>
              {mandates.data.map((m) => (
                <Tr key={m.id}>
                  <Td>
                    <div className="flex flex-wrap items-center gap-1.5 text-sm">
                      <span className="text-muted">{personLabel(m.subject)}</span>
                      {m.chain_names.map((n, i) => (
                        <span key={i} className="flex items-center gap-1.5">
                          <ArrowRight className="size-3.5 text-faint" aria-hidden />
                          <Link to={`/agents/${m.chain[i]}`} className={cx("rounded hover:text-accent", focusRing, i === m.chain.length - 1 ? "font-medium text-fg" : "text-muted")}>
                            {n}
                          </Link>
                        </span>
                      ))}
                    </div>
                    <div className="mt-0.5 font-mono text-2xs text-muted">
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
                  <Td>{status === "active" ? <Countdown until={m.expires_at} /> : <span className="text-muted"><TimeAgo value={m.issued_at} /></span>}</Td>
                  <Td>
                    <StatusPill status={m.status} />
                    {m.revoked_reason && (
                      <div className="mt-1 max-w-56 truncate text-xs text-muted" title={m.revoked_reason}>
                        {m.revoked_reason}
                      </div>
                    )}
                  </Td>
                  <Td>
                    {status === "active" && (
                      <Button variant="danger" size="sm" icon={Ban} roles={["soc-analyst", "risk-approver"]} loading={revoke.isPending && revoke.variables === m.id} onClick={() => revoke.mutate(m.id)}>
                        Revoke
                      </Button>
                    )}
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}
