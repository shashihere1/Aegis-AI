import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, BadgeCheck, CheckCircle2, Fingerprint, Hourglass, XCircle } from "lucide-react";
import { api, post } from "../lib/api";
import { usePendingApprovals } from "../lib/queries";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import { euro, personLabel, shortHash, timeAgo } from "../lib/format";
import type { Approval } from "../lib/types";
import { Button, Card, Countdown, EmptyState, Loading, PageHeader, StatusPill, Tabs, Td, TextInput, Th } from "../components/ui";

function ApprovalCard({ a }: { a: Approval }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const { persona } = useSession();
  const [justification, setJustification] = useState("");
  const decide = useMutation({
    mutationFn: (verdict: "approve" | "reject") => post(`/v1/approvals/${a.id}/${verdict}`, { justification }),
    onSuccess: (_r, verdict) => {
      toast("success", verdict === "approve" ? "Approved" : "Rejected", verdict === "approve" ? "The waiting agent resumes with an approval bound to exactly this action." : undefined);
      queryClient.invalidateQueries();
    },
    onError: (e: Error) => toast("error", "Aegis refused this decision", e.message),
  });
  const args = a.arguments as Record<string, unknown>;
  const amount = typeof args.amount === "number" ? args.amount : null;

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-start gap-6 border-b border-line p-5">
        <div className="min-w-0 flex-1">
          <div className="mb-1 flex items-center gap-2 text-sm text-warning-ink">
            <Hourglass className="size-4" /> {a.reasons.map((r) => r.rule).join(", ")} · {a.reasons[0]?.message}
          </div>
          {amount !== null ? (
            <div className="text-4xl font-semibold tracking-tight">{euro(amount)}</div>
          ) : (
            <div className="font-mono text-lg">{a.tool}</div>
          )}
          {amount !== null && (
            <div className="mt-1 font-mono text-sm text-muted">
              to {String(args.creditor_iban)} {args.new_beneficiary ? <span className="font-sans text-warning-ink">· new beneficiary</span> : null}
            </div>
          )}
        </div>
        <div className="text-right text-sm">
          <div className="text-muted">Expires in</div>
          <div className="text-lg font-medium">
            <Countdown until={a.expires_at} />
          </div>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-x-8 gap-y-3 p-5 text-sm md:grid-cols-2">
        <div>
          <div className="text-xs font-semibold tracking-wide text-muted uppercase">Requested for</div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            {personLabel(a.subject)}
            {a.chain_names.map((n) => (
              <span key={n} className="flex items-center gap-1.5">
                <ArrowRight className="size-3.5 text-faint" />
                {n}
              </span>
            ))}
          </div>
        </div>
        <div>
          <div className="text-xs font-semibold tracking-wide text-muted uppercase">Tool</div>
          <div className="mt-1 font-mono">{a.tool}</div>
        </div>
        <div>
          <div className="text-xs font-semibold tracking-wide text-muted uppercase">Declared intent</div>
          <div className="mt-1">{a.intent}</div>
        </div>
        <div>
          <div className="text-xs font-semibold tracking-wide text-muted uppercase">Bound to</div>
          <div className="mt-1 flex items-center gap-1.5 font-mono text-xs text-muted">
            <Fingerprint className="size-3.5" /> {shortHash(a.action_hash, 16)}
            <span className="font-sans">(tool + exact arguments + mandate; single use)</span>
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-3 border-t border-line bg-inset p-4">
        <TextInput value={justification} onChange={(e) => setJustification(e.target.value)} placeholder="Justification (recorded in the ledger)" className="max-w-md flex-1" />
        <div className="ml-auto flex gap-2">
          <Button icon={XCircle} roles={["risk-approver"]} loading={decide.isPending && decide.variables === "reject"} onClick={() => decide.mutate("reject")}>
            Reject
          </Button>
          <Button variant="primary" icon={CheckCircle2} roles={["risk-approver"]} loading={decide.isPending && decide.variables === "approve"} onClick={() => decide.mutate("approve")}>
            Approve
          </Button>
        </div>
        {!persona?.roles.includes("risk-approver") && <div className="w-full text-xs text-faint">Switch to Sanne Bakker (risk approver) to decide. Segregation of duties: the customer and the agents' owner can never approve.</div>}
      </div>
    </Card>
  );
}

export function Approvals() {
  const [tab, setTab] = useState<"pending" | "all">("pending");
  const pending = usePendingApprovals();
  const history = useQuery({ queryKey: ["approvals", "all"], queryFn: () => api<Approval[]>("/v1/approvals", { query: { status: "all" } }), enabled: tab === "all", refetchInterval: 3000 });

  return (
    <>
      <PageHeader icon={BadgeCheck} title="Approvals" subtitle="High-impact actions wait here for a human. Each approval authorises one exact action, once." />
      <div className="mb-4">
        <Tabs value={tab} onChange={setTab} tabs={[{ value: "pending", label: `Pending (${pending.data?.length ?? 0})` }, { value: "all", label: "History" }]} />
      </div>
      {tab === "pending" ? (
        pending.isLoading ? (
          <Loading />
        ) : !pending.data?.length ? (
          <Card>
            <EmptyState icon={BadgeCheck} title="Nothing waiting for approval">
              Run scene S3 (€25,000 transfer) from Demo Studio.
            </EmptyState>
          </Card>
        ) : (
          <div className="space-y-4">
            {pending.data.map((a) => (
              <ApprovalCard key={a.id} a={a} />
            ))}
          </div>
        )
      ) : (
        <Card className="overflow-x-auto">
          {!history.data ? (
            <Loading />
          ) : (
            <table className="w-full">
              <thead className="border-b border-line bg-inset">
                <tr>
                  <Th>Requested</Th>
                  <Th>Tool</Th>
                  <Th>Details</Th>
                  <Th>Status</Th>
                  <Th>Decided by</Th>
                  <Th>Justification</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {history.data.map((a) => (
                  <tr key={a.id}>
                    <Td className="text-muted">{timeAgo(a.created_at)}</Td>
                    <Td className="font-mono text-xs">{a.tool}</Td>
                    <Td>{typeof a.arguments.amount === "number" ? euro(a.arguments.amount as number) : "—"}</Td>
                    <Td>
                      <StatusPill status={a.status} />
                    </Td>
                    <Td>{a.approver ?? "—"}</Td>
                    <Td className="text-muted">{a.justification || "—"}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </>
  );
}
