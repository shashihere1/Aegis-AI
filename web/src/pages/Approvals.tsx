import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, BadgeCheck, CheckCircle2, Fingerprint, Info, Lock, XCircle } from "lucide-react";
import { api, post } from "../lib/api";
import { APPROVAL_READERS, usePendingApprovals } from "../lib/queries";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import { euro, personLabel, secondsUntil, shortHash } from "../lib/format";
import type { Approval } from "../lib/types";
import {
  Badge,
  Button,
  Card,
  Countdown,
  DLRow,
  DescriptionList,
  EmptyState,
  ErrorState,
  Field,
  PageHeader,
  SkeletonRows,
  Stat,
  StatGroup,
  StatusPill,
  TBody,
  THead,
  Table,
  Tabs,
  Td,
  TextInput,
  Th,
  TimeAgo,
  Tr,
  useNow,
} from "../components/ui";

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
  const left = secondsUntil(a.expires_at);

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-start gap-6 p-5">
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap gap-1.5">
            {a.reasons.map((r) => (
              <Badge key={r.rule} tone="warning">
                {r.rule}
              </Badge>
            ))}
          </div>
          {amount !== null ? (
            <div className="text-3xl font-semibold tracking-tight text-fg">{euro(amount)}</div>
          ) : (
            <div className="font-mono text-lg text-fg">{a.tool}</div>
          )}
          <p className="mt-1 text-sm text-muted">
            {a.reasons[0]?.message}
            {amount !== null && (
              <>
                {" · to "}
                <span className="font-mono">{String(args.creditor_iban)}</span>
                {args.new_beneficiary ? <span className="text-warning-ink"> · new beneficiary</span> : null}
              </>
            )}
          </p>
        </div>
        <div className="text-right">
          <div className="text-caption text-muted">Expires in</div>
          <div className={left <= 60 ? "text-lg font-semibold text-warning-ink" : "text-lg font-semibold text-fg"}>
            <Countdown until={a.expires_at} />
          </div>
        </div>
      </div>
      <DescriptionList className="border-t border-line px-5">
        <DLRow label="Requested for">
          <span className="flex flex-wrap items-center gap-1.5">
            {personLabel(a.subject)}
            {a.chain_names.map((n) => (
              <span key={n} className="flex items-center gap-1.5 text-muted">
                <ArrowRight className="size-3.5 text-faint" />
                {n}
              </span>
            ))}
          </span>
        </DLRow>
        <DLRow label="Tool">
          <span className="font-mono">{a.tool}</span>
        </DLRow>
        <DLRow label="Declared intent">{a.intent}</DLRow>
        <DLRow label="Bound to">
          <span className="inline-flex flex-wrap items-center gap-1.5">
            <Fingerprint className="size-3.5 text-muted" />
            <span className="font-mono text-xs">{shortHash(a.action_hash, 16)}</span>
            <span className="text-caption text-muted">tool + exact arguments + mandate, single use</span>
          </span>
        </DLRow>
      </DescriptionList>
      <div className="flex flex-wrap items-end gap-3 border-t border-line bg-inset/60 p-4">
        <div className="min-w-60 flex-1">
          <Field label="Justification" hint="Recorded in the evidence ledger with your decision">
            <TextInput value={justification} onChange={(e) => setJustification(e.target.value)} placeholder="Why this decision is right" />
          </Field>
        </div>
        <div className="flex gap-2 pb-6">
          <Button icon={XCircle} roles={["risk-approver"]} loading={decide.isPending && decide.variables === "reject"} onClick={() => decide.mutate("reject")}>
            Reject
          </Button>
          <Button variant="primary" icon={CheckCircle2} roles={["risk-approver"]} loading={decide.isPending && decide.variables === "approve"} onClick={() => decide.mutate("approve")}>
            Approve
          </Button>
        </div>
        {!persona?.roles.includes("risk-approver") && (
          <p className="flex w-full items-center gap-1.5 text-caption text-muted">
            <Info className="size-3.5" /> Sign in as Sanne Bakker (risk approver) to decide. Segregation of duties: the customer and the agent's owner can never approve.
          </p>
        )}
      </div>
    </Card>
  );
}

export function Approvals() {
  const { can } = useSession();
  const allowed = can(...APPROVAL_READERS);
  const [tab, setTab] = useState<"pending" | "all">("pending");
  const pending = usePendingApprovals(allowed);
  const history = useQuery({
    queryKey: ["approvals", "all"],
    queryFn: () => api<Approval[]>("/v1/approvals", { query: { status: "all" } }),
    enabled: allowed && tab === "all",
    refetchInterval: 3000,
  });
  useNow(5000);

  if (!allowed)
    return (
      <>
        <PageHeader title="Approvals" subtitle="High-impact actions wait here for a human. Each approval authorises one exact action, once." />
        <Card>
          <EmptyState icon={Lock} title="Approvals are visible to approvers, the SOC and auditors">
            Your role can't read the approval queue. Sign in as a risk approver, SOC analyst or auditor to see it.
          </EmptyState>
        </Card>
      </>
    );

  const waiting = pending.data ?? [];
  const value = waiting.reduce((sum, a) => sum + (typeof a.arguments.amount === "number" ? (a.arguments.amount as number) : 0), 0);
  const expiringSoon = waiting.filter((a) => {
    const left = secondsUntil(a.expires_at);
    return left > 0 && left <= 300;
  }).length;

  return (
    <>
      <PageHeader title="Approvals" subtitle="High-impact actions wait here for a human. Each approval authorises one exact action, once." />

      <StatGroup columns={3} className="mb-8">
        <Stat label="Waiting for a decision" tone="warning" value={pending.data ? waiting.length : "—"} caption={waiting.length ? "Oldest expires first" : "All clear"} />
        <Stat label="Value awaiting approval" value={pending.data ? euro(value) : "—"} caption="Sum of transfer amounts" />
        <Stat label="Expiring within 5 minutes" tone="critical" value={pending.data ? expiringSoon : "—"} caption={expiringSoon ? "Decide soon or the agent's request lapses" : "None urgent"} />
      </StatGroup>

      <Tabs
        variant="underline"
        label="Approvals"
        className="mb-6"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "pending", label: "Pending", count: pending.data?.length },
          { value: "all", label: "History" },
        ]}
      />

      {tab === "pending" ? (
        pending.isLoading ? (
          <Card>
            <SkeletonRows rows={3} cols={3} />
          </Card>
        ) : pending.isError ? (
          <Card>
            <ErrorState title="Couldn't load approvals" error={pending.error} onRetry={() => void pending.refetch()} />
          </Card>
        ) : !waiting.length ? (
          <Card>
            <EmptyState icon={BadgeCheck} title="Nothing waiting for approval">
              Confirm a high-value or new-beneficiary transfer in Bank Assistant to request independent approval.
            </EmptyState>
          </Card>
        ) : (
          <div className="space-y-4">
            {[...waiting]
              .sort((x, y) => x.expires_at.localeCompare(y.expires_at))
              .map((a) => (
                <ApprovalCard key={a.id} a={a} />
              ))}
          </div>
        )
      ) : (
        <Card className="overflow-hidden">
          {history.isError ? (
            <ErrorState title="Couldn't load approval history" error={history.error} onRetry={() => void history.refetch()} />
          ) : !history.data ? (
            <SkeletonRows cols={5} />
          ) : !history.data.length ? (
            <EmptyState icon={BadgeCheck} title="No approvals yet" />
          ) : (
            <Table>
              <THead>
                <Th>Requested</Th>
                <Th>Tool</Th>
                <Th numeric>Amount</Th>
                <Th>Status</Th>
                <Th>Decided by</Th>
                <Th>Justification</Th>
              </THead>
              <TBody>
                {history.data.map((a) => (
                  <Tr key={a.id}>
                    <Td className="text-muted">
                      <TimeAgo value={a.created_at} />
                    </Td>
                    <Td className="font-mono text-xs">{a.tool}</Td>
                    <Td numeric>{typeof a.arguments.amount === "number" ? euro(a.arguments.amount as number) : "—"}</Td>
                    <Td>
                      <StatusPill status={a.status} />
                    </Td>
                    <Td>{a.approver ?? <span className="text-muted">—</span>}</Td>
                    <Td className="max-w-xs truncate text-muted">{a.justification || "—"}</Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </Card>
      )}
    </>
  );
}
