import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, ClipboardCheck, Play, ShieldX, UserCog, UserX } from "lucide-react";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import type { Agent, AgentPage, AttestationStatus } from "../lib/types";
import { Tooltip, TooltipContent, TooltipTrigger } from "../components/shadcn/tooltip";
import { Avatar, Button, Callout, Card, EmptyState, ErrorState, Field, Modal, PageHeader, RowLink, Select, SkeletonRows, Stat, StatGroup, StatusPill, TBody, THead, Table, Tabs, Td, TextInput, Th, Tr, cx, focusRing } from "../components/ui";

export function Attestation() {
  const { persona, personas } = useSession();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<"due" | "orphaned">("due");
  const [leaver, setLeaver] = useState(false);
  const [who, setWho] = useState("niels.vandijk");
  const [handOver, setHandOver] = useState<Agent | null>(null);
  const [newOwner, setNewOwner] = useState("");
  const [reason, setReason] = useState("");
  const list = useQuery({ queryKey: ["agents", "attestation", tab], queryFn: () => api<AgentPage>("/v1/agents", { query: { attestation: tab, limit: 100 } }), refetchInterval: 4000 });
  const status = useQuery({ queryKey: ["attestation-status"], queryFn: () => api<AttestationStatus>("/v1/attestations/status"), refetchInterval: 4000 });

  const done = (title: string, detail?: string) => {
    toast("success", title, detail);
    queryClient.invalidateQueries();
  };
  const fail = (e: Error) => toast("error", "Refused", e.message);
  const campaign = useMutation({ mutationFn: () => post<{ agents: number }>("/v1/attestations/campaign", { due_in_days: 14 }), onSuccess: (r) => done("Campaign started", `${r.agents} active agents must be re-attested by their owners within 14 days.`), onError: fail });
  const enforce = useMutation({ mutationFn: () => post<{ suspended: string[] }>("/v1/attestations/enforce"), onSuccess: (r) => done("Overdue attestations enforced", `${r.suspended.length} agents suspended.`), onError: fail });
  const runSchedule = useMutation({
    mutationFn: () => post<{ opened: string[]; flagged: string[]; suspended: string[] }>("/v1/attestations/run"),
    onSuccess: (r) => done("Schedule run", `${r.opened.length} agents became due, ${r.flagged.length} overdue alerts raised, ${r.suspended.length} suspended.`),
    onError: fail,
  });
  const attest = useMutation({ mutationFn: (id: string) => post(`/v1/agents/${id}/attest`), onSuccess: () => done("Attested", "Ownership and purpose confirmed."), onError: fail });
  const leave = useMutation({
    mutationFn: () => post<{ orphaned: string[] }>("/v1/idp-events/leaver", { username: who }),
    onSuccess: (r) => (setLeaver(false), done("Leaver processed", `${r.orphaned.length} agents are now orphaned and must be re-attested.`)),
    onError: fail,
  });
  const reassign = useMutation({
    mutationFn: () => post<Agent>(`/v1/agents/${handOver?.id}/owner`, { new_owner: newOwner.trim(), reason: reason.trim() }),
    onSuccess: (a) => {
      setHandOver(null);
      setNewOwner("");
      setReason("");
      done("Owner reassigned", `${a.name} now belongs to ${a.owner}, who must re-attest it.`);
    },
    onError: fail,
  });

  const s = status.data;
  const schedule = !s
    ? null
    : s.interval_days > 0
      ? `Every ${s.interval_days} days, with ${s.grace_days} days to confirm. ${s.auto_enforce ? "Overdue agents are suspended automatically." : "Overdue agents raise an alert; a person decides."}${s.scheduler_running ? "" : " The background job is not running in this deployment; use Run schedule now."}`
      : `No schedule: campaigns are started by hand.${s.auto_enforce ? " Overdue agents are suspended automatically." : ""}`;

  return (
    <>
      <PageHeader
        title="Re-attestation"
        subtitle="Owners periodically confirm each agent is still needed, correctly scoped and owned"
        actions={
          <>
            <Button icon={Play} roles={["risk-approver", "admin"]} loading={runSchedule.isPending} onClick={() => runSchedule.mutate()}>
              Run schedule now
            </Button>
            <Button icon={CalendarClock} roles={["risk-approver", "admin"]} loading={campaign.isPending} onClick={() => campaign.mutate()}>
              Start campaign
            </Button>
            <Button icon={ShieldX} roles={["risk-approver", "admin"]} loading={enforce.isPending} onClick={() => enforce.mutate()}>
              Enforce overdue
            </Button>
            <Button variant="danger" icon={UserX} roles={["admin"]} onClick={() => setLeaver(true)}>
              Simulate owner leaving
            </Button>
          </>
        }
      />
      {status.isError ? (
        <Callout
          tone="critical"
          title="Couldn't load the attestation status"
          className="mb-6"
          action={
            <Button size="sm" onClick={() => void status.refetch()}>
              Try again
            </Button>
          }
        >
          {status.error instanceof Error ? status.error.message : "The attestation schedule is unavailable."}
        </Callout>
      ) : (
        <>
          <StatGroup className="mb-6">
            <Stat label="Active agents" value={s ? s.active_agents : "—"} caption="In scope for attestation" />
            <Stat label="Due" tone="warning" value={s ? s.due : "—"} caption={s?.next_due ? `Next deadline ${new Date(s.next_due).toLocaleDateString()}` : "Owner must re-confirm"} />
            <Stat label="Overdue" tone="critical" value={s ? s.overdue : "—"} caption="Past the grace period" />
            <Stat label="Orphaned" tone="critical" value={s ? s.orphaned : "—"} caption="Owner has left" />
          </StatGroup>
          {schedule && (
            <Callout tone="info" title="Schedule" className="mb-8">
              {schedule}
            </Callout>
          )}
        </>
      )}
      <Tabs
        variant="underline"
        label="Attestation view"
        className="mb-6"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "due", label: "Attestation due" },
          { value: "orphaned", label: "Orphaned (owner left)" },
        ]}
      />
      <Card className="overflow-hidden">
        {list.isLoading ? (
          <SkeletonRows cols={5} />
        ) : list.isError ? (
          <ErrorState title="Couldn't load agents" error={list.error} onRetry={() => void list.refetch()} />
        ) : !list.data?.items.length ? (
          <EmptyState icon={ClipboardCheck} title={tab === "due" ? "No attestations outstanding" : "No orphaned agents"}>
            Start a campaign (Sanne Bakker) or simulate an owner leaving (Platform Admin).
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <Th>Agent</Th>
              <Th>Owner</Th>
              <Th>Status</Th>
              <Th>Due</Th>
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            </THead>
            <TBody>
              {list.data.items.map((a) => {
                const notOwner = persona?.username !== a.owner;
                const attestButton = (
                  <Button size="sm" disabled={notOwner} loading={attest.isPending && attest.variables === a.id} onClick={() => attest.mutate(a.id)}>
                    Attest
                  </Button>
                );
                return (
                  <Tr key={a.id}>
                    <Td>
                      <RowLink to={`/agents/${a.id}`}>{a.name}</RowLink>
                      {a.orphaned && <div className="text-xs text-critical-ink">Owner has left: reassign or retire</div>}
                    </Td>
                    <Td>
                      <span className="flex items-center gap-2">
                        <Avatar name={a.owner} size="sm" /> {a.owner}
                      </span>
                    </Td>
                    <Td>
                      <StatusPill status={a.status} />
                    </Td>
                    <Td className="text-muted">{a.attestation_due ? new Date(a.attestation_due).toLocaleDateString() : "—"}</Td>
                    <Td className="text-right">
                      <span className="inline-flex gap-2">
                        <Button size="sm" icon={UserCog} roles={["agent-owner", "risk-approver", "admin"]} onClick={() => setHandOver(a)}>
                          Reassign owner
                        </Button>
                        {notOwner ? (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span tabIndex={0} className={cx("inline-flex rounded-lg", focusRing)}>
                                {attestButton}
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>Only the agent's owner can attest</TooltipContent>
                          </Tooltip>
                        ) : (
                          attestButton
                        )}
                      </span>
                    </Td>
                  </Tr>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>
      <Modal open={leaver} onClose={() => setLeaver(false)} title="Simulate an owner leaving the bank">
        <p className="mb-4 text-sm text-muted">The IdP sends a leaver event. Their agents become orphaned (DET-12) and must be re-attested immediately. The persona can no longer sign in for the rest of this session.</p>
        <Field label="Owner">
          <Select label="Owner" value={who} onChange={setWho} options={personas.map((p) => ({ value: p.username, label: p.name }))} className="w-full" />
        </Field>
        <div className="mt-5 flex justify-end">
          <Button variant="danger" loading={leave.isPending} onClick={() => leave.mutate()}>
            Process leaver
          </Button>
        </div>
      </Modal>
      <Modal open={handOver !== null} onClose={() => setHandOver(null)} title={`Reassign ${handOver?.name ?? "agent"}`}>
        <p className="mb-4 text-sm text-muted">
          The agent keeps running under its new owner, who must re-attest it within the grace period. Currently owned by {handOver?.owner}. You cannot make yourself the owner (SOD-004), and the new owner must not have left.
        </p>
        <div className="space-y-4">
          <Field label="New owner (username)">
            <TextInput value={newOwner} onChange={(e) => setNewOwner(e.target.value)} placeholder="e.g. niels.vandijk" />
          </Field>
          <Field label="Reason (recorded in the ledger)" hint="At least 5 characters">
            <TextInput value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Previous owner left the bank" />
          </Field>
        </div>
        <div className="mt-5 flex justify-end">
          <Button variant="primary" icon={UserCog} loading={reassign.isPending} disabled={!newOwner.trim() || reason.trim().length < 5} onClick={() => reassign.mutate()}>
            Reassign owner
          </Button>
        </div>
      </Modal>
    </>
  );
}
