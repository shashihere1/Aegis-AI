import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, ClipboardCheck, ShieldX, UserX } from "lucide-react";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import type { AgentPage } from "../lib/types";
import { Avatar, Button, Card, EmptyState, Loading, Modal, PageHeader, Select, StatusPill, Td, Th, Tabs } from "../components/ui";

export function Attestation() {
  const { persona, personas } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<"due" | "orphaned">("due");
  const [leaver, setLeaver] = useState(false);
  const [who, setWho] = useState("niels.vandijk");
  const list = useQuery({ queryKey: ["agents", "attestation", tab], queryFn: () => api<AgentPage>("/v1/agents", { query: { attestation: tab, limit: 100 } }), refetchInterval: 4000 });

  const done = (title: string, detail?: string) => {
    toast("success", title, detail);
    queryClient.invalidateQueries();
  };
  const fail = (e: Error) => toast("error", "Refused", e.message);
  const campaign = useMutation({ mutationFn: () => post<{ agents: number }>("/v1/attestations/campaign", { due_in_days: 14 }), onSuccess: (r) => done("Campaign started", `${r.agents} active agents must be re-attested by their owners within 14 days.`), onError: fail });
  const enforce = useMutation({ mutationFn: () => post<{ suspended: string[] }>("/v1/attestations/enforce"), onSuccess: (r) => done("Overdue attestations enforced", `${r.suspended.length} agents suspended.`), onError: fail });
  const attest = useMutation({ mutationFn: (id: string) => post(`/v1/agents/${id}/attest`), onSuccess: () => done("Attested", "Ownership and purpose confirmed."), onError: fail });
  const leave = useMutation({
    mutationFn: () => post<{ orphaned: string[] }>("/v1/idp-events/leaver", { username: who }),
    onSuccess: (r) => (setLeaver(false), done("Leaver processed", `${r.orphaned.length} agents are now orphaned and must be re-attested.`)),
    onError: fail,
  });

  return (
    <>
      <PageHeader
        icon={ClipboardCheck}
        title="Re-attestation"
        subtitle="Owners periodically confirm each agent is still needed, correctly scoped and owned"
        actions={
          <>
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
      <div className="mb-4">
        <Tabs value={tab} onChange={setTab} tabs={[{ value: "due", label: "Attestation due" }, { value: "orphaned", label: "Orphaned (owner left)" }]} />
      </div>
      <Card>
        {list.isLoading ? (
          <Loading />
        ) : !list.data?.items.length ? (
          <EmptyState icon={ClipboardCheck} title={tab === "due" ? "No attestations outstanding" : "No orphaned agents"}>
            Start a campaign (Sanne Bakker) or simulate an owner leaving (Platform Admin).
          </EmptyState>
        ) : (
          <table className="w-full">
            <thead className="border-b border-line bg-inset">
              <tr>
                <Th>Agent</Th>
                <Th>Owner</Th>
                <Th>Status</Th>
                <Th>Due</Th>
                <Th></Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {list.data.items.map((a) => (
                <tr key={a.id} className="hover:bg-hover">
                  <Td>
                    <button onClick={() => navigate(`/agents/${a.id}`)} className="font-medium text-accent hover:underline">
                      {a.name}
                    </button>
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
                    <Button
                      disabled={persona?.username !== a.owner}
                      title={persona?.username !== a.owner ? "Only the agent's owner can attest" : undefined}
                      loading={attest.isPending && attest.variables === a.id}
                      onClick={() => attest.mutate(a.id)}
                    >
                      Attest
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Modal open={leaver} onClose={() => setLeaver(false)} title="Simulate an owner leaving the bank">
        <p className="mb-4 text-sm text-muted">The IdP sends a leaver event. Their agents become orphaned (DET-12) and must be re-attested immediately. The persona can no longer sign in for the rest of this session.</p>
        <Select label="Owner" value={who} onChange={setWho} options={personas.map((p) => ({ value: p.username, label: p.name }))} className="w-full" />
        <div className="mt-5 flex justify-end">
          <Button variant="danger" loading={leave.isPending} onClick={() => leave.mutate()}>
            Process leaver
          </Button>
        </div>
      </Modal>
    </>
  );
}
