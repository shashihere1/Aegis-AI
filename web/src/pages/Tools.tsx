import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertOctagon, Lock, Plug, ShieldBan, ShieldCheck } from "lucide-react";
import { api, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { shortHash, titleCase } from "../lib/format";
import type { McpServer, Tool } from "../lib/types";
import { Button, Card, Chip, DataClassPill, EmptyState, Loading, Modal, PageHeader, Pill, StatusPill, Td, Th, cx } from "../components/ui";

export function Tools() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const servers = useQuery({ queryKey: ["servers"], queryFn: () => api<McpServer[]>("/v1/mcp/servers") });
  const tools = useQuery({ queryKey: ["tools"], queryFn: () => api<Tool[]>("/v1/tools"), refetchInterval: 3000 });
  const [server, setServer] = useState<string>("");
  const [override, setOverride] = useState<Tool | null>(null);
  const approve = useMutation({
    mutationFn: ({ id, force }: { id: string; force?: boolean }) => post(`/v1/tools/${id}/approve${force ? "?override=true" : ""}`),
    onSuccess: () => (toast("success", "Tool approved", "Its current definition is now pinned."), setOverride(null), queryClient.invalidateQueries({ queryKey: ["tools"] })),
    onError: (e: Error, v) => {
      const tool = tools.data?.find((t) => t.id === v.id);
      if (tool?.poisoning_findings.length && !v.force) setOverride(tool);
      else toast("error", "Approval refused", e.message);
    },
  });
  const quarantine = useMutation({
    mutationFn: (id: string) => post(`/v1/tools/${id}/quarantine`),
    onSuccess: () => (toast("success", "Tool quarantined", "Hidden from tools/list and uncallable for every agent."), queryClient.invalidateQueries({ queryKey: ["tools"] })),
    onError: (e: Error) => toast("error", "Quarantine refused", e.message),
  });

  if (servers.isLoading || tools.isLoading) return <Loading />;
  const activeServers = (servers.data ?? []).filter(s => s.status === "active");
  const activeIds = new Set(activeServers.map(s => s.id));
  const all = (tools.data ?? []).filter(t => activeIds.has(t.server_id));
  const shown = server ? all.filter((t) => t.server_id === server) : all;

  return (
    <>
      <PageHeader icon={Plug} title="MCP Servers & Tools" subtitle="Every tool an agent can reach: classified by its owner, pinned at approval, quarantined on drift" />
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4 2xl:grid-cols-7">
        {activeServers.map((s) => {
          const ts = all.filter((t) => t.server_id === s.id);
          const bad = ts.filter((t) => t.status !== "approved").length;
          return (
            <button
              key={s.id}
              onClick={() => setServer(server === s.id ? "" : s.id)}
              className={cx("rounded-xl border bg-card p-4 text-left transition hover:bg-hover", server === s.id ? "border-accent/60" : "border-line")}
            >
              <div className="flex items-center gap-2">
                <Plug className="size-4 text-accent" />
                <span className="font-medium">{s.id}</span>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs text-muted">
                <span>{ts.length} {ts.length === 1 ? "tool" : "tools"}</span>
                {s.vendor !== "internal" && <Pill tone="warning">third-party</Pill>}
                {bad > 0 && <Pill tone="critical">{bad} blocked</Pill>}
              </div>
            </button>
          );
        })}
      </div>
      <Card className="overflow-x-auto">
        {!shown.length ? (
          <EmptyState icon={Plug} title="No tools" />
        ) : (
          <table className="w-full">
            <thead className="border-b border-line bg-inset">
              <tr>
                <Th>Tool</Th>
                <Th>Classification (authoritative)</Th>
                <Th>Returns</Th>
                <Th>Pin</Th>
                <Th>Status</Th>
                <Th></Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {shown.map((t) => {
                const drift = t.approved_hash && t.approved_hash !== t.definition_hash;
                const c = t.classification;
                return (
                  <tr key={t.id} className="align-top hover:bg-hover">
                    <Td className="max-w-80">
                      <div className="font-mono text-sm font-medium">{t.id}</div>
                      <div className="mt-0.5 line-clamp-2 text-xs text-muted" title={t.description}>
                        {t.description}
                      </div>
                      {t.poisoning_findings.length > 0 && (
                        <div className="mt-1.5 inline-flex items-center gap-1.5 text-xs text-critical-ink">
                          <AlertOctagon className="size-3.5" /> Poisoned description: {t.poisoning_findings.map((f) => f.rule).join(", ")}
                        </div>
                      )}
                    </Td>
                    <Td>
                      <div className="flex max-w-80 flex-wrap gap-1">
                        <Chip>{titleCase(c.side_effect ?? "read")}</Chip>
                        {c.egress && c.egress !== "none" && <Chip>egress: {c.egress}</Chip>}
                        {c.untrusted_content && <Chip>untrusted output</Chip>}
                        {c.required_entitlement && <Chip>needs {c.required_entitlement}</Chip>}
                        {c.rate_limit_per_min && <Chip>{c.rate_limit_per_min}/min</Chip>}
                        {(c.intent_tags ?? []).map((tag) => (
                          <Chip key={tag} mono>
                            {tag}
                          </Chip>
                        ))}
                      </div>
                    </Td>
                    <Td>{c.returns_data_class && <DataClassPill value={c.returns_data_class} />}</Td>
                    <Td>
                      <div className={cx("flex items-center gap-1.5 font-mono text-xs", drift ? "text-critical-ink" : "text-muted")}>
                        <Lock className="size-3.5" /> {shortHash(t.approved_hash ?? t.definition_hash, 10)}
                      </div>
                      {drift && <div className="text-xs text-critical-ink">definition changed</div>}
                    </Td>
                    <Td>
                      <StatusPill status={t.status} />
                    </Td>
                    <Td>
                      <div className="flex justify-end gap-2">
                        {t.status !== "approved" && (
                          <Button icon={ShieldCheck} roles={["security-approver"]} loading={approve.isPending && approve.variables?.id === t.id} onClick={() => approve.mutate({ id: t.id })}>
                            Approve
                          </Button>
                        )}
                        {t.status === "approved" && (
                          <Button variant="ghost" icon={ShieldBan} roles={["security-approver", "soc-analyst"]} onClick={() => quarantine.mutate(t.id)}>
                            Quarantine
                          </Button>
                        )}
                      </div>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
      <Modal open={!!override} onClose={() => setOverride(null)} title="This tool description looks poisoned">
        <p className="mb-3 text-sm text-muted">The Guard found instruction-like content in the description. Approving pins it as-is; agents would read these instructions.</p>
        <div className="mb-4 space-y-1.5">
          {override?.poisoning_findings.map((f, i) => (
            <div key={i} className="rounded-lg border border-line bg-inset px-3 py-2 text-sm">
              <span className="mr-2 font-mono text-xs text-critical-ink">{f.rule}</span>
              <mark className="rounded bg-critical/20 px-1 text-fg">{f.snippet}</mark>
            </div>
          ))}
        </div>
        <div className="flex justify-end gap-2">
          <Button onClick={() => setOverride(null)}>Keep blocked</Button>
          <Button variant="danger" onClick={() => override && approve.mutate({ id: override.id, force: true })}>
            Security override
          </Button>
        </div>
      </Modal>
    </>
  );
}
