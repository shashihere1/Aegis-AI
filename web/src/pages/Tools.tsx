import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertOctagon, Lock, Plug, ShieldBan, ShieldCheck, X } from "lucide-react";
import { api, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { shortHash, titleCase } from "../lib/format";
import type { McpServer, Tool } from "../lib/types";
import {
  Badge,
  Button,
  Card,
  Chip,
  DataClassPill,
  EmptyState,
  ErrorState,
  FilterSelect,
  Modal,
  PageHeader,
  SkeletonRows,
  Stat,
  StatGroup,
  StatusPill,
  TBody,
  THead,
  Table,
  TableToolbar,
  Td,
  Th,
  Tr,
  cx,
} from "../components/ui";

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

  const loading = servers.isLoading || tools.isLoading;
  const failed = servers.isError ? servers : tools.isError ? tools : null;
  const activeServers = (servers.data ?? []).filter((s) => s.status === "active");
  const activeIds = new Set(activeServers.map((s) => s.id));
  const all = (tools.data ?? []).filter((t) => activeIds.has(t.server_id));
  const shown = server ? all.filter((t) => t.server_id === server) : all;
  const serverById = new Map(activeServers.map((s) => [s.id, s]));
  const blocked = all.filter((t) => t.status !== "approved").length;
  const poisoned = all.filter((t) => t.poisoning_findings.length > 0).length;
  const thirdParty = activeServers.filter((s) => s.vendor !== "internal").length;
  const ready = !loading && !failed;

  return (
    <>
      <PageHeader title="MCP servers and tools" subtitle="Every tool an agent can reach: classified by its owner, pinned at approval, quarantined on drift" />

      <StatGroup className="mb-8">
        <Stat label="Active servers" value={ready ? activeServers.length : "—"} caption={ready ? `${thirdParty} third-party` : " "} />
        <Stat label="Tools" value={ready ? all.length : "—"} caption="Across active servers" />
        <Stat label="Blocked tools" tone="warning" value={ready ? blocked : "—"} caption="Not approved, uncallable" />
        <Stat label="Poisoned descriptions" tone="critical" value={ready ? poisoned : "—"} caption="Instruction-like content found" />
      </StatGroup>

      <TableToolbar
        end={
          ready && (
            <span className="tabular">
              {shown.length} {shown.length === 1 ? "tool" : "tools"}
            </span>
          )
        }
      >
        <FilterSelect
          label="Server"
          value={server}
          onChange={setServer}
          allLabel="All"
          options={activeServers.map((s) => {
            const n = all.filter((t) => t.server_id === s.id).length;
            return { value: s.id, label: `${s.id} (${n})` };
          })}
        />
        {server && (
          <Button variant="ghost" size="sm" icon={X} onClick={() => setServer("")}>
            Clear
          </Button>
        )}
      </TableToolbar>

      <Card className="overflow-hidden">
        {loading ? (
          <SkeletonRows cols={6} />
        ) : failed ? (
          <ErrorState
            title="Couldn't load tools"
            error={failed.error}
            onRetry={() => {
              void servers.refetch();
              void tools.refetch();
            }}
          />
        ) : !shown.length ? (
          <EmptyState icon={Plug} title="No tools" />
        ) : (
          <Table>
            <THead>
              <Th>Tool</Th>
              <Th>Server</Th>
              <Th>Classification (authoritative)</Th>
              <Th>Returns</Th>
              <Th>Pin</Th>
              <Th>Status</Th>
              <Th>
                <span className="sr-only">Actions</span>
              </Th>
            </THead>
            <TBody>
              {shown.map((t) => {
                const drift = t.approved_hash && t.approved_hash !== t.definition_hash;
                const c = t.classification;
                const srv = serverById.get(t.server_id);
                return (
                  <Tr key={t.id} className="align-top">
                    <Td className="max-w-80">
                      <div className="font-mono text-sm font-medium text-fg">{t.id}</div>
                      <div className="mt-0.5 line-clamp-2 text-xs text-muted" title={t.description}>
                        {t.description}
                      </div>
                      {t.poisoning_findings.length > 0 && (
                        <div className="mt-1.5 inline-flex items-center gap-1.5 text-xs text-critical-ink">
                          <AlertOctagon className="size-3.5" aria-hidden /> Poisoned description: {t.poisoning_findings.map((f) => f.rule).join(", ")}
                        </div>
                      )}
                    </Td>
                    <Td>
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-mono text-xs text-muted">{t.server_id}</span>
                        {srv && srv.vendor !== "internal" && <Badge tone="warning">Third-party</Badge>}
                      </div>
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
                        <Lock className="size-3.5" aria-hidden /> {shortHash(t.approved_hash ?? t.definition_hash, 10)}
                      </div>
                      {drift && <div className="text-xs text-critical-ink">Definition changed</div>}
                    </Td>
                    <Td>
                      <StatusPill status={t.status} />
                    </Td>
                    <Td>
                      <div className="flex justify-end gap-2">
                        {t.status !== "approved" && (
                          <Button size="sm" icon={ShieldCheck} roles={["security-approver"]} loading={approve.isPending && approve.variables?.id === t.id} onClick={() => approve.mutate({ id: t.id })}>
                            Approve
                          </Button>
                        )}
                        {t.status === "approved" && (
                          <Button variant="ghost" size="sm" icon={ShieldBan} roles={["security-approver", "soc-analyst"]} onClick={() => quarantine.mutate(t.id)}>
                            Quarantine
                          </Button>
                        )}
                      </div>
                    </Td>
                  </Tr>
                );
              })}
            </TBody>
          </Table>
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
