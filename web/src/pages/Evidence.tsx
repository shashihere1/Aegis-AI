import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link2, RefreshCw, ShieldCheck, ShieldX } from "lucide-react";
import { api } from "../lib/api";
import { clock, shortHash } from "../lib/format";
import type { LedgerEntry, LedgerVerify } from "../lib/types";
import { Button, Card, Chip, Drawer, JsonBlock, Loading, PageHeader, TextInput, Td, Th } from "../components/ui";

export function Evidence() {
  const verify = useQuery({ queryKey: ["ledger-verify"], queryFn: () => api<LedgerVerify>("/v1/ledger/verify"), refetchInterval: 5000 });
  const entries = useQuery({ queryKey: ["ledger"], queryFn: () => api<LedgerEntry[]>("/v1/ledger", { query: { limit: 300 } }), refetchInterval: 3000 });
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<LedgerEntry | null>(null);
  const rows = (entries.data ?? []).filter((e) => !filter || `${e.event_type} ${e.actor} ${e.subject}`.toLowerCase().includes(filter.toLowerCase()));
  const v = verify.data;

  return (
    <>
      <PageHeader icon={ShieldCheck} title="Audit Ledger" subtitle="Hash-chained, append-only evidence of every decision, approval, policy and lifecycle change" />
      <Card className={v && !v.ok ? "mb-5 border-critical/50" : "mb-5"}>
        <div className="flex flex-wrap items-center gap-4 p-5">
          {v?.ok === false ? <ShieldX className="size-10 text-critical-ink" /> : <ShieldCheck className="size-10 text-good-ink" />}
          <div className="flex-1">
            <div className="text-lg font-semibold">{!v ? "Verifying…" : v.ok ? "Ledger integrity verified" : `Tampering detected at entry #${v.broken_at_seq}`}</div>
            <div className="text-sm text-muted">
              {v ? `${v.entries.toLocaleString()} entries recomputed from the first block` : ""} {v?.tip && <span className="font-mono">· tip {shortHash(v.tip, 16)}</span>}
            </div>
          </div>
          <Button icon={RefreshCw} loading={verify.isFetching} onClick={() => verify.refetch()}>
            Re-verify
          </Button>
        </div>
      </Card>
      <Card className="mb-4 p-4">
        <TextInput value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by event, actor or subject (e.g. decision.deny, agent.suspended, sanne)" />
      </Card>
      <Card className="overflow-x-auto">
        {entries.isLoading ? (
          <Loading />
        ) : (
          <table className="w-full">
            <thead className="border-b border-line bg-inset">
              <tr>
                <Th>#</Th>
                <Th>Time</Th>
                <Th>Event</Th>
                <Th>Actor</Th>
                <Th>Subject</Th>
                <Th>Hash chain</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((e) => (
                <tr key={e.seq} onClick={() => setOpen(e)} className="cursor-pointer hover:bg-hover">
                  <Td className="tabular text-muted">{e.seq}</Td>
                  <Td className="tabular text-muted">{clock(e.ts)}</Td>
                  <Td>
                    <Chip mono>{e.event_type}</Chip>
                  </Td>
                  <Td className="text-sm">{e.actor}</Td>
                  <Td className="max-w-72 truncate font-mono text-xs text-muted">{e.subject}</Td>
                  <Td>
                    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-faint">
                      {shortHash(e.prev_hash, 6)} <Link2 className="size-3" /> <span className="text-muted">{shortHash(e.entry_hash, 6)}</span>
                    </span>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Drawer open={!!open} onClose={() => setOpen(null)} title={open ? `#${open.seq} · ${open.event_type}` : ""}>
        {open && (
          <div className="space-y-4 text-sm">
            <div>
              <span className="text-muted">Actor</span> {open.actor}
            </div>
            <div>
              <span className="text-muted">Subject</span> <span className="font-mono">{open.subject}</span>
            </div>
            <div className="font-mono text-xs break-all text-muted">prev {open.prev_hash}</div>
            <div className="font-mono text-xs break-all">hash {open.entry_hash}</div>
            <JsonBlock value={open.payload} />
          </div>
        )}
      </Drawer>
    </>
  );
}
