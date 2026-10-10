import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, Link2, RefreshCw, ScrollText } from "lucide-react";
import { api, downloadFile } from "../lib/api";
import { clock, shortHash } from "../lib/format";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import type { EvidenceSummary, LedgerEntry, LedgerVerify } from "../lib/types";
import {
  Button,
  Callout,
  Card,
  DLRow,
  DescriptionList,
  Drawer,
  EmptyState,
  ErrorState,
  JsonBlock,
  PageHeader,
  RowLink,
  SearchInput,
  Skeleton,
  SkeletonRows,
  TBody,
  THead,
  Table,
  TableToolbar,
  Td,
  Th,
  Tr,
} from "../components/ui";
import { EvidenceReports } from "./EvidenceReports";

export function Evidence() {
  const { can } = useSession();
  const toast = useToast();
  const auditor = can("auditor");
  const verify = useQuery({ queryKey: ["ledger-verify"], queryFn: () => api<LedgerVerify>("/v1/ledger/verify"), refetchInterval: 5000 });
  const entries = useQuery({ queryKey: ["ledger"], queryFn: () => api<LedgerEntry[]>("/v1/ledger", { query: { limit: 300 } }), refetchInterval: 3000 });
  const pack = useQuery({ queryKey: ["evidence-summary"], queryFn: () => api<EvidenceSummary>("/v1/evidence/summary"), enabled: auditor, refetchInterval: 5000 });
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<LedgerEntry | null>(null);
  const [downloading, setDownloading] = useState(false);
  const all = entries.data ?? [];
  const rows = all.filter((e) => !filter || `${e.event_type} ${e.actor} ${e.subject}`.toLowerCase().includes(filter.toLowerCase()));
  const v = verify.data;

  async function downloadPack() {
    setDownloading(true);
    try {
      const { blob, filename } = await downloadFile("/v1/evidence/pack");
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
      toast("success", "Evidence pack downloaded", "Open report.html in the ZIP; run verify_pack.py to check signatures, hashes and inclusion proofs.");
    } catch (error) {
      toast("error", "Evidence pack unavailable", error instanceof Error ? error.message : String(error));
    } finally {
      setDownloading(false);
    }
  }

  const reverify = (
    <Button size="sm" icon={RefreshCw} loading={verify.isFetching} onClick={() => verify.refetch()}>
      Re-verify
    </Button>
  );
  const detail = v ? (
    <>
      {v.entries.toLocaleString()} entries recomputed from the first block{v.tip && <span className="font-mono"> · tip {shortHash(v.tip, 16)}</span>}
    </>
  ) : null;

  return (
    <>
      <PageHeader title="Audit ledger" subtitle="Hash-chained, append-only evidence of every decision, approval, policy and lifecycle change." />

      <div className="mb-6">
        {verify.isError ? (
          <Callout tone="critical" title="Couldn't verify the ledger" action={reverify}>
            {verify.error instanceof Error ? verify.error.message : "The integrity check did not complete."} The result is unknown, so do not treat the ledger as verified.
          </Callout>
        ) : !v ? (
          <div className="rounded-lg border border-line bg-card p-3.5 shadow-card" role="status" aria-label="Verifying the ledger">
            <Skeleton className="h-4 w-64" />
            <Skeleton className="mt-2 h-3.5 w-96 max-w-full" />
          </div>
        ) : v.ok ? (
          <Callout tone="good" title="Ledger integrity verified" action={reverify}>
            {detail}
          </Callout>
        ) : (
          <Callout tone="critical" title={`Tampering detected at entry #${v.broken_at_seq}`} action={reverify}>
            {detail}
          </Callout>
        )}
      </div>

      <EvidenceReports />

      <Card title="Quick export" description="Last seven UTC days" className="mb-6">
        <div className="flex flex-wrap items-center gap-5 p-5">
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold text-fg">Download the evidence behind this demo</div>
            <p className="mt-1 text-sm text-muted">
              A signed manifest, readable HTML report, JSON/CSV, control coverage and offline inclusion-proof verifier. The pack is synthetic demo evidence, not a certified regulatory report.
            </p>
            {auditor && pack.data && (
              <p className="mt-2 text-caption text-muted">
                {pack.data.counts.decisions} decisions · {pack.data.counts.approvals} approvals · {pack.data.counts.alerts} alerts · {pack.data.counts.ledger} ledger entries
                {pack.data.integrity.ok ? " · chain verified" : " · chain verification failed"}
              </p>
            )}
            {!auditor && <p className="mt-2 text-sm text-warning-ink">Switch to Eva Visser (Auditor) to export the pack.</p>}
            {auditor && pack.isError && (
              <p role="alert" className="mt-2 text-sm text-critical-ink">
                Could not load pack preview: {pack.error.message}
              </p>
            )}
          </div>
          <Button icon={Download} variant="primary" loading={downloading} disabled={!auditor || !pack.data?.integrity.ok || downloading} onClick={downloadPack}>
            Download evidence pack
          </Button>
        </div>
      </Card>

      <TableToolbar end={entries.data && <span className="tabular">{rows.length.toLocaleString()} shown</span>}>
        <SearchInput
          label="Filter ledger entries"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by event, actor or subject (e.g. decision.deny, sanne)"
          className="w-full sm:w-96"
        />
      </TableToolbar>

      <Card className="overflow-hidden">
        {entries.isLoading ? (
          <SkeletonRows cols={6} />
        ) : entries.isError ? (
          <ErrorState title="Couldn't load the ledger" error={entries.error} onRetry={() => void entries.refetch()} />
        ) : !rows.length ? (
          <EmptyState icon={ScrollText} title={all.length ? "No entries match this filter" : "The ledger is empty"}>
            {all.length ? "Try a different event, actor or subject." : "Entries appear as agents make decisions and policies change."}
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <Th numeric>#</Th>
              <Th>Time</Th>
              <Th>Event</Th>
              <Th>Actor</Th>
              <Th>Subject</Th>
              <Th>Hash chain</Th>
            </THead>
            <TBody>
              {rows.map((e) => (
                <Tr key={e.seq} onClick={() => setOpen(e)}>
                  <Td numeric className="text-muted">
                    {e.seq}
                  </Td>
                  <Td className="tabular text-muted">{clock(e.ts)}</Td>
                  <Td>
                    <RowLink onClick={() => setOpen(e)} className="font-mono text-xs">
                      {e.event_type}
                    </RowLink>
                  </Td>
                  <Td>{e.actor}</Td>
                  <Td className="max-w-72 truncate font-mono text-xs text-muted">{e.subject}</Td>
                  <Td>
                    <span className="inline-flex items-center gap-1.5 font-mono text-xs text-muted">
                      {shortHash(e.prev_hash, 6)} <Link2 className="size-3 text-faint" aria-hidden /> <span className="text-fg">{shortHash(e.entry_hash, 6)}</span>
                    </span>
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      <Drawer open={!!open} onClose={() => setOpen(null)} title={open ? `#${open.seq} · ${open.event_type}` : ""}>
        {open && (
          <div className="space-y-4">
            <DescriptionList>
              <DLRow label="Actor">{open.actor}</DLRow>
              <DLRow label="Subject">
                <span className="font-mono text-xs break-all">{open.subject}</span>
              </DLRow>
              <DLRow label="Previous hash">
                <span className="font-mono text-xs break-all text-muted">{open.prev_hash}</span>
              </DLRow>
              <DLRow label="Entry hash">
                <span className="font-mono text-xs break-all">{open.entry_hash}</span>
              </DLRow>
            </DescriptionList>
            <JsonBlock value={open.payload} />
          </div>
        )}
      </Drawer>
    </>
  );
}
