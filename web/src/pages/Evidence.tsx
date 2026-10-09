import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock, Download, KeyRound, Link2, RefreshCw, ShieldCheck, ShieldX, Stamp } from "lucide-react";
import { api, downloadFile, post } from "../lib/api";
import { clock, shortHash, timeAgo } from "../lib/format";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import type { EvidenceSummary, LedgerCheckpoint, LedgerCheckpoints, LedgerEntry, LedgerVerify } from "../lib/types";
import { Button, Card, Chip, Drawer, JsonBlock, Loading, PageHeader, Pill, TextInput, Td, Th } from "../components/ui";

function verifyHeadline(v: LedgerVerify | undefined): string {
  if (!v) return "Verifying…";
  if (v.ok) return "Ledger integrity verified";
  if (v.broken_at_seq !== undefined) return `Tampering detected at entry #${v.broken_at_seq}`;
  return `History rewritten: contradicts signed checkpoint #${v.checkpoint} (entry #${v.at_seq})`;
}

function verifyDetail(v: LedgerVerify): string {
  if (!v.ok) return v.reason ? `${v.reason}.` : "";
  const signed = v.checkpoints
    ? ` · ${v.checkpoints} signed ${v.checkpoints === 1 ? "checkpoint" : "checkpoints"} up to entry #${v.signed_upto_seq}` +
      (v.unsigned_tail ? ` (${v.unsigned_tail} newer entries not yet signed)` : "") +
      ` · ${v.anchored ?? 0} externally timestamped`
    : " · no signed checkpoint yet";
  return `${v.entries.toLocaleString()} entries recomputed from the first block${signed}`;
}

function AnchorPill({ cp }: { cp: LedgerCheckpoint }) {
  if (cp.anchor_status === "anchored") return <Pill tone="good" icon={Clock}>Timestamped {clock(cp.anchored_at ?? "")} UTC</Pill>;
  if (cp.anchor_status === "pending") return <Pill tone="warning" icon={Clock}>Timestamp pending{cp.anchor_error ? ` · ${cp.anchor_error}` : ""} · retrying</Pill>;
  return <Pill tone="neutral">No timestamp authority configured</Pill>;
}

function Signing({ data, canSign }: { data: LedgerCheckpoints; canSign: boolean }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const sign = useMutation({
    mutationFn: () => post<LedgerCheckpoint>("/v1/ledger/checkpoints"),
    onSuccess: (cp) => {
      toast("success", `Checkpoint #${cp.number} signed`, cp.anchor_status === "anchored" ? `Timestamped by ${cp.tsa_signer ?? "the timestamp authority"}` : "Signed with the ledger key");
      queryClient.invalidateQueries({ queryKey: ["ledger-checkpoints"] });
      queryClient.invalidateQueries({ queryKey: ["ledger-verify"] });
    },
    onError: (e: Error) => toast("error", "Checkpoint refused", e.message),
  });
  const last = data.checkpoints[0];
  return (
    <Card title="Signing and timestamps" className="mb-4" action={<Button icon={Stamp} roles={["auditor", "admin"]} disabled={!canSign} loading={sign.isPending} onClick={() => sign.mutate()}>Sign checkpoint now</Button>}>
      <div className="grid gap-4 p-5 md:grid-cols-3">
        <div>
          <div className="mb-1 flex items-center gap-2 text-xs text-faint"><KeyRound className="size-3.5" />Ledger signing key</div>
          <div className="font-mono text-sm break-all" title={data.key.fingerprint}>{data.key.fingerprint}</div>
          <div className="mt-1 text-xs text-muted">
            {data.key.persistent ? "Persistent key (Key Vault/HSM in production)" : "Ephemeral demo key: changes on every restart"} · published at <span className="font-mono">/.well-known/aegis-ledger-key</span>
          </div>
        </div>
        <div>
          <div className="mb-1 flex items-center gap-2 text-xs text-faint"><Stamp className="size-3.5" />Latest signed checkpoint</div>
          {last ? (
            <>
              <div className="text-sm font-medium">#{last.number} · covers entries up to #{last.upto_seq}</div>
              <div className="mt-1 text-xs text-muted">Signed {timeAgo(last.created_at)} · {data.interval_seconds ? `automatic every ${data.interval_seconds}s when there are new entries` : "on demand and at every evidence export"}</div>
            </>
          ) : (
            <div className="text-sm text-muted">None yet: one is signed {data.interval_seconds ? `within ${data.interval_seconds}s of new entries` : "at the next evidence export"}.</div>
          )}
        </div>
        <div>
          <div className="mb-1 flex items-center gap-2 text-xs text-faint"><Clock className="size-3.5" />External timestamp (RFC 3161)</div>
          {last ? <AnchorPill cp={last} /> : <Pill tone="neutral">—</Pill>}
          <div className="mt-1 text-xs text-muted">
            {data.anchoring.configured ? (last?.tsa_signer ? `Authority: ${last.tsa_signer}` : `Authority: ${data.anchoring.tsa_url}`) : "Set AEGIS_TSA_URL to have checkpoint hashes timestamped by an independent authority."}
            {data.anchoring.configured && " Only checkpoint hashes are sent, never ledger content."}
          </div>
        </div>
      </div>
    </Card>
  );
}

export function Evidence() {
  const { can } = useSession();
  const toast = useToast();
  const auditor = can("auditor");
  const verify = useQuery({ queryKey: ["ledger-verify"], queryFn: () => api<LedgerVerify>("/v1/ledger/verify"), refetchInterval: 5000 });
  const signing = useQuery({ queryKey: ["ledger-checkpoints"], queryFn: () => api<LedgerCheckpoints>("/v1/ledger/checkpoints", { query: { limit: 1 } }), refetchInterval: 10000 });
  const entries = useQuery({ queryKey: ["ledger"], queryFn: () => api<LedgerEntry[]>("/v1/ledger", { query: { limit: 300 } }), refetchInterval: 3000 });
  const pack = useQuery({ queryKey: ["evidence-summary"], queryFn: () => api<EvidenceSummary>("/v1/evidence/summary"), enabled: auditor, refetchInterval: 5000 });
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<LedgerEntry | null>(null);
  const [downloading, setDownloading] = useState(false);
  const rows = (entries.data ?? []).filter((e) => !filter || `${e.event_type} ${e.actor} ${e.subject}`.toLowerCase().includes(filter.toLowerCase()));
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
      toast("success", "Evidence pack downloaded", "Open report.html in the ZIP; run verify_pack.py to check its hashes, audit chain, signatures and timestamps.");
    } catch (error) {
      toast("error", "Evidence pack unavailable", error instanceof Error ? error.message : String(error));
    } finally {
      setDownloading(false);
    }
  }

  return (
    <>
      <PageHeader icon={ShieldCheck} title="Audit Ledger" subtitle="Hash-chained, append-only evidence of every decision, approval, policy and lifecycle change" />
      <Card className={v && !v.ok ? "mb-5 border-critical/50" : "mb-5"}>
        <div className="flex flex-wrap items-center gap-4 p-5">
          {v?.ok === false ? <ShieldX className="size-10 text-critical-ink" /> : <ShieldCheck className="size-10 text-good-ink" />}
          <div className="flex-1">
            <div className="text-lg font-semibold">{verifyHeadline(v)}</div>
            <div className="text-sm text-muted">
              {v ? verifyDetail(v) : ""} {v?.tip && <span className="font-mono">· tip {shortHash(v.tip, 16)}</span>}
            </div>
          </div>
          <Button icon={RefreshCw} loading={verify.isFetching} onClick={() => verify.refetch()}>
            Re-verify
          </Button>
        </div>
      </Card>
      {signing.data && <Signing data={signing.data} canSign={!!v?.ok} />}
      <Card title="Auditor proof pack" className="mb-4">
        <div className="flex flex-wrap items-center gap-5 p-5">
          <div className="min-w-0 flex-1">
            <div className="font-semibold">Download the evidence behind this demo</div>
            <p className="mt-1 text-sm text-muted">
              A readable HTML report, structured JSON records, a signed SHA-256 file manifest, the signed ledger checkpoints
              with any external timestamps, and an offline verifier. Exporting first signs the current ledger tip.
              The pack is synthetic demo evidence, not a certified regulatory report.
            </p>
            {auditor && pack.data && (
              <p className="mt-2 text-xs text-faint">
                {pack.data.counts.decisions} decisions · {pack.data.counts.approvals} approvals · {pack.data.counts.alerts} alerts · {pack.data.counts.ledger} ledger entries
                {pack.data.integrity.ok ? " · chain verified" : " · chain verification failed"}
              </p>
            )}
            {!auditor && <p className="mt-2 text-sm text-warning-ink">Switch to Eva Visser (Auditor) to export the pack.</p>}
            {auditor && pack.isError && <p className="mt-2 text-sm text-critical-ink">Could not load pack preview: {pack.error.message}</p>}
          </div>
          <Button icon={Download} variant="primary" loading={downloading} disabled={!auditor || !pack.data?.integrity.ok || downloading} onClick={downloadPack}>
            Download evidence pack
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
