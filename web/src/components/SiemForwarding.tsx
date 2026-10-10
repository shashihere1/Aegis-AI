import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post } from "../lib/api";
import { titleCase } from "../lib/format";
import { useSession } from "../lib/session";
import { Badge, Button, Callout, Card, EmptyState, ErrorState, SkeletonRows, TBody, THead, Table, Td, Th, Tr, cx, focusRing, type Tone } from "./ui";

type Delivery = { alert_id: string; status: string; attempts: number; latency_ms: number | null; last_error: string | null };

const DELIVERY_TONE: Record<string, Tone> = { delivered: "good", failed: "critical", pending: "warning", queued: "warning", retrying: "warning" };

export function SiemForwarding() {
  const { can, persona } = useSession();
  const cache = useQueryClient();
  const permitted = can("soc-analyst", "auditor", "admin", "risk-approver");
  const deliveries = useQuery({ queryKey: ["siem-deliveries", persona?.username], enabled: permitted,
    queryFn: () => api<{ enabled: boolean; items: Delivery[] }>("/v1/siem/deliveries"), refetchInterval: 2000 });
  const retry = useMutation({ retry: false, mutationFn: (id: string) => post(`/v1/siem/deliveries/${id}/retry`),
    onSuccess: () => cache.invalidateQueries({ queryKey: ["siem-deliveries"] }) });
  if (!permitted) return null;
  const items = deliveries.data?.items ?? [];
  return <Card className="mb-6 overflow-hidden" title="External alert forwarding · transactional outbox">
    <div className="space-y-3 p-5 text-sm">
      <div>{deliveries.data
        ? <Badge tone={deliveries.data.enabled ? "good" : "warning"}>{deliveries.data.enabled ? "Forwarding enabled" : "Forwarding disabled / unavailable"}</Badge>
        : <Badge>{deliveries.isError ? "Forwarding status unavailable" : "Checking forwarding status"}</Badge>}</div>
      <p className="text-caption text-muted">Delivered means the receiver acknowledged this exact event ID and hash. Failures remain durable; retry does not rerun an agent or banking action.</p>
      <p className="text-caption text-muted">Local mock receiver: <a className={cx("rounded font-medium text-accent hover:underline", focusRing)} href="http://127.0.0.1:8011/" target="_blank" rel="noreferrer">Open central alert inbox →</a>. This is not a Sentinel/Splunk integration.</p>
      {retry.error && <Callout tone="critical" title="Retry could not be completed">{retry.error.message}</Callout>}
    </div>
    <div className="border-t border-line">
      {deliveries.isLoading ? <SkeletonRows rows={3} cols={5} />
        : deliveries.isError ? <ErrorState title="Could not load forwarding status" error={deliveries.error} onRetry={() => void deliveries.refetch()} />
        : !items.length ? <EmptyState title="No alert deliveries yet">Forwarded alerts and their acknowledgement status appear here.</EmptyState>
        : <Table>
          <THead><Th>Alert ID</Th><Th>Delivery</Th><Th numeric>Attempts</Th><Th numeric>Alert → acknowledgement</Th><Th>Error / retry</Th></THead>
          <TBody>{items.map(item => <Tr key={item.alert_id}>
            <Td className="font-mono text-xs">{item.alert_id}</Td>
            <Td><Badge tone={DELIVERY_TONE[item.status] ?? "neutral"}>{titleCase(item.status)}</Badge></Td>
            <Td numeric>{item.attempts}</Td>
            <Td numeric>{item.latency_ms == null ? "—" : `${item.latency_ms.toFixed(0)} ms`}</Td>
            <Td><div className="flex flex-wrap items-center gap-3">
              <span className="min-w-0 break-words text-muted">{item.last_error ?? "—"}</span>
              {item.status === "failed" && deliveries.data?.enabled && can("soc-analyst", "admin") &&
                <Button size="sm" loading={retry.isPending && retry.variables === item.alert_id} onClick={() => retry.mutate(item.alert_id)}>Retry delivery</Button>}
            </div></Td></Tr>)}</TBody>
        </Table>}
    </div>
  </Card>;
}
