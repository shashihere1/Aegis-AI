import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { Button, Card, Pill, Td, Th } from "./ui";

type Delivery = { alert_id: string; status: string; attempts: number; latency_ms: number | null; last_error: string | null };

export function SiemForwarding() {
  const { can, persona } = useSession();
  const cache = useQueryClient();
  const permitted = can("soc-analyst", "auditor", "admin", "risk-approver");
  const deliveries = useQuery({ queryKey: ["siem-deliveries", persona?.username], enabled: permitted,
    queryFn: () => api<{ enabled: boolean; items: Delivery[] }>("/v1/siem/deliveries"), refetchInterval: 2000 });
  const retry = useMutation({ retry: false, mutationFn: (id: string) => post(`/v1/siem/deliveries/${id}/retry`),
    onSuccess: () => cache.invalidateQueries({ queryKey: ["siem-deliveries"] }) });
  if (!permitted) return null;
  return <Card className="mb-5 overflow-x-auto" title="External alert forwarding · transactional outbox">
    <div className="p-4 text-sm"><Pill tone={deliveries.data?.enabled ? "good" : "warning"}>{deliveries.data?.enabled ? "Forwarding enabled" : "Forwarding disabled / unavailable"}</Pill>
      <p className="mt-2 text-xs text-muted">Delivered means the receiver acknowledged this exact event ID and hash. Failures remain durable; retry does not rerun an agent or banking action.</p>
      <p className="mt-2 text-xs text-muted">Local mock receiver: <a className="text-accent" href="http://127.0.0.1:8011/" target="_blank" rel="noreferrer">Open central alert inbox →</a>. This is not a Sentinel/Splunk integration.</p>
      {deliveries.isError && <p role="alert" className="mt-2 text-critical-ink">Could not load forwarding status.</p>}
      {retry.error && <p role="alert" className="mt-2 text-critical-ink">{retry.error.message}</p>}
    </div>
    {!!deliveries.data?.items.length && <table className="w-full text-sm"><thead><tr><Th>Alert ID</Th><Th>Delivery</Th><Th>Attempts</Th><Th>Alert → acknowledgement</Th><Th>Error / retry</Th></tr></thead>
      <tbody>{deliveries.data.items.map(item => <tr key={item.alert_id}><Td className="font-mono text-xs">{item.alert_id}</Td>
        <Td>{item.status}</Td><Td>{item.attempts}</Td><Td>{item.latency_ms == null ? "—" : `${item.latency_ms.toFixed(0)} ms`}</Td>
        <Td>{item.last_error ?? "—"}{item.status === "failed" && deliveries.data.enabled && can("soc-analyst", "admin") &&
          <Button loading={retry.isPending} onClick={() => retry.mutate(item.alert_id)}>Retry delivery</Button>}</Td></tr>)}</tbody></table>}
  </Card>;
}
