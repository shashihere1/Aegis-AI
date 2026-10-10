import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Download, Plus, Search, X } from "lucide-react";
import { api } from "../lib/api";
import { compact, titleCase } from "../lib/format";
import { useFindings, useStats } from "../lib/queries";
import type { AgentPage } from "../lib/types";
import {
  Avatar,
  Button,
  Card,
  Chip,
  CopyButton,
  DataClassPill,
  EmptyState,
  ErrorState,
  FilterSelect,
  PageHeader,
  Pagination,
  RiskPill,
  RowLink,
  SearchInput,
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
  TimeAgo,
  Tr,
} from "../components/ui";
import { RegisterAgentModal } from "./RegisterAgent";

const PAGE = 25;
const CLOUD_LABEL: Record<string, string> = { azure: "Azure", aws: "AWS", gcp: "GCP", "on-prem": "On-prem" };

const FILTERS = [
  { key: "status", label: "Status", options: ["active", "pending_approval", "draft", "suspended", "discovered", "retired"].map((v) => ({ value: v, label: titleCase(v) })) },
  { key: "cloud", label: "Cloud", options: ["azure", "aws", "gcp", "on-prem"].map((v) => ({ value: v, label: CLOUD_LABEL[v] })) },
  { key: "environment", label: "Environment", options: ["PRD", "ACC", "TST", "DEV"].map((v) => ({ value: v, label: v })) },
  { key: "data_class", label: "Data class", options: ["public", "internal", "confidential", "restricted"].map((v) => ({ value: v, label: titleCase(v) })) },
] as const;
type FilterKey = (typeof FILTERS)[number]["key"];

function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function Registry() {
  const navigate = useNavigate();
  const stats = useStats().data;
  const findings = useFindings().data ?? [];
  // Filters live in the URL, so other screens can deep-link (e.g. /agents?status=pending_approval).
  const [params, setParams] = useSearchParams();
  const f = Object.fromEntries(FILTERS.map(({ key }) => [key, params.get(key) ?? ""])) as Record<FilterKey, string>;
  const setFilter = (key: FilterKey, value: string) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        return next;
      },
      { replace: true },
    );
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const [registering, setRegistering] = useState(false);
  const search = useDebounced(q);
  const filterKey = JSON.stringify(f);
  useEffect(() => setPage(0), [search, filterKey]);

  const list = useQuery({
    queryKey: ["agents", search, f, page],
    queryFn: () => api<AgentPage>("/v1/agents", { query: { q: search, ...f, limit: PAGE, offset: page * PAGE } }),
    placeholderData: keepPreviousData,
    refetchInterval: 5000,
  });

  const exportCsv = async () => {
    const all = await api<AgentPage>("/v1/agents", { query: { q: search, ...f, limit: 200 } });
    const cols = ["id", "name", "status", "environment", "cloud", "owner", "max_data_class", "risk_tier", "last_active_at"] as const;
    const rows = [cols.join(","), ...all.items.map((a) => cols.map((c) => JSON.stringify(a[c] ?? "")).join(","))];
    const url = URL.createObjectURL(new Blob([rows.join("\n")], { type: "text/csv" }));
    Object.assign(document.createElement("a"), { href: url, download: "aegis-agents.csv" }).click();
    URL.revokeObjectURL(url);
  };

  const openFindings = findings.filter((x) => x.status === "open").length;
  const total = list.data?.total ?? 0;
  const filtered = !!search || FILTERS.some(({ key }) => f[key]);

  return (
    <>
      <PageHeader
        title="Agent registry"
        subtitle="Every AI agent in the organisation, with its owner, data ceiling and risk."
        actions={
          <>
            <Button icon={Download} onClick={exportCsv}>
              Export CSV
            </Button>
            <Button variant="primary" icon={Plus} roles={["agent-developer", "admin"]} onClick={() => setRegistering(true)}>
              Register agent
            </Button>
          </>
        }
      />

      <StatGroup className="mb-8">
        <Stat label="Total agents" value={stats ? compact(stats.total) : "—"} caption={stats ? `${compact(stats.by_status.active ?? 0)} active` : " "} />
        <Stat label="Shadow agents" tone="warning" value={stats ? stats.shadow + openFindings : "—"} caption="Unregistered, needs an owner" to="/shadow" />
        <Stat label="Pending attestation" tone="warning" value={stats?.pending_attestation ?? "—"} caption="Owner must re-confirm" to="/attestation" />
        <Stat label="Active alerts" tone="critical" value={stats?.active_alerts ?? "—"} caption="Untriaged detections" to="/alerts" />
      </StatGroup>

      <TableToolbar
        end={
          list.data && (
            <span className="tabular">
              {total.toLocaleString()} agent{total === 1 ? "" : "s"}
            </span>
          )
        }
      >
        <SearchInput label="Search agents" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, owner or ID…" className="w-full sm:w-72" />
        {FILTERS.map(({ key, label, options }) => (
          <FilterSelect key={key} label={label} value={f[key]} onChange={(v) => setFilter(key, v)} options={[...options]} />
        ))}
        {filtered && (
          <Button
            variant="ghost"
            size="sm"
            icon={X}
            onClick={() => {
              setQ("");
              setParams({}, { replace: true });
            }}
          >
            Clear
          </Button>
        )}
      </TableToolbar>

      <Card className="overflow-hidden">
        {list.isLoading ? (
          <SkeletonRows cols={6} />
        ) : list.isError ? (
          <ErrorState title="Couldn't load agents" error={list.error} onRetry={() => void list.refetch()} />
        ) : !list.data?.items.length ? (
          <EmptyState icon={Search} title={filtered ? "No agents match these filters" : "No agents registered yet"}>
            {filtered ? "Try a different search or clear the filters." : "Register the first agent to start governing it."}
          </EmptyState>
        ) : (
          <div className={list.isPlaceholderData ? "opacity-60 transition-opacity" : undefined}>
            <Table>
              <THead>
                <Th>Agent</Th>
                <Th>Aegis ID</Th>
                <Th>Cloud</Th>
                <Th>Owner</Th>
                <Th>Status</Th>
                <Th>Data class</Th>
                <Th>Risk</Th>
                <Th>Last active</Th>
              </THead>
              <TBody>
                {list.data.items.map((a) => (
                  <Tr key={a.id} onClick={() => navigate(`/agents/${a.id}`)}>
                    <Td>
                      <RowLink to={`/agents/${a.id}`}>{a.name}</RowLink>
                      <div className="text-caption text-muted">
                        {a.framework} · {a.environment}
                      </div>
                    </Td>
                    <Td>
                      <span className="inline-flex items-center gap-1.5 font-mono text-xs text-muted">
                        {a.id} <CopyButton value={a.id} />
                      </span>
                    </Td>
                    <Td>
                      <Chip>{CLOUD_LABEL[a.cloud] ?? a.cloud}</Chip>
                    </Td>
                    <Td>
                      <div className="flex items-center gap-2">
                        <Avatar name={a.owner} size="sm" />
                        <span className="whitespace-nowrap">{a.owner}</span>
                      </div>
                    </Td>
                    <Td>
                      <StatusPill status={a.status} />
                    </Td>
                    <Td>
                      <DataClassPill value={a.max_data_class} />
                    </Td>
                    <Td>
                      <RiskPill tier={a.risk_tier} />
                    </Td>
                    <Td className="text-muted">
                      <TimeAgo value={a.last_active_at} />
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </div>
        )}
        <Pagination page={page} pageSize={PAGE} total={total} onPage={setPage} noun="agents" />
      </Card>
      <RegisterAgentModal open={registering} onClose={() => setRegistering(false)} />
    </>
  );
}
