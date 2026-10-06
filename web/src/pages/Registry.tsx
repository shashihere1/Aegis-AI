import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Bot, ChevronLeft, ChevronRight, ClipboardCheck, Download, Ghost, LayoutGrid, Plus, Search, Siren } from "lucide-react";
import { api } from "../lib/api";
import { compact, timeAgo, titleCase } from "../lib/format";
import { useFindings, useStats } from "../lib/queries";
import type { AgentPage } from "../lib/types";
import {
  Avatar,
  Button,
  Card,
  CopyButton,
  DataClassPill,
  EmptyState,
  Kpi,
  Loading,
  PageHeader,
  RiskPill,
  Select,
  StatusPill,
  Td,
  TextInput,
  Th,
} from "../components/ui";
import { RegisterAgentModal } from "./RegisterAgent";

const PAGE = 25;
const CLOUD_LABEL: Record<string, string> = { azure: "Azure", aws: "AWS", gcp: "GCP", "on-prem": "On-prem" };

const filters = {
  cloud: [{ value: "", label: "All clouds" }, ...["azure", "aws", "gcp", "on-prem"].map((v) => ({ value: v, label: CLOUD_LABEL[v] }))],
  status: [{ value: "", label: "All statuses" }, ...["active", "pending_approval", "draft", "suspended", "discovered", "retired"].map((v) => ({ value: v, label: titleCase(v) }))],
  environment: [{ value: "", label: "All environments" }, ...["PRD", "ACC", "TST", "DEV"].map((v) => ({ value: v, label: v }))],
  data_class: [{ value: "", label: "All data classes" }, ...["public", "internal", "confidential", "restricted"].map((v) => ({ value: v, label: titleCase(v) }))],
};

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
  const [q, setQ] = useState("");
  const [f, setF] = useState({ cloud: "", status: "", environment: "", data_class: "" });
  const [page, setPage] = useState(0);
  const [registering, setRegistering] = useState(false);
  const search = useDebounced(q);
  useEffect(() => setPage(0), [search, f]);

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

  return (
    <>
      <PageHeader
        icon={LayoutGrid}
        title="Agent Registry"
        subtitle="Monitor and govern all AI agents across your organisation"
        actions={
          <Button variant="primary" icon={Plus} roles={["agent-developer", "admin"]} onClick={() => setRegistering(true)}>
            Register Agent
          </Button>
        }
      />
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi icon={Bot} label="Total agents" value={stats ? compact(stats.total) : "—"} hint={stats && `${compact(stats.by_status.active ?? 0)} active`} />
        <Kpi
          icon={Ghost}
          tone="warning"
          label="Shadow agents"
          value={stats ? stats.shadow + openFindings : "—"}
          hint="View & resolve"
          onClick={() => navigate("/shadow")}
        />
        <Kpi icon={ClipboardCheck} tone="warning" label="Pending attestation" value={stats?.pending_attestation ?? "—"} hint="Action needed" onClick={() => navigate("/attestation")} />
        <Kpi icon={Siren} tone="critical" label="Active alerts" value={stats?.active_alerts ?? "—"} hint="View alerts" onClick={() => navigate("/alerts")} />
      </div>

      <Card className="mb-4 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-72 flex-1">
            <Search className="absolute top-3 left-3 size-4 text-faint" />
            <TextInput value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search agents, owners, IDs…" className="pl-9" />
          </div>
          {(Object.keys(filters) as (keyof typeof filters)[]).map((key) => (
            <Select key={key} label={key} value={f[key]} onChange={(v) => setF({ ...f, [key]: v })} options={filters[key]} className="min-w-44" />
          ))}
          <Button icon={Download} onClick={exportCsv}>
            Export CSV
          </Button>
        </div>
      </Card>

      <Card className="overflow-hidden">
        {list.isLoading ? (
          <Loading />
        ) : !list.data?.items.length ? (
          <EmptyState icon={Search} title="No agents match these filters" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-line bg-inset">
                <tr>
                  <Th>Agent name</Th>
                  <Th>Aegis ID</Th>
                  <Th>Cloud</Th>
                  <Th>Owner</Th>
                  <Th>Status</Th>
                  <Th>Data class</Th>
                  <Th>Risk</Th>
                  <Th>Last active</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {list.data.items.map((a) => (
                  <tr key={a.id} onClick={() => navigate(`/agents/${a.id}`)} className="cursor-pointer hover:bg-hover">
                    <Td>
                      <div className="font-medium text-accent">{a.name}</div>
                      <div className="text-xs text-faint">
                        {a.framework} · {a.environment}
                      </div>
                    </Td>
                    <Td>
                      <span className="inline-flex items-center gap-2 font-mono text-xs text-muted">
                        {a.id} <CopyButton value={a.id} />
                      </span>
                    </Td>
                    <Td>
                      <span className="rounded-md border border-line bg-inset px-2 py-0.5 text-xs font-medium">{CLOUD_LABEL[a.cloud] ?? a.cloud}</span>
                    </Td>
                    <Td>
                      <div className="flex items-center gap-2.5">
                        <Avatar name={a.owner} size="sm" />
                        <span>{a.owner}</span>
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
                    <Td className="text-muted">{timeAgo(a.last_active_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex items-center justify-between border-t border-line px-4 py-3 text-sm text-muted">
          <span className="tabular">
            {total ? `${page * PAGE + 1}–${Math.min(total, (page + 1) * PAGE)} of ${total.toLocaleString()}` : "0 agents"}
          </span>
          <div className="flex gap-2">
            <Button variant="ghost" icon={ChevronLeft} disabled={page === 0} onClick={() => setPage(page - 1)}>
              Previous
            </Button>
            <Button variant="ghost" disabled={(page + 1) * PAGE >= total} onClick={() => setPage(page + 1)}>
              Next <ChevronRight className="size-4" />
            </Button>
          </div>
        </div>
      </Card>
      <RegisterAgentModal open={registering} onClose={() => setRegistering(false)} />
    </>
  );
}
