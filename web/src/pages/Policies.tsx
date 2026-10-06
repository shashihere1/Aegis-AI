import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Ban, BookLock, EyeOff, Hourglass } from "lucide-react";
import { api } from "../lib/api";
import type { Policies } from "../lib/types";
import { Card, Chip, JsonBlock, Loading, PageHeader, Pill, Tabs, Td, Th } from "../components/ui";

const EFFECT = {
  deny: { tone: "critical" as const, icon: Ban, label: "Deny" },
  require_approval: { tone: "warning" as const, icon: Hourglass, label: "Needs approval" },
  obligation: { tone: "info" as const, icon: EyeOff, label: "Obligation" },
};

export function PoliciesPage() {
  const policies = useQuery({ queryKey: ["policies"], queryFn: () => api<Policies>("/v1/policies") });
  const [file, setFile] = useState("tool_call.rego");
  if (!policies.data) return <Loading />;
  const p = policies.data;
  const source = p.files[file] ?? "";

  return (
    <>
      <PageHeader
        icon={BookLock}
        title="Policy Editor"
        subtitle="Policy-as-code (Rego v1). Every decision records the version it was made under."
        actions={<Chip mono>{p.version}</Chip>}
      />
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1fr_1.15fr]">
        <div className="space-y-5">
          <Card title={`Rules · ${p.rules.length}`}>
            <table className="w-full">
              <thead className="border-b border-line bg-inset">
                <tr>
                  <Th>Code</Th>
                  <Th>Effect</Th>
                  <Th>Rule</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {p.rules.map((r) => {
                  const e = EFFECT[r.effect as keyof typeof EFFECT] ?? EFFECT.obligation;
                  return (
                    <tr key={r.rule}>
                      <Td className="font-mono text-xs font-semibold">{r.rule}</Td>
                      <Td>
                        <Pill tone={e.tone} icon={e.icon}>
                          {e.label}
                        </Pill>
                      </Td>
                      <Td className="text-muted">{r.message}</Td>
                    </tr>
                  );
                })}
                <tr>
                  <Td className="font-mono text-xs font-semibold">—</Td>
                  <Td>
                    <Pill tone="info" icon={EyeOff}>
                      Obligation
                    </Pill>
                  </Td>
                  <Td className="text-muted">Redact PII from confidential results · rate-limit tools with a per-minute limit</Td>
                </tr>
              </tbody>
            </table>
          </Card>
          <Card title="Policy data (thresholds)">
            <div className="p-5">
              <JsonBlock value={p.data} />
              <p className="mt-3 text-xs text-faint">
                Combination: deny › needs approval › allow (with obligations). Default deny. Locally the same rules run in-process; in Azure an OPA sidecar evaluates this exact bundle.
              </p>
            </div>
          </Card>
        </div>
        <Card title="Source" action={<Tabs value={file} onChange={setFile} tabs={Object.keys(p.files).map((f) => ({ value: f, label: f }))} />}>
          <pre className="max-h-[calc(100vh-15rem)] overflow-auto p-5 font-mono text-xs leading-relaxed">
            {source.split("\n").map((line, i) => (
              <div key={i} className="flex">
                <span className="w-10 shrink-0 pr-3 text-right text-faint select-none">{i + 1}</span>
                <span className={line.trim().startsWith("#") ? "text-faint" : /^(deny|approval|obligations|decision) /.test(line) ? "text-accent" : "text-muted"}>{line || " "}</span>
              </div>
            ))}
          </pre>
        </Card>
      </div>
    </>
  );
}
