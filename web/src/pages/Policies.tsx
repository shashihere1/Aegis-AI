import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Ban, EyeOff, Hourglass } from "lucide-react";
import { api } from "../lib/api";
import type { Policies } from "../lib/types";
import { PolicyGovernance } from "../components/PolicyGovernance";
import { Card, Chip, ErrorState, JsonBlock, PageHeader, Pill, Skeleton, SkeletonRows, TBody, THead, Table, Tabs, Td, Th, Tr, cx, focusRing } from "../components/ui";

const EFFECT = {
  deny: { tone: "critical" as const, icon: Ban, label: "Deny" },
  require_approval: { tone: "warning" as const, icon: Hourglass, label: "Needs approval" },
  obligation: { tone: "info" as const, icon: EyeOff, label: "Obligation" },
};

const HEADER = {
  title: "Policy governance",
  subtitle: "Versioned configuration and Rego, automatic checks, independent approval, historical replay and rollback.",
};

export function PoliciesPage() {
  const policies = useQuery({ queryKey: ["policies"], queryFn: () => api<Policies>("/v1/policies"), refetchInterval: 5000 });
  const [file, setFile] = useState("tool_call.rego");
  const p = policies.data;

  if (!p)
    return (
      <>
        <PageHeader {...HEADER} />
        <Card>
          {policies.isError ? (
            <ErrorState title="Couldn't load policies" error={policies.error} onRetry={() => void policies.refetch()} />
          ) : (
            <div className="space-y-4 p-5" role="status" aria-label="Loading policies">
              <Skeleton className="h-4 w-64" />
              <Skeleton className="h-3.5 w-full" />
              <Skeleton className="h-9 w-full" />
              <SkeletonRows rows={4} cols={3} />
            </div>
          )}
        </Card>
      </>
    );

  const source = p.files[file] ?? "";

  return (
    <>
      <PageHeader {...HEADER} actions={<Chip mono>{p.version}</Chip>} />
      <PolicyGovernance policy={p} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_1.15fr]">
        <div className="min-w-0 space-y-6">
          <Card title={`Rules · ${p.rules.length}`} className="overflow-hidden">
            <Table>
              <THead>
                <Th>Code</Th>
                <Th>Effect</Th>
                <Th>Rule</Th>
              </THead>
              <TBody>
                {p.rules.map((r, i) => {
                  const e = EFFECT[r.effect as keyof typeof EFFECT] ?? EFFECT.obligation;
                  return (
                    <Tr key={`${r.rule}-${r.effect}-${i}`}>
                      <Td className="font-mono text-xs font-semibold whitespace-nowrap">{r.rule}</Td>
                      <Td>
                        <Pill tone={e.tone} icon={e.icon}>
                          {e.label}
                        </Pill>
                      </Td>
                      <Td className="text-muted">{r.message}</Td>
                    </Tr>
                  );
                })}
                <Tr>
                  <Td className="font-mono text-xs font-semibold">—</Td>
                  <Td>
                    <Pill tone="info" icon={EyeOff}>
                      Obligation
                    </Pill>
                  </Td>
                  <Td className="text-muted">Redact PII from confidential results · rate-limit tools with a per-minute limit</Td>
                </Tr>
              </TBody>
            </Table>
          </Card>
          <Card title="Policy data (thresholds)">
            <div className="p-5">
              <JsonBlock value={p.data} />
              <p className="mt-3 text-caption text-muted">
                Combination: deny, needs approval, then allow with obligations. Default deny.{" "}
                {p.engine === "python" ? "This runtime is the Python evaluator, a mirror of the Rego shown here." : `The ${p.engine} engine evaluates exactly the Rego shown here, from the active version.`}
              </p>
            </div>
          </Card>
        </div>
        <Card
          className="min-w-0"
          title={p.rules_recorded ? `Active Rego · version ${p.version} (read-only)` : "Repository Rego (read-only)"}
          action={<Tabs label="Rego file" value={file} onChange={setFile} tabs={Object.keys(p.files).map((f) => ({ value: f, label: f }))} />}
        >
          <pre className={cx("max-h-[calc(100vh-15rem)] overflow-auto p-5 font-mono text-xs leading-relaxed", focusRing, "focus-visible:-outline-offset-2")} tabIndex={0} aria-label={`Rego source: ${file}`}>
            {source.split("\n").map((line, i) => (
              <div key={i} className="flex">
                <span className="w-10 shrink-0 pr-3 text-right text-faint select-none" aria-hidden>
                  {i + 1}
                </span>
                <span className={line.trim().startsWith("#") ? "text-muted italic" : /^(deny|approval|obligations|decision) /.test(line) ? "text-accent" : "text-fg"}>{line || " "}</span>
              </div>
            ))}
          </pre>
        </Card>
      </div>
    </>
  );
}
