import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post } from "../lib/api";
import { useSession } from "../lib/session";
import { useToast } from "../lib/toast";
import { titleCase } from "../lib/format";
import type { Agent, Tool } from "../lib/types";
import { Button, Field, Modal, Select, TextInput, cx } from "../components/ui";

export interface AgentDraft {
  name: string;
  purpose: string;
  intent_categories: string[];
  owner: string;
  sponsor: string;
  environment: string;
  cloud: string;
  framework: string;
  autonomy: string;
  max_data_class: string;
  customer_facing: boolean;
  capabilities: string[];
}

const AUTONOMY = [
  { value: "L0", label: "L0 · suggest only" },
  { value: "L1", label: "L1 · human in the loop" },
  { value: "L2", label: "L2 · human on the loop" },
  { value: "L3", label: "L3 · autonomous" },
];

function ChipPicker({ options, value, onChange }: { options: string[]; value: string[]; onChange: (v: string[]) => void }) {
  return (
    <div className="flex max-h-40 flex-wrap gap-1.5 overflow-auto rounded-lg border border-line-strong bg-inset p-2">
      {options.map((o) => {
        const on = value.includes(o);
        return (
          <button
            type="button"
            key={o}
            onClick={() => onChange(on ? value.filter((x) => x !== o) : [...value, o])}
            className={cx("rounded-md border px-2 py-1 font-mono text-xs transition", on ? "border-accent/50 bg-accent-soft text-accent" : "border-line text-muted hover:text-fg")}
            aria-pressed={on}
          >
            {o}
          </button>
        );
      })}
    </div>
  );
}

export function AgentForm({ initial, submitLabel, onSubmit, busy }: { initial?: Partial<AgentDraft>; submitLabel: string; onSubmit: (d: AgentDraft) => void; busy?: boolean }) {
  const { personas } = useSession();
  const taxonomy = useQuery({ queryKey: ["taxonomy"], queryFn: () => api<{ categories: string[] }>("/v1/taxonomy") });
  const tools = useQuery({ queryKey: ["tools"], queryFn: () => api<Tool[]>("/v1/tools") });
  const [d, setD] = useState<AgentDraft>({
    name: "",
    purpose: "",
    intent_categories: [],
    owner: "niels.vandijk",
    sponsor: "retail.ops.head",
    environment: "PRD",
    cloud: "azure",
    framework: "langgraph",
    autonomy: "L1",
    max_data_class: "internal",
    customer_facing: false,
    capabilities: [],
    ...initial,
  });
  const set = <K extends keyof AgentDraft>(k: K, v: AgentDraft[K]) => setD({ ...d, [k]: v });
  const valid = d.name.length >= 3 && d.purpose.length >= 10 && d.intent_categories.length > 0;
  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        if (valid) onSubmit(d);
      }}
    >
      <div className="grid grid-cols-2 gap-4">
        <Field label="Name">
          <TextInput value={d.name} onChange={(e) => set("name", e.target.value)} placeholder="Mortgage-Advice-Agent" />
        </Field>
        <Field label="Owner">
          <Select label="Owner" value={d.owner} onChange={(v) => set("owner", v)} options={personas.map((p) => ({ value: p.username, label: p.name }))} className="w-full" />
        </Field>
      </div>
      <Field label="Purpose" hint="What the agent is for. Mandates can only be issued for intents within this purpose.">
        <TextInput value={d.purpose} onChange={(e) => set("purpose", e.target.value)} placeholder="Answer mortgage questions for retail customers." />
      </Field>
      <Field label="Intent categories">
        <ChipPicker options={taxonomy.data?.categories ?? []} value={d.intent_categories} onChange={(v) => set("intent_categories", v)} />
      </Field>
      <Field label="Tools (capabilities)" hint="Eligibility only: the agent still needs a Mandate for each task.">
        <ChipPicker options={(tools.data ?? []).filter((t) => t.status === "approved").map((t) => t.id)} value={d.capabilities} onChange={(v) => set("capabilities", v)} />
      </Field>
      <div className="grid grid-cols-3 gap-4">
        <Field label="Environment">
          <Select label="Environment" value={d.environment} onChange={(v) => set("environment", v)} options={["PRD", "ACC", "TST", "DEV"].map((v) => ({ value: v, label: v }))} className="w-full" />
        </Field>
        <Field label="Autonomy">
          <Select label="Autonomy" value={d.autonomy} onChange={(v) => set("autonomy", v)} options={AUTONOMY} className="w-full" />
        </Field>
        <Field label="Data ceiling">
          <Select
            label="Data ceiling"
            value={d.max_data_class}
            onChange={(v) => set("max_data_class", v)}
            options={["public", "internal", "confidential", "restricted"].map((v) => ({ value: v, label: titleCase(v) }))}
            className="w-full"
          />
        </Field>
      </div>
      <div className="grid grid-cols-3 gap-4">
        <Field label="Cloud">
          <Select label="Cloud" value={d.cloud} onChange={(v) => set("cloud", v)} options={["azure", "aws", "gcp", "on-prem"].map((v) => ({ value: v, label: v }))} className="w-full" />
        </Field>
        <Field label="Framework">
          <TextInput value={d.framework} onChange={(e) => set("framework", e.target.value)} />
        </Field>
        <Field label="Sponsor">
          <TextInput value={d.sponsor} onChange={(e) => set("sponsor", e.target.value)} />
        </Field>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={d.customer_facing} onChange={(e) => set("customer_facing", e.target.checked)} className="accent-[var(--accent)]" />
        Customer-facing (raises the inherent risk score)
      </label>
      <div className="flex justify-end gap-2 pt-2">
        <Button type="submit" variant="primary" disabled={!valid} loading={busy}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}

export function RegisterAgentModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const create = useMutation({
    mutationFn: (d: AgentDraft) => post<Agent>("/v1/agents", d),
    onSuccess: (agent) => {
      toast("success", `${agent.name} registered as a draft`, `Inherent risk: ${agent.risk_tier}. Submit it for approval from its page.`);
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      onClose();
      navigate(`/agents/${agent.id}`);
    },
    onError: (e: Error) => toast("error", "Registration refused", e.message),
  });
  return (
    <Modal open={open} onClose={onClose} title="Register an agent" wide>
      <AgentForm submitLabel="Register as draft" onSubmit={(d) => create.mutate(d)} busy={create.isPending} />
    </Modal>
  );
}
