import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Bomb, FileWarning, Ghost, Landmark, UserRoundCheck, type LucideIcon } from "lucide-react";
import { post } from "./api";
import { useToast } from "./toast";
import type { StudioRun } from "./types";

export interface Scene {
  key: string;
  code: string;
  title: string;
  icon: LucideIcon;
  story: string;
  proves: string;
  next?: string;
  body?: unknown;
}

export const SCENES: Scene[] = [
  {
    key: "policy-transfer", code: "S7", title: "EUR 5,000 policy threshold comparison", icon: Landmark,
    story: "Run the same transfer before and after an approved policy change. At a EUR 10,000 threshold it is allowed; at EUR 2,000 it requires human approval, provided the agent has no other risk-based restrictions.",
    proves: "Live policy activation · same action, different policy version · rollback",
    next: "Priya drafts and replays a EUR 2,000 threshold in Policy Governance; Fatima approves and activates it. Run this scene again, then roll back.",
  },
  {
    key: "address-change",
    code: "S2",
    title: "Governed customer journey",
    icon: UserRoundCheck,
    story: "Jan asks Ava to change his address. Ava gets a 5-minute Mandate, delegates the ID check to the KYC agent over A2A, and receives the result with BSN and IBAN redacted.",
    proves: "JIT purpose-bound access · delegation chain · PII redaction · lineage",
    next: "Open Agent Lineage to see Jan → Ava → KYC → tool → data.",
  },
  {
    key: "transfer",
    code: "S3",
    title: "€25,000 transfer to a new beneficiary",
    icon: Landmark,
    story: "The Payments agent tries to send €25,000 to Jan's new landlord. Policy PAY-010 holds it for a human; the approval is bound to that exact amount and IBAN.",
    proves: "Human approval · segregation of duties · single-use approval",
    next: "Switch to Sanne Bakker and approve it in Approvals: the payment then executes by itself.",
    body: { amount: 25000, new_beneficiary: true },
  },
  {
    key: "attack",
    code: "S4",
    title: "Prompt-injection attack",
    icon: Bomb,
    story: "A rental contract hides an instruction to e-mail all customer records outside the bank. Aegis blocks the e-mail, raises a critical alert, suspends Ava and cascade-revokes the KYC agent's mandate.",
    proves: "Lethal-trifecta breaker · SOC alerting · kill switch · cascade revocation",
    next: "Use Reset in Demo Studio to resume Ava afterwards.",
  },
  {
    key: "shadow",
    code: "S5",
    title: "Shadow agents",
    icon: Ghost,
    story: "A script calls the CRM with a static API key, and an identity is created directly in the IdP behind Aegis's back. Both are discovered.",
    proves: "Automated discovery of unregistered agents",
    next: "Claim or quarantine them in Shadow Agents.",
  },
  {
    key: "rug-pull",
    code: "A4",
    title: "Tool rug pull",
    icon: FileWarning,
    story: "The KYC MCP server silently changes a tool description after it was approved. The definition no longer matches its pin, so the tool is quarantined.",
    proves: "MCP tool pinning · supply-chain protection",
    next: "Reset restores the original server.",
  },
];

export function useRunScene() {
  const queryClient = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: (scene: Scene) => post<StudioRun>(`/demo/api/scenarios/${scene.key}`, scene.body ?? {}),
    onSuccess: (run) => {
      const tone = run.status === "blocked" ? "error" : "success";
      const last = run.steps[run.steps.length - 1];
      toast(tone, `${run.scene} ${run.title}: ${run.status}`, last?.label);
      queryClient.invalidateQueries();
    },
    onError: (err: Error) => toast("error", "Scene failed", err.message),
  });
}

export function useResetDemo() {
  const queryClient = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: () => post<{ done: string[] }>("/demo/api/reset"),
    onSuccess: (r) => {
      toast("success", "Demo reset", r.done.length ? r.done.join(" · ") : "Nothing to reset");
      queryClient.invalidateQueries();
    },
  });
}
