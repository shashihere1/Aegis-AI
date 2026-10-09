export type BankMode = "inquiry" | "documents" | "address" | "transfer";

export type BankEvent = {
  kind: string;
  label: string;
  arguments?: unknown;
  result?: unknown;
  runtime?: string;
  usage?: { prompt_tokens: number; completion_tokens: number };
  metadata?: Record<string, string>;
  approval_id?: string;
};

export type BankRun = {
  id: string;
  subject: string;
  mode: BankMode;
  status: string;
  reply: string;
  events: BankEvent[];
  root_id: string | null;
  pending: { name?: string; arguments?: unknown; approval_id?: string };
  resumable: boolean;
};

export type BankStatus = {
  bank_storage?: string;
  bank_tools_requiring_review?: string[];
  ready: boolean;
  azure_configured: boolean;
  frameworks: Record<string, string | null>;
  policy_error: string | null;
  policy: {
    deployment: string;
    processing_scope: string;
    allowed_processing_scope: string;
    max_data_class: string;
    daily_budget_eur: number;
  };
  budget: {
    remaining_estimate_eur: number;
    used_or_reserved_eur: number;
    outstanding_holds: number;
    day_utc: string;
  };
};

export const OPEN_BANK_STATUSES = ["running", "confirmation_required", "approval_required"];

export const BANK_TASKS: Record<BankMode, { label: string; description: string; example: string }> = {
  inquiry: {
    label: "Account inquiry",
    description: "Check your balance or profile",
    example: "What is my account balance?",
  },
  documents: {
    label: "Verify a document",
    description: "Ask KYC to check a demo passport",
    example: "Verify my passport D-77 and explain the result.",
  },
  address: {
    label: "Change address",
    description: "Verify identity, then review a change",
    example: "Verify my passport D-77, then change my address to Keizersgracht 401, 1016 EK Amsterdam.",
  },
  transfer: {
    label: "Make a transfer",
    description: "Review a synthetic EUR payment",
    example: "Transfer EUR 25,000 to the demo landlord as a new beneficiary, reference Rent.",
  },
};

export function bankStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    running: "In progress",
    confirmation_required: "Your confirmation needed",
    approval_required: "Risk approval required",
    completed: "Completed",
    not_executed: "No action prepared",
    uncertain: "Execution uncertain",
    failed: "Could not finish",
    denied: "Blocked",
    blocked: "Blocked",
    cancelled: "Cancelled",
    expired: "Expired",
    interrupted: "Interrupted",
  };
  return labels[status] ?? status.replace(/_/g, " ");
}

export function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

/** A missing estimate is unknown, not a zero-cost model request. */
export function eventEstimate(event: BankEvent): number | null {
  const value = event.metadata?.["x-aegis-llm-estimated-cost-eur"];
  if (!value?.trim()) return null;
  const amount = Number(value);
  return Number.isFinite(amount) && amount >= 0 ? amount : null;
}

export function bankRunStats(events: BankEvent[]) {
  const modelEvents = events.filter(event => event.kind === "model");
  const estimates = modelEvents.map(eventEstimate).filter((value): value is number => value !== null);
  return {
    modelCalls: modelEvents.length,
    receipts: events.filter(event => event.kind === "tool" && event.result !== undefined && event.result !== null).length,
    estimatedCost: estimates.length ? estimates.reduce((sum, value) => sum + value, 0) : null,
    partialEstimate: estimates.length !== modelEvents.length,
  };
}

export type BankReceipt = {
  title: string;
  value: string | number;
  money: boolean;
  detail: string | null;
};

/** Never derive execution claims from model prose, proposals, or pending arguments. */
export function bankReceipt(event: BankEvent): BankReceipt | null {
  if (event.kind !== "tool") return null;
  const data = record(event.result);
  if (!data) return null;
  const string = (key: string) => typeof data[key] === "string" ? data[key] as string : null;
  if (event.label === "get_balance" && typeof data.balance_eur === "number" && Number.isFinite(data.balance_eur)) {
    return { title: "Account balance", value: data.balance_eur, money: true, detail: string("iban") };
  }
  if (event.label === "verify_document" && data.verified === true) {
    return { title: "Document check", value: "Verified", money: false, detail: string("document_id") };
  }
  if (event.label === "update_address" && data.status === "updated" && string("address")) {
    return { title: "Address updated", value: string("address")!, money: false, detail: string("customer_id") };
  }
  if (event.label === "initiate_transfer" && data.status === "accepted" && string("payment_id")
    && typeof data.amount === "number" && Number.isFinite(data.amount) && data.amount > 0) {
    return { title: "Synthetic transfer accepted", value: data.amount, money: true, detail: string("payment_id") };
  }
  return null;
}

/** Old text-only action runs remain historical records, not pending or verified writes. */
export function lacksChangeReceipt(run: BankRun): boolean {
  const tool = run.mode === "transfer" ? "initiate_transfer" : run.mode === "address" ? "update_address" : null;
  return run.status === "completed" && tool !== null
    && !run.events.some(event => event.label === tool && bankReceipt(event) !== null);
}
