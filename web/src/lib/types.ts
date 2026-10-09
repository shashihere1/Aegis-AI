// Shapes returned by the Aegis control plane (src/aegis/control/*.py).

export type DecisionKind = "allow" | "deny" | "require_approval" | "rate_limited";
export type Severity = "critical" | "high" | "medium" | "low";

export interface Persona {
  username: string;
  name: string;
  roles: string[];
  status: string;
}

export interface Reason {
  rule: string;
  message: string;
}

export interface Agent {
  id: string;
  name: string;
  description: string;
  purpose: string;
  intent_categories: string[];
  owner: string;
  sponsor: string;
  registered_by: string;
  business_unit: string;
  environment: string;
  cloud: string;
  framework: string;
  autonomy: string;
  max_data_class: string;
  customer_facing: boolean;
  capabilities: string[];
  can_delegate_to: string[];
  can_receive_from: string[];
  max_depth: number;
  endpoint_url: string | null;
  inherent_risk: number;
  risk_tier: string;
  status: string;
  idp_client_id: string | null;
  orphaned: boolean;
  attestation_due: string | null;
  created_at: string;
  last_active_at: string | null;
  risk_breakdown?: Record<string, number>;
}

export interface AgentPage {
  total: number;
  items: Agent[];
}

export interface AgentStats {
  total: number;
  by_status: Record<string, number>;
  shadow: number;
  pending_attestation: number;
  active_alerts: number;
}

export interface Decision {
  id: string;
  ts: string;
  agent_id: string | null;
  agent_name: string | null;
  subject: string | null;
  action: string;
  action_label: string;
  decision: DecisionKind;
  reasons: Reason[];
  obligations: { type: string; entities?: string[]; limit?: number }[];
  policy_version: string;
  mandate_id: string | null;
  root_id: string | null;
  data_class: string | null;
  latency_ms: number;
  redactions: number;
  outcome: CallOutcome | null;
}

export interface Alert {
  id: string;
  ts: string;
  rule_id: string;
  severity: Severity;
  title: string;
  agent_id: string | null;
  agent_name: string | null;
  evidence: Record<string, unknown>;
  actions_taken: { action: string; agent: string; blast_radius: BlastRadius }[];
  status: string;
}

export interface BlastRadius {
  agent_id: string;
  mandates: string[];
  agents_affected: string[];
  pending_approvals: string[];
}

export interface Task {
  root_id: string;
  subject: string;
  agent_id: string;
  agent_name: string | null;
  intent: string;
  intent_categories: string[];
  issued_at: string;
  status: string;
  revoked_reason: string | null;
  agents: { id: string; name: string }[];
  decisions: Partial<Record<DecisionKind, number>>;
}

export type CallOutcome = "executed" | "tool_error" | "failed" | "denied" | "rate_limited" | "awaiting_approval" | "not_recorded";
export type TaskOutcome = "revoked" | "failed" | "blocked" | "waiting" | "expired" | "in_progress" | "completed";

export interface LineageNode {
  id: string;
  kind: "user" | "agent" | "tool" | "data" | "approval" | "result";
  label: string;
  status?: string;
  depth?: number;
  outcome?: CallOutcome | TaskOutcome;
  outcomes?: Partial<Record<CallOutcome, number>>;
  approval_status?: string;
  approver?: string | null;
  detail?: string;
  task_outcomes?: Partial<Record<TaskOutcome, number>>;
}

export interface LineageEdge {
  from: string;
  to: string;
  kind: "initiated" | "delegated_to" | "attempted_delegation" | "invoked" | "read" | "approval" | "resulted_in";
  count: number;
  decisions: Partial<Record<DecisionKind, number>>;
  decision?: DecisionKind;
  rules?: string[];
  intent?: string;
}

export interface Lineage {
  root_id?: string;
  nodes: LineageNode[];
  edges: LineageEdge[];
  tasks?: number;
  truncated?: boolean;
}

export interface Mandate {
  id: string;
  root_id: string;
  parent_id: string | null;
  agent_id: string;
  agent_name: string | null;
  subject: string;
  chain: string[];
  chain_names: string[];
  intent: string;
  intent_categories: string[];
  scopes: string[];
  depth: number;
  issued_at: string;
  expires_at: string;
  status: string;
  revoked_reason: string | null;
}

export interface Approval {
  id: string;
  status: string;
  tool: string;
  arguments: Record<string, unknown>;
  intent: string;
  subject: string;
  chain: string[];
  chain_names: string[];
  agent_id: string;
  mandate_id: string;
  reasons: Reason[];
  approver: string | null;
  justification: string | null;
  created_at: string;
  expires_at: string;
  action_hash: string;
}

export interface Tool {
  id: string;
  server_id: string;
  name: string;
  description: string;
  definition_hash: string;
  approved_hash: string | null;
  classification: {
    intent_tags?: string[];
    side_effect?: string;
    egress?: string;
    returns_data_class?: string;
    rate_limit_per_min?: number | null;
    untrusted_content?: boolean;
    required_entitlement?: string | null;
  };
  poisoning_findings: { rule: string; snippet: string }[];
  status: string;
}

export interface McpServer {
  id: string;
  url: string;
  owner: string;
  vendor: string;
  status: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  sources: string[];
  evidence: Record<string, unknown>[];
  suggested_owner: string | null;
  hits: number;
  first_seen: string;
  last_seen: string;
  status: string;
  agent_id: string | null;
}

export interface LedgerEntry {
  seq: number;
  ts: string;
  event_type: string;
  actor: string;
  subject: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
}

export interface LedgerVerify {
  ok: boolean;
  entries: number;
  tip?: string;
  broken_at_seq?: number;
}

export interface EvidenceSummary {
  generated_at: string;
  source: string;
  integrity: LedgerVerify;
  counts: Record<"agents" | "mandates" | "decisions" | "approvals" | "alerts" | "ledger", number>;
  period: { from: string; to: string; start: string; end_exclusive: string; timezone: string };
  scope: { agent_id: string | null; root_id: string | null; framework: string; context: string; proof_mode: string };
  evidence_key: { fingerprint: string; mode: string };
  automation: { enabled: boolean; persistent_key: boolean; check_seconds: number };
  coverage: EvidenceControl[];
  executive_summary: string;
}

export interface EvidenceControl {
  id: string;
  title: string;
  status: string;
  observed_records: number;
  limitations: string;
  references: { framework: string; name: string; reference: string; source_url: string }[];
  sources: { file: string; count: number; query: string; filters: { event_type_prefixes?: string[] }; record_ids: (string | number)[] }[];
}

export interface EvidenceReport {
  id: string;
  schedule_id: string | null;
  generated_by: string;
  generated_at: string;
  status: "ready" | "failed";
  sha256: string;
  key_fingerprint: string;
  error_code: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_note: string | null;
  summary: Partial<EvidenceSummary>;
}

export interface EvidenceSchedule {
  id: string;
  name: string;
  created_by: string;
  scope: { agent_id?: string | null; root_id?: string | null; framework: string };
  interval_hours: number;
  enabled: boolean;
  next_run_at: string;
}

export interface Usage {
  agent_id: string;
  agent_name: string;
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_eur: number;
  avg_latency_ms: number;
}

export type SocBucket = {
  t: string;
  allow: number;
  require_approval: number;
  deny: number;
  rate_limited: number;
};

export interface SocSummary {
  window_minutes: number;
  buckets: SocBucket[];
  totals: Record<DecisionKind, number>;
  decisions: number;
  deny_rate: number;
  top_denied: { agent_id: string; agent_name: string; denies: number }[];
  alerts: { open: number; by_severity: Record<Severity, number>; injections: number; exfiltration_blocked: number };
  pending_approvals: number;
  active_mandates: number;
  open_findings: number;
}

export interface Policies {
  engine: string;
  version: string;
  files: Record<string, string>; // the Rego the active version runs
  rules: { rule: string; effect: string; message: string }[];
  data: Record<string, unknown>;
  editing: "configuration-only" | "configuration-and-rules";
  rules_recorded: boolean;
}

export interface RulesCheck {
  passed: boolean;
  skipped?: string;
  problems?: string[];
  cases?: { total: number; passed: number; failed: { name: string; problem: string }[] };
}

export interface PolicyDiff {
  version: string;
  against: string;
  rules: { file: string; status: string; added_lines: number; removed_lines: number; diff: string }[];
  configuration: { path: string; before: unknown; after: unknown }[];
  cases: { before: number; after: number; changed: boolean };
}

export interface GuardScan {
  injection: boolean;
  score: number;
  findings: { rule: string; weight: number; snippet: string }[];
  pii: { entity: string; text: string }[];
  pii_count: number;
  redacted: string;
}

export type DiscoverySourceState = "active" | "scheduled" | "manual" | "planned";

export interface DiscoveryStatus {
  sources: Record<"gateway" | "idp" | "otel" | "repo" | "cloud", DiscoverySourceState>;
  idp_scan: {
    automatic: boolean;
    interval_seconds: number;
    next_run_at: string | null;
    last_run:
      | { at: string; trigger: "manual" | "scheduled"; actor: string; ok: true; checked: number; ungoverned: number; new: number }
      | { at: string; trigger: "manual" | "scheduled"; actor: string; ok: false; error: string }
      | null;
  };
}

export interface IdentityStatus {
  provider: string;
  reachable: boolean;
  issuer: string;
  detail?: string;
  agents_with_identity: number;
}

export interface AttestationStatus {
  interval_days: number;
  grace_days: number;
  auto_enforce: boolean;
  scheduler_running: boolean;
  active_agents: number;
  due: number;
  overdue: number;
  orphaned: number;
  next_due: string | null;
}

export interface ReconcileReport {
  provider: string;
  checked: number;
  enabled: string[];
  disabled: string[];
  missing: string[];
  orphaned: string[];
  errors: { client_id: string; error: string }[];
}
