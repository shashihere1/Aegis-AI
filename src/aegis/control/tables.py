"""PostgreSQL schema (SQLite is used for local development and tests)."""

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    purpose: Mapped[str] = mapped_column(Text)
    intent_categories: Mapped[list] = mapped_column(JSON, default=list)
    owner: Mapped[str] = mapped_column(String(120), index=True)
    sponsor: Mapped[str] = mapped_column(String(120))
    registered_by: Mapped[str] = mapped_column(String(120))
    business_unit: Mapped[str] = mapped_column(String(80), default="")
    environment: Mapped[str] = mapped_column(String(8), index=True)
    cloud: Mapped[str] = mapped_column(String(16), index=True)
    framework: Mapped[str] = mapped_column(String(40), default="custom")
    autonomy: Mapped[str] = mapped_column(String(4))
    max_data_class: Mapped[str] = mapped_column(String(16), index=True)
    customer_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    can_delegate_to: Mapped[list] = mapped_column(JSON, default=list)
    can_receive_from: Mapped[list] = mapped_column(JSON, default=list)
    max_depth: Mapped[int] = mapped_column(Integer, default=2)
    endpoint_url: Mapped[str | None] = mapped_column(String(300), nullable=True)
    inherent_risk: Mapped[int] = mapped_column(Integer, default=0)
    risk_tier: Mapped[str] = mapped_column(String(10), default="low")
    status: Mapped[str] = mapped_column(String(20), index=True)
    idp_client_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    orphaned: Mapped[bool] = mapped_column(Boolean, default=False)
    attestation_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class McpServer(Base):
    __tablename__ = "mcp_servers"
    id: Mapped[str] = mapped_column(String(60), primary_key=True)
    url: Mapped[str] = mapped_column(String(300))
    owner: Mapped[str] = mapped_column(String(120))
    vendor: Mapped[str] = mapped_column(String(60), default="internal")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Tool(Base):
    __tablename__ = "tools"
    id: Mapped[str] = mapped_column(String(130), primary_key=True)  # "server.tool"
    server_id: Mapped[str] = mapped_column(String(60), index=True)
    name: Mapped[str] = mapped_column(String(70))
    description: Mapped[str] = mapped_column(Text, default="")
    input_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    annotations: Mapped[dict] = mapped_column(JSON, default=dict)
    definition_hash: Mapped[str] = mapped_column(String(64))
    approved_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classification: Mapped[dict] = mapped_column(JSON, default=dict)
    poisoning_findings: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending | approved | quarantined


class Mandate(Base):
    __tablename__ = "mandates"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    parent_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    root_id: Mapped[str] = mapped_column(String(40), index=True)
    agent_id: Mapped[str] = mapped_column(String(20), index=True)
    subject: Mapped[str] = mapped_column(String(120))
    chain: Mapped[list] = mapped_column(JSON, default=list)
    intent: Mapped[str] = mapped_column(Text)
    intent_categories: Mapped[list] = mapped_column(JSON, default=list)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    audience: Mapped[list] = mapped_column(JSON, default=list)
    entitlements: Mapped[list] = mapped_column(JSON, default=list)
    max_data_class: Mapped[str] = mapped_column(String(16))
    depth: Mapped[int] = mapped_column(Integer, default=0)
    jti: Mapped[str] = mapped_column(String(60), unique=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(12), default="active", index=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    action_hash: Mapped[str] = mapped_column(String(64), index=True)
    mandate_id: Mapped[str] = mapped_column(String(40), index=True)
    agent_id: Mapped[str] = mapped_column(String(20))
    subject: Mapped[str] = mapped_column(String(120))
    chain: Mapped[list] = mapped_column(JSON, default=list)
    tool: Mapped[str] = mapped_column(String(130))
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    intent: Mapped[str] = mapped_column(Text, default="")
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(12), default="pending", index=True)
    approver: Mapped[str | None] = mapped_column(String(120), nullable=True)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DecisionRecord(Base):
    __tablename__ = "decisions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    mandate_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    root_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    agent_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    subject: Mapped[str | None] = mapped_column(String(120), nullable=True)
    action: Mapped[str] = mapped_column(String(160))
    decision: Mapped[str] = mapped_column(String(20), index=True)
    obligations: Mapped[list] = mapped_column(JSON, default=list)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    policy_version: Mapped[str] = mapped_column(String(40), default="")
    input_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    data_class: Mapped[str | None] = mapped_column(String(16), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    rule_id: Mapped[str] = mapped_column(String(10), index=True)
    severity: Mapped[str] = mapped_column(String(10))
    title: Mapped[str] = mapped_column(Text)
    agent_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    actions_taken: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="new")


class DiscoveryFinding(Base):
    __tablename__ = "discovery_findings"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(120), unique=True)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    suggested_owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | claimed | quarantined | dismissed
    agent_id: Mapped[str | None] = mapped_column(String(20), nullable=True)


class Usage(Base):
    __tablename__ = "usage"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    agent_id: Mapped[str] = mapped_column(String(20), index=True)
    mandate_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    model: Mapped[str] = mapped_column(String(80))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_eur: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(40))  # ISO timestamp, part of the hashed content
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    actor: Mapped[str] = mapped_column(String(120))
    subject: Mapped[str] = mapped_column(String(160))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64))
