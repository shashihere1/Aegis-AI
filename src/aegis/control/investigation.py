"""Bounded audit projections, never SQL supplied by a user or model.

Raw prompts, tool arguments/results, alert payloads and trace attributes are deliberately excluded.
The MCP upstream is credential-protected; user RBAC and Mandates are enforced before it at Aegis.
"""

import hmac
import re
from datetime import UTC, timedelta
from typing import Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from starlette.responses import JSONResponse

from aegis.common.investigation import SERVER, TOOLS
from aegis.control.tables import (
    Agent,
    Alert,
    Approval,
    DecisionRecord,
    Mandate,
    PolicyVersion,
    TraceSpan,
    Usage,
    utcnow,
)
from aegis.guard.pii import redact_text


class InvestigationQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    agent: str | None = Field(default=None, min_length=1, max_length=80)
    subject: str | None = Field(default=None, min_length=1, max_length=120)
    root_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,40}$")
    trace_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    record_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    decision: Literal["allow", "deny", "require_approval", "rate_limited"] | None = None
    hours: int = Field(default=24, ge=1, le=744)
    limit: int = Field(default=5, ge=1, le=20)
    approver: str | None = Field(default=None, min_length=1, max_length=120)
    min_amount_eur: float | None = Field(default=None, ge=0, le=1000000000, allow_inf_nan=False)


FILTERS = {
    "search_decisions": {"agent", "subject", "root_id", "trace_id", "record_id", "decision"},
    "get_agent": {"agent", "record_id"},
    "list_alerts": {"agent", "record_id"},
    "get_trace_timeline": {"trace_id", "record_id"},
    "get_delegation_chain": {"agent", "subject", "root_id", "record_id"},
    "usage_summary": {"agent", "record_id"},
    "get_lineage": {"root_id"},
    "get_policy_version": {"record_id"},
    "search_approvals": {"agent", "subject", "record_id", "approver", "min_amount_eur"},
}


def safe_text(value: str, limit: int = 600) -> str:
    text = re.sub(
        r"(?i)\b(?:bearer\s+\S+|(?:api[-_ ]?key|password|secret|access_token)\s*[:=]\s*\S+)", "[REDACTED_SECRET]", value
    )
    return redact_text(text)[0][:limit]


def timestamp(value):
    if value is None:
        return None
    # SQLite drops timezone metadata; stored audit timestamps are UTC in both supported databases.
    return (value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)).isoformat()


def evidence(row) -> dict:
    """One citation with a server-created ID/link and an allowlisted, redacted source excerpt."""
    if isinstance(row, DecisionRecord):
        kind, href = "decision", f"/copilot?evidence=decision:{row.id}"
        fields = {
            k: getattr(row, k)
            for k in (
                "agent_id",
                "subject",
                "action",
                "decision",
                "root_id",
                "mandate_id",
                "trace_id",
                "policy_version",
            )
        }
        fields.update(
            ts=timestamp(row.ts),
            reasons=[
                {"rule": safe_text(str(r.get("rule", "")), 80), "message": safe_text(str(r.get("message", "")))}
                for r in (row.reasons or [])[:8]
                if isinstance(r, dict)
            ],
        )
    elif isinstance(row, Agent):
        kind, href = "agent", f"/agents/{row.id}"
        fields = {k: getattr(row, k) for k in ("name", "status", "risk_tier", "owner", "framework", "max_data_class")}
        fields["note"] = "Current registry snapshot; not historical proof of why a call was blocked."
    elif isinstance(row, Alert):
        kind, href = "alert", f"/copilot?evidence=alert:{row.id}"
        fields = {k: getattr(row, k) for k in ("agent_id", "rule_id", "severity", "title", "status")}
        fields["ts"] = timestamp(row.ts)
        # No raw detection payloads: these may contain hostile tool content or secrets.
        fields["response_recorded"] = bool(row.actions_taken)
    elif isinstance(row, TraceSpan):
        kind, href = "span", f"/copilot?evidence=span:{row.span_id}"
        fields = {k: getattr(row, k) for k in ("trace_id", "parent_id", "name", "service", "status")}
        fields.update(start_ns=row.start_ns, duration_ms=round((row.end_ns - row.start_ns) / 1e6, 3))
    elif isinstance(row, Mandate):
        kind, href = "mandate", f"/lineage/{row.root_id}"
        fields = {k: getattr(row, k) for k in ("agent_id", "subject", "parent_id", "root_id", "status", "depth")}
        fields.update(issued_at=timestamp(row.issued_at), expires_at=timestamp(row.expires_at))
    elif isinstance(row, Usage):
        kind, href = "usage", f"/copilot?evidence=usage:{row.id}"
        fields = {
            k: getattr(row, k) for k in ("agent_id", "mandate_id", "model", "input_tokens", "output_tokens", "cost_eur")
        }
        fields.update(ts=timestamp(row.ts), note="Configured cost estimate, not Azure billing.")
    elif isinstance(row, PolicyVersion):
        kind, href = "policy", f"/copilot?evidence=policy:{row.id}"
        fields = {k: getattr(row, k) for k in ("name", "status", "content_hash", "rules_hash", "author", "approver")}
        fields.update(configuration=row.configuration, created_at=timestamp(row.created_at))
    elif isinstance(row, Approval):
        kind, href = "approval", f"/copilot?evidence=approval:{row.id}"
        fields = {k: getattr(row, k) for k in ("agent_id", "subject", "mandate_id", "tool", "status", "approver")}
        fields.update(created_at=timestamp(row.created_at), decided_at=timestamp(row.decided_at))
        amount = (row.arguments or {}).get("amount")
        if type(amount) in (int, float) and 0 <= amount <= 1000000000:
            fields["amount_eur"] = amount
    else:
        raise ValueError("Unsupported evidence type")
    # Structured policy configuration is schema-controlled; everything else is a small flat projection.
    fields = {k: safe_text(v) if isinstance(v, str) else v for k, v in fields.items()}
    record_id = str(row.span_id if isinstance(row, TraceSpan) else row.id)
    return {"ref": f"{kind}:{record_id}", "kind": kind, "id": record_id, "href": href, "facts": fields}


class InvestigationData:
    def __init__(self, ctx):
        self.ctx = ctx

    async def read(self, name: str, q: InvestigationQuery) -> dict:
        if name not in TOOLS:
            raise ValueError("Unknown read-only investigation tool")
        supplied = set(q.model_dump(exclude_none=True, exclude_defaults=True)) - {"hours", "limit"}
        if supplied - FILTERS[name]:
            raise ValueError("Unsupported filters for this investigation tool")
        models = {
            "get_agent": Agent,
            "search_decisions": DecisionRecord,
            "list_alerts": Alert,
            "get_delegation_chain": Mandate,
            "usage_summary": Usage,
            "get_policy_version": PolicyVersion,
            "get_trace_timeline": TraceSpan,
            "search_approvals": Approval,
        }
        if name == "get_lineage":
            if not q.root_id:
                raise ValueError("get_lineage requires an exact root_id")
            chain = await self.read("get_delegation_chain", q)
            decisions = await self.read("search_decisions", q)
            return {
                "records": chain["records"] + decisions["records"],
                "queries": [chain["query"], decisions["query"]],
                "truncated": chain["truncated"] or decisions["truncated"],
            }
        model = models[name]
        query = select(model)
        async with self.ctx.db.sessionmaker() as s:
            if q.agent:
                escaped = q.agent.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                ids = select(Agent.id).where(or_(Agent.id == q.agent, Agent.name.ilike(f"%{escaped}%", escape="\\")))
                query = (
                    query.where(model.id.in_(ids) if model is Agent else model.agent_id.in_(ids))
                    if hasattr(model, "agent_id") or model is Agent
                    else query
                )
            if q.subject and hasattr(model, "subject"):
                query = query.where(
                    model.subject == (q.subject if q.subject.startswith("user:") else f"user:{q.subject}")
                )
            if model is Approval:
                if q.approver:
                    query = query.where(model.approver == q.approver.removeprefix("user:"))
                if q.min_amount_eur is not None:
                    # Typed JSON comparison supported by PostgreSQL and SQLite, never a SQL string from the model.
                    query = query.where(model.arguments["amount"].as_float() >= q.min_amount_eur)
            if q.record_id:
                pk = model.span_id if model is TraceSpan else model.id
                if model is Usage:
                    if not q.record_id.isdecimal():
                        raise ValueError("Usage record_id must be an integer")
                    query = query.where(pk == int(q.record_id))
                elif model is PolicyVersion:
                    query = query.where(or_(pk == q.record_id, model.content_hash == q.record_id))
                else:
                    query = query.where(pk == q.record_id)
            if q.root_id:
                if not hasattr(model, "root_id"):
                    raise ValueError("This tool does not accept a root_id filter")
                query = query.where(model.root_id == q.root_id)
            if model is TraceSpan:
                if not q.trace_id and not q.record_id:
                    raise ValueError("get_trace_timeline requires an exact trace_id")
                if q.trace_id:
                    query = query.where(model.trace_id == q.trace_id)
                query = query.order_by(model.start_ns)
            elif model is Agent:
                if not q.agent and not q.record_id:
                    raise ValueError("get_agent requires an agent ID or name")
                query = query.order_by(model.name)
            else:
                if name == "get_delegation_chain" and not q.root_id and not q.record_id:
                    raise ValueError("get_delegation_chain requires an exact root_id")
                if model is PolicyVersion and not q.record_id:
                    raise ValueError("get_policy_version requires an exact record_id or content hash")
                time_field = (
                    model.ts if hasattr(model, "ts") else model.issued_at if model is Mandate else model.created_at
                )
                if not q.record_id and not q.root_id:
                    query = query.where(time_field >= utcnow() - timedelta(hours=q.hours))
                query = query.order_by(time_field.desc())
            if model is DecisionRecord:
                query = query.where(or_(model.data_class.is_(None), model.data_class != "restricted"))
                if q.decision:
                    query = query.where(model.decision == q.decision)
                if q.trace_id:
                    query = query.where(model.trace_id == q.trace_id)
            rows = (await s.scalars(query.limit(q.limit + 1))).all()
            return {
                "records": [evidence(row) for row in rows[: q.limit]],
                "truncated": len(rows) > q.limit,
                "query": {"tool": name, **q.model_dump(exclude_none=True)},
                "note": "Bounded records; missing data does not prove no event occurred. Raw payloads excluded.",
            }

    async def source(self, kind: str, record_id: str) -> dict | None:
        names = {
            "agent": "get_agent",
            "decision": "search_decisions",
            "alert": "list_alerts",
            "span": "get_trace_timeline",
            "mandate": "get_delegation_chain",
            "usage": "usage_summary",
            "policy": "get_policy_version",
            "approval": "search_approvals",
        }
        if kind not in names:
            return None
        result = await self.read(names[kind], InvestigationQuery(record_id=record_id, limit=1))
        return next(iter(result["records"]), None)


class RequireInvestigationGateway:
    def __init__(self, app, secret: str):
        self.app, self.secret = app, secret

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            value = dict(scope["headers"]).get(b"x-aegis-investigation", b"")
            if not self.secret or not hmac.compare_digest(value, self.secret.encode()):
                await JSONResponse({"detail": "Use the authenticated Aegis investigation gateway."}, status_code=401)(
                    scope, receive, send
                )
                return
        await self.app(scope, receive, send)


def investigation_app(ctx):
    data = InvestigationData(ctx)
    mcp = FastMCP(SERVER, stateless_http=True, json_response=True)

    def register(name):
        async def read(query: InvestigationQuery) -> dict:
            return await data.read(name, query)

        mcp.tool(
            name=name,
            description=TOOLS[name],
            annotations=ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=False,
            ),
        )(read)

    for name in TOOLS:
        register(name)
    app = mcp.streamable_http_app()
    app.add_middleware(RequireInvestigationGateway, secret=ctx.settings.investigation_token)
    return app
