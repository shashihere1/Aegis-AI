"""Auditor-only, self-verifying evidence bundle for the local Aegis demonstration."""

import hashlib
import html
import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.control import ledger
from aegis.control.auth import require_roles
from aegis.control.context import session
from aegis.control.identity.idp import Persona
from aegis.control.tables import (
    Agent,
    AgentRisk,
    Alert,
    AlertCase,
    Approval,
    CaseEvent,
    DecisionRecord,
    LedgerEntry,
    Mandate,
    PolicyState,
    PolicyVersion,
    TraceSpan,
)

FIELDS = {
    "agents": (
        "id",
        "name",
        "purpose",
        "owner",
        "sponsor",
        "environment",
        "framework",
        "autonomy",
        "risk_tier",
        "status",
        "created_at",
        "last_active_at",
    ),
    "mandates": (
        "id",
        "parent_id",
        "root_id",
        "agent_id",
        "subject",
        "chain",
        "intent",
        "scopes",
        "issued_at",
        "expires_at",
        "status",
        "revoked_reason",
    ),
    "decisions": (
        "id",
        "ts",
        "mandate_id",
        "root_id",
        "agent_id",
        "subject",
        "action",
        "decision",
        "reasons",
        "obligations",
        "policy_version",
        "input_snapshot",
        "data_class",
        "trace_id",
        "latency_ms",
    ),
    "approvals": (
        "id",
        "action_hash",
        "mandate_id",
        "agent_id",
        "subject",
        "chain",
        "tool",
        "arguments",
        "intent",
        "reasons",
        "status",
        "approver",
        "justification",
        "created_at",
        "expires_at",
        "decided_at",
    ),
    "alerts": ("id", "ts", "rule_id", "severity", "title", "agent_id", "evidence", "actions_taken", "status"),
    "ledger": ("seq", "ts", "event_type", "actor", "subject", "payload", "prev_hash", "entry_hash"),
    "policies": (
        "id",
        "name",
        "configuration",
        "content_hash",
        "rules_hash",
        "author",
        "approver",
        "status",
        "justification",
        "simulation",
        "created_at",
        "approved_at",
    ),
    "policy_state": ("id", "active_version", "updated_at"),
    "cases": ("alert_id", "assigned_to", "updated_at"),
    "case_events": ("id", "alert_id", "actor", "kind", "detail", "ts"),
    "risk": ("agent_id", "score", "tier", "breakdown", "baseline", "updated_at"),
    "traces": ("span_id", "trace_id", "parent_id", "name", "service", "start_ns", "end_ns", "status", "attributes"),
}


def record(row, fields: tuple[str, ...]) -> dict:
    return jsonable_encoder({name: getattr(row, name) for name in fields})


async def snapshot(s: AsyncSession, generated_by: str, source: str) -> dict:
    """Read one consistent PostgreSQL snapshot, including policy and investigation evidence."""
    if s.bind.dialect.name == "postgresql":
        await s.connection(execution_options={"isolation_level": "REPEATABLE READ"})
    tables = {
        "agents": (Agent, Agent.id),
        "mandates": (Mandate, Mandate.issued_at),
        "decisions": (DecisionRecord, DecisionRecord.ts),
        "approvals": (Approval, Approval.created_at),
        "alerts": (Alert, Alert.ts),
        "ledger": (LedgerEntry, LedgerEntry.seq),
        "policies": (PolicyVersion, PolicyVersion.created_at),
        "policy_state": (PolicyState, PolicyState.id),
        "cases": (AlertCase, AlertCase.alert_id),
        "case_events": (CaseEvent, CaseEvent.ts),
        "risk": (AgentRisk, AgentRisk.agent_id),
        "traces": (TraceSpan, TraceSpan.start_ns),
    }
    rows = {}
    for name, (model, order) in tables.items():
        rows[name] = (await s.execute(select(model).order_by(order))).scalars().all()
    integrity = ledger.verify_entries(rows["ledger"])
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "generated_by": generated_by,
        "source": source,
        "integrity": integrity,
        "counts": {name: len(items) for name, items in rows.items()},
        "records": {name: [record(item, FIELDS[name]) for item in items] for name, items in rows.items()},
    }


def evidence_index(pack: dict) -> list[dict]:
    counts = pack["counts"]
    return [
        {
            "question": "Who owns the agents?",
            "files": ["records/agents.json", "records/ledger.json"],
            "observed_records": counts["agents"],
        },
        {
            "question": "Which task-scoped access was issued?",
            "files": ["records/mandates.json", "records/decisions.json"],
            "observed_records": counts["mandates"],
        },
        {
            "question": "Which actions required human approval?",
            "files": ["records/approvals.json"],
            "observed_records": counts["approvals"],
        },
        {
            "question": "Which security events were detected?",
            "files": ["records/alerts.json"],
            "observed_records": counts["alerts"],
        },
        {
            "question": "Does the exported audit chain verify?",
            "files": ["records/ledger.json"],
            "observed_records": counts["ledger"],
        },
        {
            "question": "Who reviewed and activated policy changes?",
            "files": ["records/policies.json", "records/policy_state.json"],
            "observed_records": counts["policies"],
        },
        {
            "question": "What did SOC analysts investigate?",
            "files": ["records/cases.json", "records/case_events.json"],
            "observed_records": counts["case_events"],
        },
        {
            "question": "Which risk signals and execution timings were recorded?",
            "files": ["records/risk.json", "records/traces.json"],
            "observed_records": counts["traces"],
        },
    ]


def _table(headers: tuple[str, ...], rows: list[tuple]) -> str:
    if not rows:
        return '<p class="empty">No matching events were recorded in this session.</p>'
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(v or '—'))}</td>" for v in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def report_html(pack: dict) -> str:
    counts = pack["counts"]
    integrity = pack["integrity"]
    alerts = sorted(pack["records"]["alerts"], key=lambda a: a["ts"], reverse=True)[:12]
    approvals = sorted(pack["records"]["approvals"], key=lambda a: a["created_at"], reverse=True)[:12]
    denials = [d for d in reversed(pack["records"]["decisions"]) if d["decision"] == "deny"][:12]
    index = evidence_index(pack)
    cards = "".join(
        f'<div class="card"><strong>{counts[key]:,}</strong><span>{label}</span></div>'
        for key, label in (
            ("agents", "Agents"),
            ("mandates", "Mandates"),
            ("decisions", "Decisions"),
            ("approvals", "Approvals"),
            ("alerts", "Alerts"),
            ("ledger", "Ledger entries"),
        )
    )
    index_rows = [(row["question"], str(row["observed_records"]), ", ".join(row["files"])) for row in index]
    alert_rows = [(a["ts"], a["id"], a["rule_id"], a["severity"], a["title"]) for a in alerts]
    approval_rows = [(a["created_at"], a["id"], a["tool"], a["status"], a["approver"] or "—") for a in approvals]
    denial_rows = [(d["ts"], d["id"], d["action"], ", ".join(r.get("rule", "") for r in d["reasons"])) for d in denials]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis AI · Demo evidence pack</title><style>
body{{font:15px/1.55 system-ui,sans-serif;color:#152337;background:#f3f6fa;margin:0}}
main{{max-width:1100px;margin:auto;padding:36px 24px 80px}}h1{{font-size:34px;margin:0}}h2{{margin-top:36px}}
.sub{{color:#506074}}.banner{{background:#132b49;color:white;padding:30px;border-radius:16px}}
.banner .sub{{color:#c8d7e8}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px;margin:22px 0}}
.card{{background:white;border:1px solid #dce5ef;border-radius:12px;padding:17px;display:flex;flex-direction:column}}
.card strong{{font-size:25px}}.card span{{color:#506074}}table{{border-collapse:collapse;width:100%;background:white}}
th,td{{border-bottom:1px solid #dce5ef;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#eaf0f7}}.scroll{{overflow-x:auto;border:1px solid #dce5ef;border-radius:12px}}
.note{{background:#fff8e8;border-left:4px solid #d69e25;padding:16px}}code{{overflow-wrap:anywhere}}
.empty{{color:#506074}}
@media print{{body{{background:white}}main{{padding:0}}.banner{{color:#152337;background:white}}}}
</style></head><body><main>
<div class="banner"><h1>Aegis AI · Demo evidence pack</h1>
<p class="sub">Generated {html.escape(pack["generated_at"])} UTC by {html.escape(pack["generated_by"])}</p>
<p>Audit chain: <strong>{"VERIFIED" if integrity["ok"] else "FAILED"}</strong> ·
{integrity["entries"]:,} entries · tip <code>{html.escape(integrity.get("tip", "none"))}</code></p></div>
<div class="grid">{cards}</div>
<h2>Evidence index</h2><p>These are pointers to recorded data, not regulatory compliance verdicts.</p>
<div class="scroll">{_table(("Question", "Records", "Files"), index_rows)}</div>
<h2>Recent security alerts</h2>
<div class="scroll">{_table(("Time", "Alert ID", "Rule", "Severity", "Finding"), alert_rows)}</div>
<h2>Recent human approvals</h2>
<p>A <em>consumed</em> approval was approved and then used for its one bound action.</p>
<div class="scroll">{_table(("Requested", "Approval ID", "Tool", "Status", "Approver"), approval_rows)}</div>
<h2>Recent denied actions</h2>
<div class="scroll">{_table(("Time", "Decision ID", "Action", "Reason codes"), denial_rows)}</div>
<h2>How to verify and use this pack</h2>
<p>Run <code>python verify_pack.py &lt;zip-file&gt;</code> after extracting the verifier. It checks every file hash
and recomputes the ledger chain. The JSON files contain the exported evidence fields for investigation.</p>
<div class="note"><strong>Scope and limitations.</strong> This is synthetic, local-demo evidence from
{html.escape(pack["source"])}. It is not a certified EU AI Act or DORA report. The hash manifest is not
externally signed or timestamped; an independent trust anchor is needed to prove authenticity after export.
The role gate uses the passwordless demo IdP, not production authentication. Treat the ZIP as confidential
because approval arguments and policy inputs may contain sensitive data.</div>
</main></body></html>"""


def build_zip(pack: dict) -> bytes:
    files = {
        f"records/{name}.json": (json.dumps(rows, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        for name, rows in pack["records"].items()
    }
    files["evidence_index.json"] = (json.dumps(evidence_index(pack), ensure_ascii=False, indent=2) + "\n").encode()
    files["report.html"] = report_html(pack).encode()
    files["verify_pack.py"] = Path(__file__).with_name("evidence_verify.py").read_bytes()
    files["README.txt"] = (
        b"Aegis AI demo evidence pack\n\nOpen report.html first. To verify all file hashes and the audit chain, "
        b"extract verify_pack.py and run: python verify_pack.py <path-to-this-zip>\n\n"
        b"This pack is synthetic demo data, not a certified regulatory report. The manifest is not externally "
        b"signed or timestamped. Keep the ZIP confidential; policy inputs and approval arguments may contain "
        b"sensitive data.\n"
    )
    manifest = {
        "format": "aegis-demo-evidence-pack-v1",
        "generated_at": pack["generated_at"],
        "generated_by": pack["generated_by"],
        "source": pack["source"],
        "counts": pack["counts"],
        "ledger": pack["integrity"],
        "files": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in sorted(files.items())
        },
        "limitations": "Hashes and the ledger chain detect changes, but this pack has no external signature "
        "or timestamp.",
    }
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return output.getvalue()


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/evidence", tags=["evidence"])

    @r.get("/summary")
    async def summary(
        request: Request, s: AsyncSession = Depends(session), user: Persona = Depends(require_roles("auditor"))
    ):
        source = (
            "local in-memory SQLite demo"
            if ":memory:" in request.app.state.ctx.settings.database_url
            else "Aegis database"
        )
        pack = await snapshot(s, user.username, source)
        return {key: pack[key] for key in ("generated_at", "source", "integrity", "counts")}

    @r.get("/pack")
    async def download_pack(
        request: Request, s: AsyncSession = Depends(session), user: Persona = Depends(require_roles("auditor"))
    ):
        source = (
            "local in-memory SQLite demo"
            if ":memory:" in request.app.state.ctx.settings.database_url
            else "Aegis database"
        )
        pack = await snapshot(s, user.username, source)
        if not pack["integrity"]["ok"]:
            raise HTTPException(409, f"Audit ledger verification failed at entry {pack['integrity']['broken_at_seq']}")
        filename = f"aegis-evidence-{datetime.now(UTC):%Y%m%d-%H%M%S}.zip"
        return Response(
            build_zip(pack),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    return r
