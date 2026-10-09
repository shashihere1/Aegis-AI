"""Auditor-only, signed and self-verifying evidence bundle for the local Aegis demonstration."""

import hashlib
import html
import io
import json
import zipfile
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.control import attestation, ledger
from aegis.control.auth import require_roles
from aegis.control.context import ControlContext, ctx, session
from aegis.control.identity.idp import Persona
from aegis.control.tables import (
    Agent,
    AgentRisk,
    Alert,
    AlertCase,
    Approval,
    CaseEvent,
    DecisionRecord,
    LedgerCheckpoint,
    LedgerEntry,
    Mandate,
    PolicyState,
    PolicyVersion,
    TraceSpan,
)

FORMAT = "aegis-demo-evidence-pack-v2"

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
    "checkpoints": ("id", "entries", "tip", "ts", "signed_by", "key_fingerprint", "jws"),
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

# Activity records a date range narrows, and the time each one happened. Everything else is current state (who owns
# which agent, which policy is active) or integrity proof (the ledger and its checkpoints), exported whole: the chain
# can only be recomputed from its first entry.
PERIOD_FIELDS = {
    "mandates": "issued_at",
    "decisions": "ts",
    "approvals": "created_at",
    "alerts": "ts",
    "case_events": "ts",
    "traces": "start_ns",
}

# Where each regulatory expectation's evidence sits in the pack. Pointers for an auditor, not compliance verdicts.
REGULATIONS = (
    ("EU AI Act", "Art. 9", "Risk management system",
     "Per-agent risk scores and tiers; governed policy versions with simulation before activation.",
     ("risk", "policies")),
    ("EU AI Act", "Art. 12", "Record-keeping",
     "Automatic, hash-chained log of every decision, approval and lifecycle change, with signed checkpoints.",
     ("ledger", "checkpoints", "decisions")),
    ("EU AI Act", "Art. 14", "Human oversight",
     "High-impact actions held for a named human; who approved, why, and the one action it was bound to.",
     ("approvals",)),
    ("EU AI Act", "Art. 15", "Accuracy, robustness and cybersecurity",
     "Denied actions with reason codes; detected attacks and the containment applied.",
     ("decisions", "alerts")),
    ("EU AI Act", "Art. 26", "Deployer obligations: monitoring and log retention",
     "Runtime monitoring alerts and the retained audit log for each deployed agent.",
     ("alerts", "ledger")),
    ("DORA", "Art. 8", "Identification of ICT assets",
     "Inventory of every agent with its owner, sponsor, environment and autonomy level.",
     ("agents",)),
    ("DORA", "Art. 9", "Protection and prevention (least privilege)",
     "Task-scoped, expiring mandates and the policy decision behind each tool call.",
     ("mandates", "decisions")),
    ("DORA", "Art. 10", "Detection of anomalous activity",
     "Detection-rule alerts raised on agent behaviour.",
     ("alerts",)),
    ("DORA", "Art. 17", "ICT-related incident management",
     "Alert triage, case assignment and the analyst's investigation steps.",
     ("alerts", "cases", "case_events")),
    ("GDPR", "Art. 5(2)", "Accountability",
     "Tamper-evident record of who changed policy, who approved it and what it decided.",
     ("ledger", "policies")),
    ("GDPR", "Art. 25", "Data protection by design and by default",
     "Redaction obligations and data-class limits enforced on each decision.",
     ("decisions", "policies")),
    ("GDPR", "Art. 30", "Records of processing activities",
     "Each agent's stated purpose and the access issued to it, per task.",
     ("agents", "mandates")),
    ("GDPR", "Art. 32", "Security of processing",
     "Access control decisions, detected misuse and an integrity-protected audit trail.",
     ("decisions", "alerts", "ledger")),
)


def record(row, fields: tuple[str, ...]) -> dict:
    return jsonable_encoder({name: getattr(row, name) for name in fields})


def period_bounds(start: date | None, end: date | None) -> tuple[datetime | None, datetime | None]:
    """Whole UTC days, both inclusive: [start 00:00, the day after end 00:00)."""
    if start and end and start > end:
        raise HTTPException(422, "'from' must be on or before 'to'")
    lower = datetime.combine(start, time.min, UTC) if start else None
    upper = datetime.combine(end + timedelta(days=1), time.min, UTC) if end else None
    return lower, upper


def _moment(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, int):  # trace spans record nanoseconds since the epoch
        return datetime.fromtimestamp(value / 1e9, UTC)
    return value if value.tzinfo else value.replace(tzinfo=UTC)  # SQLite returns naive UTC


def in_period(value, lower: datetime | None, upper: datetime | None) -> bool:
    moment = _moment(value)
    if moment is None:
        return lower is None and upper is None
    return (lower is None or moment >= lower) and (upper is None or moment < upper)


async def snapshot(
    s: AsyncSession, generated_by: str, source: str, start: date | None = None, end: date | None = None
) -> dict:
    """Read one consistent PostgreSQL snapshot, including policy and investigation evidence."""
    lower, upper = period_bounds(start, end)
    if s.bind.dialect.name == "postgresql":
        await s.connection(execution_options={"isolation_level": "REPEATABLE READ"})
    tables = {
        "agents": (Agent, Agent.id),
        "mandates": (Mandate, Mandate.issued_at),
        "decisions": (DecisionRecord, DecisionRecord.ts),
        "approvals": (Approval, Approval.created_at),
        "alerts": (Alert, Alert.ts),
        "ledger": (LedgerEntry, LedgerEntry.seq),
        "checkpoints": (LedgerCheckpoint, LedgerCheckpoint.id),
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
        if name in PERIOD_FIELDS and (lower or upper):
            rows[name] = [r for r in rows[name] if in_period(getattr(r, PERIOD_FIELDS[name]), lower, upper)]
    integrity = ledger.verify_entries(rows["ledger"])
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "generated_by": generated_by,
        "source": source,
        "period": {
            "from": start.isoformat() if start else None,
            "to": end.isoformat() if end else None,
            "filtered": sorted(PERIOD_FIELDS) if (lower or upper) else [],
            "timezone": "UTC",
        },
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
            "question": "Does the exported audit chain verify, and was it signed?",
            "files": ["records/ledger.json", "records/checkpoints.json", "signature.jws"],
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


def regulatory_mapping(pack: dict) -> list[dict]:
    counts = pack["counts"]
    return [
        {
            "regulation": regulation,
            "reference": reference,
            "expectation": expectation,
            "evidence": evidence,
            "files": [f"records/{key}.json" for key in keys],
            "observed_records": sum(counts[key] for key in keys),
        }
        for regulation, reference, expectation, evidence, keys in REGULATIONS
    ]


def _table(headers: tuple[str, ...], rows: list[tuple]) -> str:
    if not rows:
        return '<p class="empty">No matching events were recorded in this session.</p>'
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(v or '—'))}</td>" for v in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def period_text(period: dict) -> str:
    if not period["filtered"]:
        return "all recorded activity"
    return f"activity from {period['from'] or 'the first record'} to {period['to'] or 'now'} (UTC, inclusive)"


def report_html(pack: dict, signing: dict) -> str:
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
    regulation_rows = [
        (f"{m['regulation']} {m['reference']}", m["expectation"], m["evidence"], str(m["observed_records"]),
         ", ".join(m["files"]))
        for m in regulatory_mapping(pack)
    ]
    regulation_table = _table(
        ("Reference", "Expectation", "What Aegis recorded", "Records", "Files"), regulation_rows
    )
    alert_rows = [(a["ts"], a["id"], a["rule_id"], a["severity"], a["title"]) for a in alerts]
    approval_rows = [(a["created_at"], a["id"], a["tool"], a["status"], a["approver"] or "—") for a in approvals]
    denial_rows = [(d["ts"], d["id"], d["action"], ", ".join(r.get("rule", "") for r in d["reasons"])) for d in denials]
    checkpoint_rows = [(c["id"], c["ts"], str(c["entries"]), c["tip"][:16] + "…", c["signed_by"])
                       for c in reversed(pack["records"]["checkpoints"][-12:])]
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
<p class="sub">Generated {html.escape(pack["generated_at"])} UTC by {html.escape(pack["generated_by"])} ·
covers {html.escape(period_text(pack["period"]))}</p>
<p>Audit chain: <strong>{"VERIFIED" if integrity["ok"] else "FAILED"}</strong> ·
{integrity["entries"]:,} entries · tip <code>{html.escape(integrity.get("tip", "none"))}</code></p>
<p>Signed with evidence key <code>{html.escape(signing["fingerprint"])}</code> ({html.escape(signing["mode"])}) ·
checkpoint #{signing["checkpoint_id"]}</p></div>
<div class="grid">{cards}</div>
<h2>Evidence index</h2><p>These are pointers to recorded data, not regulatory compliance verdicts.</p>
<div class="scroll">{_table(("Question", "Records", "Files"), index_rows)}</div>
<h2>Regulatory mapping</h2>
<p>Where the evidence for each expectation in the EU AI Act, DORA and GDPR sits in this pack. It shows what Aegis
recorded; whether that satisfies an obligation is for your compliance function to judge.</p>
<div class="scroll">{regulation_table}</div>
<h2>Recent security alerts</h2>
<div class="scroll">{_table(("Time", "Alert ID", "Rule", "Severity", "Finding"), alert_rows)}</div>
<h2>Recent human approvals</h2>
<p>A <em>consumed</em> approval was approved and then used for its one bound action.</p>
<div class="scroll">{_table(("Requested", "Approval ID", "Tool", "Status", "Approver"), approval_rows)}</div>
<h2>Recent denied actions</h2>
<div class="scroll">{_table(("Time", "Decision ID", "Action", "Reason codes"), denial_rows)}</div>
<h2>Signed ledger checkpoints</h2>
<p>Each checkpoint is a signed statement of the chain's length and last hash. If the chain is rewritten after a
checkpoint, even with every hash recomputed, the checkpoint no longer matches.</p>
<div class="scroll">{_table(("#", "Signed at", "Entries", "Tip", "Signed by"), checkpoint_rows)}</div>
<h2>How to verify and use this pack</h2>
<p>Extract the verifier and run <code>python verify_pack.py &lt;zip-file&gt; --key
{html.escape(signing["fingerprint"])}</code>. It checks the signature on the manifest, every file hash, the ledger
chain, and every signed checkpoint against the chain. Compare the key with the fingerprint Aegis publishes at
<code>/v1/evidence/key</code> or one you recorded earlier; without <code>--key</code> the verifier proves the pack is
intact and self-consistent, not who made it. Signature checks need the <code>cryptography</code> package.</p>
<div class="note"><strong>Scope and limitations.</strong> This is synthetic, local-demo evidence from
{html.escape(pack["source"])}. It is not a certified EU AI Act, DORA or GDPR report. The evidence key is a local
file, not an HSM or Key Vault key, and the signature carries no trusted timestamp. The ledger and checkpoints are
always exported in full, because the chain can only be recomputed from its first entry; a date range narrows the
activity records only. Treat the ZIP as confidential because approval arguments and policy inputs may contain
sensitive data.</div>
</main></body></html>"""


def build_zip(pack: dict, key, checkpoint_id: int, mode: str, issuer: str) -> bytes:
    fingerprint = key.fingerprint
    signing = {"fingerprint": fingerprint, "mode": mode, "checkpoint_id": checkpoint_id}
    files = {
        f"records/{name}.json": (json.dumps(rows, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        for name, rows in pack["records"].items()
    }
    files["evidence_index.json"] = (json.dumps(evidence_index(pack), ensure_ascii=False, indent=2) + "\n").encode()
    files["regulatory_mapping.json"] = (
        json.dumps(regulatory_mapping(pack), ensure_ascii=False, indent=2) + "\n"
    ).encode()
    files["report.html"] = report_html(pack, signing).encode()
    files["verify_pack.py"] = Path(__file__).with_name("evidence_verify.py").read_bytes()
    files["README.txt"] = (
        "Aegis AI demo evidence pack\n\nOpen report.html first. To verify the signature, all file hashes, the audit "
        "chain and its signed checkpoints, extract verify_pack.py and run:\n\n"
        f"    python verify_pack.py <path-to-this-zip> --key {fingerprint}\n\n"
        "Compare that key fingerprint with the one Aegis publishes at /v1/evidence/key. Signature checks need the "
        "Python 'cryptography' package.\n\nThis pack is synthetic demo data, not a certified regulatory report. The "
        "evidence key is a local file and the signature has no trusted timestamp. Keep the ZIP confidential; policy "
        "inputs and approval arguments may contain sensitive data.\n"
    ).encode()
    manifest = {
        "format": FORMAT,
        "generated_at": pack["generated_at"],
        "generated_by": pack["generated_by"],
        "source": pack["source"],
        "period": pack["period"],
        "counts": pack["counts"],
        "ledger": pack["integrity"],
        "checkpoint_id": checkpoint_id,
        "evidence_key": {"fingerprint": fingerprint, "mode": mode, "jwk": attestation.public_key(key)},
        "files": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in sorted(files.items())
        },
        "limitations": "Signed with a local evidence key, without a trusted timestamp. Pin the key fingerprint to "
        "prove who signed it.",
    }
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    claims = {
        "typ": attestation.PACK,
        "iss": issuer,
        "iat": int(datetime.now(UTC).timestamp()),
        "manifest_sha256": hashlib.sha256(files["manifest.json"]).hexdigest(),
    }
    files["signature.jws"] = (attestation.sign(key, claims) + "\n").encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return output.getvalue()


def _source(c: ControlContext) -> str:
    return "local in-memory SQLite demo" if ":memory:" in c.settings.database_url else "Aegis database"


def _key_mode(c: ControlContext) -> str:
    return "persistent local key" if c.settings.evidence_key_file else "ephemeral key (changes on restart)"


def _issuer(c: ControlContext) -> str:
    return f"{c.settings.control_url}/evidence"


def router() -> APIRouter:
    r = APIRouter(prefix="/v1/evidence", tags=["evidence"])
    auditor = require_roles("auditor")

    @r.get("/key")
    async def evidence_key(c: ControlContext = Depends(ctx)):
        """Public: the key evidence packs and checkpoints are signed with, to pin when verifying a pack."""
        return {"fingerprint": c.evidence_key.fingerprint, "mode": _key_mode(c), "issuer": _issuer(c),
                "keys": [attestation.public_key(c.evidence_key)]}

    @r.get("/summary")
    async def summary(
        start: date | None = Query(None, alias="from"),
        end: date | None = Query(None, alias="to"),
        s: AsyncSession = Depends(session),
        user: Persona = Depends(auditor),
        c: ControlContext = Depends(ctx),
    ):
        pack = await snapshot(s, user.username, _source(c), start, end)
        latest = pack["records"]["checkpoints"][-1] if pack["records"]["checkpoints"] else None
        return {key: pack[key] for key in ("generated_at", "source", "period", "integrity", "counts")} | {
            "evidence_key": {"fingerprint": c.evidence_key.fingerprint, "mode": _key_mode(c)},
            "latest_checkpoint": (
                {k: latest[k] for k in ("id", "entries", "tip", "ts", "signed_by")} if latest else None
            ),
            "regulations": [
                {k: m[k] for k in ("regulation", "reference", "expectation", "observed_records")}
                for m in regulatory_mapping(pack)
            ],
        }

    @r.get("/pack")
    async def download_pack(
        start: date | None = Query(None, alias="from"),
        end: date | None = Query(None, alias="to"),
        s: AsyncSession = Depends(session),
        user: Persona = Depends(auditor),
        c: ControlContext = Depends(ctx),
    ):
        pack = await snapshot(s, user.username, _source(c), start, end)
        if not pack["integrity"]["ok"]:
            raise HTTPException(409, f"Audit ledger verification failed at entry {pack['integrity']['broken_at_seq']}")
        await s.rollback()  # end the read snapshot; the checkpoint and ledger event are written fresh below
        async with c.db.sessionmaker() as w:
            checkpoint = await attestation.record_checkpoint(
                w, c.evidence_key, user.username, _issuer(c), pack["integrity"]["entries"], pack["integrity"]["tip"]
            )
            pack["records"]["checkpoints"].append(attestation.checkpoint_record(checkpoint))
            pack["counts"]["checkpoints"] += 1
            body = build_zip(pack, c.evidence_key, checkpoint.id, _key_mode(c), _issuer(c))
            await ledger.append(w, "evidence.exported", user.username, f"checkpoint:{checkpoint.id}", {
                "period": pack["period"], "entries": checkpoint.entries, "tip": checkpoint.tip,
                "pack_sha256": hashlib.sha256(body).hexdigest(), "key_fingerprint": c.evidence_key.fingerprint,
            })
            await w.commit()
        filename = f"aegis-evidence-{datetime.now(UTC):%Y%m%d-%H%M%S}.zip"
        return Response(
            body,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @r.get("/checkpoints")
    async def checkpoints(
        limit: int = Query(50, ge=1, le=500),
        s: AsyncSession = Depends(session),
        _: Persona = Depends(require_roles("auditor", "admin", "soc-analyst")),
        c: ControlContext = Depends(ctx),
    ):
        """Recent checkpoints, each re-checked: is the signature good, and does today's chain still contain it?"""
        entries = (await s.execute(select(LedgerEntry).order_by(LedgerEntry.seq))).scalars().all()
        rows = (
            await s.execute(select(LedgerCheckpoint).order_by(LedgerCheckpoint.id.desc()).limit(limit))
        ).scalars().all()
        return [attestation.checkpoint_status(row, entries, c.evidence_key) for row in rows]

    @r.post("/checkpoints", status_code=201)
    async def create_checkpoint(
        s: AsyncSession = Depends(session),
        user: Persona = Depends(require_roles("auditor", "admin")),
        c: ControlContext = Depends(ctx),
    ):
        try:
            row = await attestation.create_checkpoint(s, c.evidence_key, user.username, _issuer(c))
        except ValueError as exc:
            raise HTTPException(409, f"Not signed: {exc}") from exc
        signed = attestation.checkpoint_record(row)
        await s.commit()
        async with c.db.sessionmaker() as w:
            await ledger.append(w, "ledger.checkpoint", user.username, f"checkpoint:{signed['id']}",
                                {"entries": signed["entries"], "tip": signed["tip"],
                                 "key_fingerprint": signed["key_fingerprint"]})
            await w.commit()
        return signed

    return r
