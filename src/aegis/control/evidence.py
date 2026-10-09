"""Auditor-only, signed and self-verifying evidence bundle for the local Aegis demonstration."""

import csv
import hashlib
import html
import io
import json
import zipfile
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.control import attestation, ledger
from aegis.control.auth import require_roles
from aegis.control.context import ControlContext, ctx, session
from aegis.control.evidence_proofs import inclusion_proofs
from aegis.control.evidence_scope import moment, select_records
from aegis.control.evidence_verify import verify_jws
from aegis.control.identity.idp import Persona
from aegis.control.tables import (
    Agent,
    AgentRisk,
    Alert,
    AlertCase,
    Approval,
    CaseEvent,
    DecisionRecord,
    DiscoveryFinding,
    LedgerCheckpoint,
    LedgerEntry,
    Mandate,
    McpServer,
    PolicyState,
    PolicyVersion,
    Tool,
    TraceSpan,
    Usage,
)

FORMAT = "aegis-scoped-evidence-pack-v3"

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
        "orphaned",
        "attestation_due",
        "max_data_class",
        "idp_client_id",
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
    "tools": ("id", "server_id", "name", "status", "definition_hash", "approved_hash", "classification"),
    "servers": ("id", "owner", "vendor", "status", "created_at"),
    "usage": ("id", "ts", "agent_id", "mandate_id", "model", "input_tokens", "output_tokens", "cost_eur", "latency_ms"),
    "discovery": ("id", "sources", "suggested_owner", "agent_id", "status", "first_seen", "last_seen", "hits"),
}

# Activity uses the reporting period. Related inventory/risk/tool state is labelled current context.
# Only selected ledger payloads are disclosed; signed Merkle proofs commit to the verified source chain.
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
    if end == date.max:
        raise HTTPException(422, "'to' is outside the supported range")
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
    s: AsyncSession, generated_by: str, source: str, start: date | None = None, end: date | None = None,
    *, agent_id: str | None = None, root_id: str | None = None, framework: str = "all",
    lower: datetime | None = None, upper: datetime | None = None,
    signing_key=None,
) -> dict:
    """Verify the full source chain, but disclose only requested activity and related context."""
    from aegis.control.evidence_controls import FRAMEWORKS

    if framework != "all" and framework not in FRAMEWORKS:
        raise HTTPException(422, "Unknown evidence framework")
    if lower is None or upper is None:
        end = end or datetime.now(UTC).date()
        try:
            start = start or end - timedelta(days=6)
        except OverflowError as exc:
            raise HTTPException(422, "Reporting dates are outside the supported range") from exc
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
        "tools": (Tool, Tool.id),
        "servers": (McpServer, McpServer.id),
        "usage": (Usage, Usage.id),
        "discovery": (DiscoveryFinding, DiscoveryFinding.id),
    }
    rows = {}
    for name, (model, order) in tables.items():
        rows[name] = (await s.execute(select(model).order_by(order))).scalars().all()
    integrity = source_integrity(rows["ledger"], rows["checkpoints"], signing_key)
    if agent_id and not any(a.id == agent_id for a in rows["agents"]):
        raise HTTPException(404, "Unknown agent")
    if root_id and not any(m.root_id == root_id for m in rows["mandates"]):
        raise HTTPException(404, "Unknown root task")
    if agent_id and root_id and not any(
        m.root_id == root_id and (m.agent_id == agent_id or agent_id in m.chain) for m in rows["mandates"]
    ):
        raise HTTPException(422, "The selected agent is not part of this root task")
    source_ledger = [record(e, FIELDS["ledger"]) for e in rows["ledger"]]
    latest_checkpoint = attestation.checkpoint_record(rows["checkpoints"][-1]) if rows["checkpoints"] else None
    rows = select_records(rows, lower, upper, agent_id, root_id)
    proofs = inclusion_proofs(source_ledger, [record(e, FIELDS["ledger"]) for e in rows["ledger"]])
    context_records = {
        name: [getattr(row, "id", None) for row in rows[name]
               if moment(getattr(row, field)) is not None and not lower <= moment(getattr(row, field)) < upper]
        for name, field in PERIOD_FIELDS.items()
    }
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "generated_by": generated_by,
        "source": source,
        "period": {
            "from": lower.date().isoformat(),
            "to": (upper - timedelta(microseconds=1)).date().isoformat(),
            "start": lower.isoformat(),
            "end_exclusive": upper.isoformat(),
            "filtered": sorted(PERIOD_FIELDS | {"ledger": "ts"}),
            "timezone": "UTC",
        },
        "scope": {"agent_id": agent_id, "root_id": root_id, "framework": framework,
                  "context": "Related current inventory/risk/tools; referenced or currently active policy versions.",
                  "prior_context_records": {name: ids for name, ids in context_records.items() if ids},
                  "proof_mode": "signed-merkle-inclusion"},
        "ledger_proofs": proofs,
        "latest_checkpoint": latest_checkpoint,
        "integrity": integrity,
        "counts": {name: len(items) for name, items in rows.items()},
        "records": {name: [record(item, FIELDS[name]) for item in items] for name, items in rows.items()},
    }


def source_integrity(entries, checkpoints, key=None):
    """Detect recomputed source hashes and verify prior checkpoints signed by the available evidence key."""
    integrity = ledger.verify_entries(entries)
    public_key = attestation.public_key(key) if key else None
    for checkpoint in checkpoints:
        n = checkpoint.entries
        tip = entries[n - 1].entry_hash if 0 < n <= len(entries) else ledger.GENESIS if n == 0 else None
        valid = n >= 0 and tip == checkpoint.tip
        if valid and key and checkpoint.key_fingerprint == key.fingerprint:
            try:
                claims = verify_jws(checkpoint.jws, public_key)
                valid = (claims.get("typ"), claims.get("entries"), claims.get("tip"), claims.get("ts"),
                         claims.get("signed_by")) == (
                    attestation.CHECKPOINT, n, checkpoint.tip, checkpoint.ts, checkpoint.signed_by
                )
            except (ValueError, KeyError, TypeError):
                valid = False
        if not valid:
            return {"ok": False, "entries": len(entries), "broken_at_seq": n,
                    "problem": "Source chain or signature differs from an earlier checkpoint"}
    return integrity


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
    mappings = [
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
    from aegis.control.evidence_controls import FRAMEWORKS

    names = {"EU AI Act": "eu-ai-act", "DORA": "dora", "GDPR": "gdpr"}
    for item in mappings:
        item["source_url"] = FRAMEWORKS[names[item["regulation"]]]["url"]
        item["assessment"] = "human_review_required"
        item["limitations"] = (
            "Supporting evidence only, not a complete Article 30 processing register."
            if item["regulation"] == "GDPR" and item["reference"] == "Art. 30" else
            "Applicability and sufficiency require Compliance/Legal review."
        )
    framework = pack.get("scope", {}).get("framework", "all")
    return [m for m in mappings if framework == "all" or names[m["regulation"]] == framework]


def _table(headers: tuple[str, ...], rows: list[tuple]) -> str:
    if not rows:
        return '<p class="empty">No matching evidence was recorded in the selected scope.</p>'
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(v if v is not None else '—'))}</td>"
                                   for v in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def period_text(period: dict) -> str:
    if not period["filtered"]:
        return "all recorded activity"
    if period.get("start") and period.get("end_exclusive"):
        return f"activity from {period['start']} up to (not including) {period['end_exclusive']}"
    return f"activity from {period['from'] or 'the first record'} to {period['to'] or 'now'} (UTC, inclusive)"


def report_html(pack: dict, signing: dict) -> str:
    from aegis.control.evidence_controls import control_coverage, executive_summary

    counts = pack["counts"]
    coverage = control_coverage(pack)
    control_table = _table(("Control", "Evidence status", "Records", "Gaps / reviewer checks"), [
        (f"{c['id']} {c['title']}", c["status"], c["observed_records"], c["limitations"]) for c in coverage
    ])
    summary_text = html.escape(executive_summary(pack, coverage))
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
<h2>Executive summary (deterministic, not AI-generated)</h2><p>{summary_text}</p>
<h2>Aegis control coverage</h2><div class="scroll">{control_table}</div>
<p>Full evidence queries, record IDs and official reference links are in control_coverage.json.</p>
<h2>Selected scope</h2><p>{html.escape(json.dumps(pack['scope'], sort_keys=True))}</p>
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
{html.escape(signing["fingerprint"])}</code>. It checks the manifest signature, file hashes, the signed source
checkpoint and inclusion proofs for disclosed ledger entries. The server verified the full chain; this verifier
does not recompute undisclosed contents. Compare the key with the fingerprint Aegis publishes at
<code>/v1/evidence/key</code> or one you recorded earlier; without <code>--key</code> the verifier proves the pack is
intact and self-consistent, not who made it. Signature checks need the <code>cryptography</code> package.</p>
<div class="note"><strong>Scope and limitations.</strong> This is synthetic, local-demo evidence from
{html.escape(pack["source"])}. It is not a certified EU AI Act, DORA or GDPR report. The evidence key is a local
file, not an HSM or Key Vault key, and the signature carries no trusted timestamp. Only selected ledger entries
are disclosed. Signed Merkle inclusion proofs bind them to the server-verified source chain; an offline verifier
does not recompute undisclosed chain contents. Current related inventory and active policies are explicitly
marked as context, not historical state. Treat the ZIP as confidential: selected approval arguments and policy
inputs may contain sensitive data.</div>
</main></body></html>"""


def build_zip(pack: dict, key, checkpoint_id: int, mode: str, issuer: str) -> bytes:
    from aegis.control.evidence_controls import CATALOG, control_coverage, executive_summary

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
    coverage = control_coverage(pack)
    for name, value in {
        "control_catalog.json": CATALOG,
        "control_coverage.json": coverage,
        "ledger_proofs.json": pack["ledger_proofs"],
        "report.json": {"summary": executive_summary(pack, coverage), "summary_method": "deterministic",
                        "counts": pack["counts"], "period": pack["period"], "scope": pack["scope"],
                        "decision_statistics": {kind: sum(d["decision"] == kind for d in pack["records"]["decisions"])
                                                for kind in ("allow", "deny", "require_approval", "rate_limited")}},
    }.items():
        files[name] = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    for name, rows in pack["records"].items():
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(FIELDS[name])
        for row in rows:
            values = []
            for field in FIELDS[name]:
                value = row.get(field)
                text = (json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else
                        str(value) if value is not None else "")
                values.append("'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text)
            writer.writerow(values)
        files[f"csv/{name}.csv"] = output.getvalue().encode("utf-8")
    files["report.html"] = report_html(pack, signing).encode()
    files["verify_pack.py"] = Path(__file__).with_name("evidence_verify.py").read_bytes()
    files["README.txt"] = (
        "Aegis AI demo evidence pack\n\nOpen report.html first. To verify the signature, all file hashes, "
        "selected ledger inclusion proofs and source checkpoint, extract verify_pack.py and run:\n\n"
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
        "scope": pack["scope"],
        "counts": pack["counts"],
        "ledger": pack["integrity"] | {"proof_mode": "signed-merkle-inclusion",
                   "merkle_root": pack["ledger_proofs"]["root"], "disclosed_entries": pack["counts"]["ledger"]},
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
        agent_id: str | None = Query(None, min_length=1, max_length=20),
        root_id: str | None = Query(None, min_length=1, max_length=40),
        framework: str = Query("all"),
        s: AsyncSession = Depends(session),
        user: Persona = Depends(auditor),
        c: ControlContext = Depends(ctx),
    ):
        from aegis.control.evidence_controls import control_coverage, executive_summary

        pack = await snapshot(s, user.username, _source(c), start, end, signing_key=c.evidence_key,
                              agent_id=agent_id, root_id=root_id, framework=framework)
        latest = pack["latest_checkpoint"]
        return {key: pack[key] for key in ("generated_at", "source", "period", "scope", "integrity", "counts")} | {
            "coverage": control_coverage(pack),
            "executive_summary": executive_summary(pack, control_coverage(pack)),
            "automation": {"enabled": (c.settings.evidence_automation_enabled
                                       and ":memory:" not in c.settings.database_url),
                           "persistent_key": bool(c.settings.evidence_key_file),
                           "check_seconds": c.settings.evidence_check_seconds},
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
        agent_id: str | None = Query(None, min_length=1, max_length=20),
        root_id: str | None = Query(None, min_length=1, max_length=40),
        framework: str = Query("all"),
        user: Persona = Depends(auditor),
        c: ControlContext = Depends(ctx),
    ):
        from pydantic import ValidationError

        from aegis.control.evidence_reports import Scope, attachment, generate_report

        try:
            spec = Scope(start=start, end=end, agent_id=agent_id, root_id=root_id, framework=framework)
        except ValidationError as exc:
            raise HTTPException(422, "Invalid evidence scope") from exc
        result, body = await generate_report(c, user.username, spec)
        return attachment(body, result["id"])

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
