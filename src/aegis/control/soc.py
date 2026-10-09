"""SOC: detections, alerts, response playbooks, decisions, lineage and evidence views (plan §8.10-8.12)."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.ids import new_id
from aegis.common.models import AgentStatus
from aegis.control import investigations, ledger
from aegis.control.auth import OPERATORS, require_roles
from aegis.control.context import ControlContext, ctx, session
from aegis.control.discovery import record_signal
from aegis.control.identity import sts
from aegis.control.identity.idp import Persona
from aegis.control.tables import (
    Agent,
    Alert,
    Approval,
    DecisionRecord,
    DiscoveryFinding,
    LedgerEntry,
    Mandate,
    PolicyBundle,
    PolicyState,
    PolicyVersion,
    Tool,
    Usage,
)
from aegis.control.tools_registry import quarantine_tool
from aegis.guard import pii
from aegis.guard.detectors import scan_text


async def raise_alert(
    c: ControlContext, s: AsyncSession, rule_id: str, severity: str, title: str, agent_id: str | None, evidence: dict
) -> Alert:
    alert = Alert(
        id=new_id("alr"), rule_id=rule_id, severity=severity, title=title, agent_id=agent_id, evidence=evidence
    )
    s.add(alert)
    await ledger.append(s, "alert.raised", "soc", alert.id, {"rule": rule_id, "severity": severity, "agent": agent_id})
    if severity == "critical" and c.settings.auto_suspend_on_critical and agent_id:
        agent = await s.get(Agent, agent_id)
        if agent is not None and agent.status == AgentStatus.ACTIVE:
            # Response playbook: contain first, investigate second.
            radius = await sts.suspend_agent(c, s, agent_id, f"{rule_id}: {title}", "soc-playbook")
            alert.actions_taken = [{"action": "suspend_agent", "agent": agent_id, "blast_radius": radius}]
    return alert


async def on_decision(c: ControlContext, s: AsyncSession, record: DecisionRecord) -> None:
    rules = {r.get("rule") for r in record.reasons}
    if record.decision == "deny" and "IFC-001" in rules:
        await raise_alert(
            c,
            s,
            "DET-02",
            "critical",
            "Exfiltration attempt blocked (lethal trifecta)",
            record.agent_id,
            {"decision": record.id, "action": record.action, "mandate": record.mandate_id},
        )
    if record.decision == "deny" and record.agent_id:
        since = datetime.now(UTC) - timedelta(minutes=5)
        await s.flush()
        rows = (
            (
                await s.execute(
                    select(DecisionRecord.ts)
                    .where(DecisionRecord.agent_id == record.agent_id, DecisionRecord.decision == "deny")
                    .order_by(DecisionRecord.ts.desc())
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )
        denies = sum(1 for ts in rows if aware(ts) >= since)
        alerted = (
            (await s.execute(select(Alert.ts).where(Alert.rule_id == "DET-04", Alert.agent_id == record.agent_id)))
            .scalars()
            .all()
        )
        recent = any(aware(ts) >= since for ts in alerted)
        if denies >= 5 and not recent:
            await raise_alert(
                c,
                s,
                "DET-04",
                "medium",
                f"Burst of {denies} denied actions in 5 minutes",
                record.agent_id,
                {"denies": denies},
            )


async def on_event(c: ControlContext, s: AsyncSession, event: dict) -> None:
    kind = event.get("type")
    if kind == "guard.injection":
        await raise_alert(
            c,
            s,
            "DET-01",
            "high",
            f"Prompt injection detected in output of {event.get('tool')}",
            event.get("agent_id"),
            event,
        )
    elif kind == "token.revoked_use":
        await raise_alert(c, s, "DET-05", "high", "Revoked or expired mandate presented", event.get("agent_id"), event)
    elif kind == "tool.drift":
        tool = await s.get(Tool, event["tool"])
        if tool is not None:
            await quarantine_tool(
                s, tool, "definition changed after approval (possible rug pull)", "gateway", event.get("upstream")
            )
    elif kind == "discovery.unknown_client":
        await record_signal(s, "gateway", event["fingerprint"], {k: v for k, v in event.items() if k != "type"})


class ScanRequest(BaseModel):
    text: str


def aware(ts: datetime) -> datetime:
    """SQLite returns naive datetimes; everything is stored in UTC."""
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


async def agent_names(s: AsyncSession, ids) -> dict[str, str]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return dict((await s.execute(select(Agent.id, Agent.name).where(Agent.id.in_(wanted)))).all())


def decision_dict(d: DecisionRecord, names: dict[str, str]) -> dict:
    action_label = d.action
    if d.action.startswith("a2a:"):
        action_label = f"delegate to {names.get(d.action[4:], d.action[4:])}"
    return {
        "id": d.id,
        "ts": d.ts,
        "agent_id": d.agent_id,
        "agent_name": names.get(d.agent_id or ""),
        "subject": d.subject,
        "action": d.action,
        "action_label": action_label,
        "decision": d.decision,
        "reasons": d.reasons,
        "obligations": d.obligations,
        "policy_version": d.policy_version,
        "mandate_id": d.mandate_id,
        "root_id": d.root_id,
        "data_class": d.data_class,
        "trace_id": d.trace_id,
        "latency_ms": d.latency_ms,
        "redactions": (d.input_snapshot or {}).get("redactions", 0),
    }


def router() -> APIRouter:
    r = APIRouter(prefix="/v1", tags=["soc", "evidence"], dependencies=[Depends(require_roles(*OPERATORS))])

    @r.get("/alerts")
    async def alerts(status: str | None = None, s: AsyncSession = Depends(session)):
        query = select(Alert).order_by(Alert.ts.desc())
        if status:
            query = query.where(Alert.status == status)
        rows = (await s.execute(query.limit(200))).scalars().all()
        names = await agent_names(s, [a.agent_id for a in rows])
        return [
            {
                "id": a.id,
                "ts": a.ts,
                "rule_id": a.rule_id,
                "severity": a.severity,
                "title": a.title,
                "agent_id": a.agent_id,
                "agent_name": names.get(a.agent_id or ""),
                "evidence": a.evidence,
                "actions_taken": a.actions_taken,
                "status": a.status,
            }
            for a in rows
        ]

    @r.patch("/alerts/{alert_id}")
    async def update_alert(
        alert_id: str,
        body: investigations.CaseUpdate,
        c=Depends(ctx),
        s: AsyncSession = Depends(session),
        user: Persona = Depends(require_roles("soc-analyst")),
    ):
        alert = await s.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(404, "unknown alert")
        return await investigations.update_case(c, s, alert, body, user)

    @r.get("/decisions")
    async def decisions(
        agent_id: str | None = None,
        root_id: str | None = None,
        decision: str | None = None,
        limit: int = 100,
        s: AsyncSession = Depends(session),
    ):
        query = select(DecisionRecord).order_by(DecisionRecord.ts.desc())
        if agent_id:
            query = query.where(DecisionRecord.agent_id == agent_id)
        if root_id:
            query = query.where(DecisionRecord.root_id == root_id)
        if decision:
            query = query.where(DecisionRecord.decision == decision)
        rows = (await s.execute(query.limit(min(limit, 500)))).scalars().all()
        names = await agent_names(
            s, [d.agent_id for d in rows] + [d.action[4:] for d in rows if d.action.startswith("a2a:")]
        )
        return [decision_dict(d, names) for d in rows]

    @r.get("/tasks")
    async def tasks(limit: int = 50, s: AsyncSession = Depends(session)):
        """Recent tasks (root mandates) with their delegations and decision counts."""
        roots = (
            (
                await s.execute(
                    select(Mandate)
                    .where(Mandate.parent_id.is_(None))
                    .order_by(Mandate.issued_at.desc())
                    .limit(min(limit, 200))
                )
            )
            .scalars()
            .all()
        )
        if not roots:
            return []
        root_ids = [m.root_id for m in roots]
        members = (await s.execute(select(Mandate).where(Mandate.root_id.in_(root_ids)))).scalars().all()
        counts = (
            await s.execute(
                select(DecisionRecord.root_id, DecisionRecord.decision, func.count())
                .where(DecisionRecord.root_id.in_(root_ids))
                .group_by(DecisionRecord.root_id, DecisionRecord.decision)
            )
        ).all()
        names = await agent_names(s, [a for m in members for a in m.chain])
        out = []
        for root in roots:
            group = [m for m in members if m.root_id == root.root_id]
            agents = list(dict.fromkeys(a for m in group for a in m.chain))
            out.append(
                {
                    "root_id": root.root_id,
                    "subject": root.subject,
                    "agent_id": root.agent_id,
                    "agent_name": names.get(root.agent_id),
                    "intent": root.intent,
                    "intent_categories": root.intent_categories,
                    "issued_at": root.issued_at,
                    "status": root.status,
                    "revoked_reason": root.revoked_reason,
                    "agents": [{"id": a, "name": names.get(a, a)} for a in agents],
                    "decisions": {d: n for rid, d, n in counts if rid == root.root_id},
                }
            )
        return out

    @r.get("/lineage/{root_id}")
    async def lineage(root_id: str, s: AsyncSession = Depends(session)):
        """User -> agents -> tools -> data for one task (plan §8.10)."""
        mandates = (
            (await s.execute(select(Mandate).where(Mandate.root_id == root_id).order_by(Mandate.issued_at)))
            .scalars()
            .all()
        )
        if not mandates:
            raise HTTPException(404, "unknown task")
        decisions = (
            (
                await s.execute(
                    select(DecisionRecord).where(DecisionRecord.root_id == root_id).order_by(DecisionRecord.ts)
                )
            )
            .scalars()
            .all()
        )
        names = await agent_names(s, [m.agent_id for m in mandates])
        subject = mandates[0].subject
        nodes = {subject: {"id": subject, "kind": "user", "label": subject.split(":", 1)[-1]}}
        edges = []
        by_id = {m.id: m for m in mandates}
        for m in mandates:
            nodes[f"agent:{m.agent_id}"] = {
                "id": f"agent:{m.agent_id}",
                "kind": "agent",
                "mandate": m.id,
                "status": m.status,
                "label": names.get(m.agent_id, m.agent_id),
                "depth": m.depth,
                "intent_categories": m.intent_categories,
            }
            source = f"agent:{by_id[m.parent_id].agent_id}" if m.parent_id in by_id else subject
            edges.append(
                {
                    "from": source,
                    "to": f"agent:{m.agent_id}",
                    "kind": "delegated_to" if m.parent_id else "initiated",
                    "intent": m.intent,
                }
            )
        for d in decisions:
            if d.action.startswith("a2a:"):
                continue  # delegations are already drawn as agent -> agent edges
            target = f"tool:{d.action}"
            nodes[target] = {"id": target, "kind": "tool", "label": d.action}
            edges.append(
                {
                    "from": f"agent:{d.agent_id}",
                    "to": target,
                    "kind": "invoked",
                    "decision": d.decision,
                    "rules": [r.get("rule") for r in d.reasons],
                    "decision_id": d.id,
                }
            )
            if d.data_class and d.decision == "allow":
                data = f"data:{d.data_class}"
                nodes[data] = {"id": data, "kind": "data", "label": d.data_class}
                edges.append({"from": target, "to": data, "kind": "read"})
        return {"root_id": root_id, "nodes": list(nodes.values()), "edges": edges}

    @r.get("/soc/summary")
    async def soc_summary(minutes: int = 30, s: AsyncSession = Depends(session)):
        now = datetime.now(UTC)
        since = now - timedelta(minutes=minutes)
        recent = [
            d
            for d in (await s.execute(select(DecisionRecord).order_by(DecisionRecord.ts.desc()).limit(5000))).scalars()
            if aware(d.ts) >= since
        ]
        buckets = []
        for i in range(minutes, 0, -1):
            start = now - timedelta(minutes=i)
            row = {"t": start.isoformat(), "allow": 0, "require_approval": 0, "deny": 0, "rate_limited": 0}
            buckets.append(row)
        for d in recent:
            idx = min(int((aware(d.ts) - since).total_seconds() // 60), minutes - 1)
            if d.decision in buckets[idx]:
                buckets[idx][d.decision] += 1
        totals = {k: sum(b[k] for b in buckets) for k in ("allow", "require_approval", "deny", "rate_limited")}
        denied: dict[str, int] = {}
        for d in recent:
            if d.decision == "deny" and d.agent_id:
                denied[d.agent_id] = denied.get(d.agent_id, 0) + 1
        names = await agent_names(s, denied)
        alerts = (await s.execute(select(Alert))).scalars().all()
        pending = (await s.execute(select(func.count()).where(Approval.status == "pending"))).scalar_one()
        active = (await s.execute(select(func.count()).where(Mandate.status == "active"))).scalar_one()
        findings = (await s.execute(select(func.count()).where(DiscoveryFinding.status == "open"))).scalar_one()
        total = sum(totals.values())
        return {
            "window_minutes": minutes,
            "buckets": buckets,
            "totals": totals,
            "decisions": total,
            "deny_rate": round(totals["deny"] / total, 3) if total else 0.0,
            "top_denied": sorted(
                ({"agent_id": a, "agent_name": names.get(a, a), "denies": n} for a, n in denied.items()),
                key=lambda x: -x["denies"],
            )[:5],
            "alerts": {
                "open": sum(1 for a in alerts if a.status == "new"),
                "by_severity": {
                    sev: sum(1 for a in alerts if a.severity == sev) for sev in ("critical", "high", "medium", "low")
                },
                "injections": sum(1 for a in alerts if a.rule_id == "DET-01"),
                "exfiltration_blocked": sum(1 for a in alerts if a.rule_id == "DET-02"),
            },
            "pending_approvals": pending,
            "active_mandates": active,
            "open_findings": findings,
        }

    @r.get("/policies")
    async def policies(request: Request, s=Depends(session)):
        """The active version's configuration and the Rego that actually runs; lifecycle is under /policies/versions."""
        settings = request.app.state.ctx.settings
        state = await s.get(PolicyState, "tool-call")
        active = await s.get(PolicyVersion, state.active_version)
        bundle = await s.get(PolicyBundle, state.active_version)
        if bundle is not None:
            files = dict(bundle.modules)
        else:  # a version saved before rules were versioned: show the repository files it was approved for
            policy_dir = Path(settings.policy_dir)
            files = {f.name: f.read_text(encoding="utf-8") for f in sorted(policy_dir.glob("*.rego"))}
        rules = []
        for name, text in files.items():
            if not name.endswith(".rego"):
                continue
            for block in re.finditer(r"(deny|approval|obligations) contains \{(.*?)\} if", text, re.S):
                rule = re.search(r'"rule":\s*"([A-Z]+-\d+)"', block.group(2))
                message = re.search(r'"message":\s*"([^"]+)"', block.group(2))
                if rule:
                    rules.append(
                        {
                            "rule": rule.group(1),
                            "effect": {"deny": "deny", "approval": "require_approval"}.get(
                                block.group(1), "obligation"
                            ),
                            "message": message.group(1) if message else "",
                        }
                    )
        return {
            "version": active.id,
            "files": files,
            "rules": rules,
            "data": active.configuration,
            "engine": settings.policy_engine,
            # The python engine mirrors the repository rules, so only its configuration can change.
            "editing": "configuration-only" if settings.policy_engine == "python" else "configuration-and-rules",
            "rules_recorded": bundle is not None,
        }

    @r.get("/taxonomy")
    async def taxonomy(request: Request):
        return {"categories": sorted(request.app.state.ctx.taxonomy)}

    @r.post("/guard/scan")
    async def guard_scan(body: ScanRequest):
        """Playground: run the Guard's injection heuristics and PII recognizers on any text."""
        result = scan_text(body.text)
        redacted, count = pii.redact_text(body.text)
        found = [{"entity": e, "text": body.text[a:b]} for e, a, b in pii.find(body.text)]
        return {
            "injection": result.injection,
            "score": result.score,
            "findings": result.findings,
            "pii": found,
            "pii_count": count,
            "redacted": redacted,
        }

    @r.get("/ledger")
    async def ledger_entries(limit: int = 100, subject: str | None = None, s: AsyncSession = Depends(session)):
        query = select(LedgerEntry).order_by(LedgerEntry.seq.desc())
        if subject:
            query = query.where(LedgerEntry.subject.contains(subject))
        rows = await s.execute(query.limit(min(limit, 500)))
        return [
            {
                "seq": e.seq,
                "ts": e.ts,
                "event_type": e.event_type,
                "actor": e.actor,
                "subject": e.subject,
                "payload": e.payload,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
            for e in rows.scalars()
        ]

    @r.get("/ledger/verify")
    async def ledger_verify(s: AsyncSession = Depends(session)):
        return await ledger.verify(s)

    @r.get("/usage")
    async def usage(s: AsyncSession = Depends(session)):
        rows = (
            await s.execute(
                select(
                    Usage.agent_id,
                    Usage.model,
                    func.count(),
                    func.sum(Usage.input_tokens),
                    func.sum(Usage.output_tokens),
                    func.sum(Usage.cost_eur),
                    func.avg(Usage.latency_ms),
                ).group_by(Usage.agent_id, Usage.model)
            )
        ).all()
        names = await agent_names(s, [row[0] for row in rows])
        return [
            {
                "agent_id": a,
                "agent_name": names.get(a, a),
                "model": m,
                "calls": n,
                "input_tokens": i or 0,
                "output_tokens": o or 0,
                "cost_eur": round(c or 0, 6),
                "avg_latency_ms": round(lat or 0, 1),
            }
            for a, m, n, i, o, c, lat in rows
        ]

    return r
