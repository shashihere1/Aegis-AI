"""SOC: detections, alerts, response playbooks, decisions, lineage and evidence views (plan §8.10-8.12)."""

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.common.ids import new_id
from aegis.common.models import AgentStatus
from aegis.control import investigations, ledger, siem
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
    await siem.enqueue(c, s, alert)
    return alert


async def on_decision(c: ControlContext, s: AsyncSession, record: DecisionRecord) -> None:
    rules = {r.get("rule") for r in record.reasons}
    if record.decision == "deny" and "LLM-BUDGET" in rules and record.agent_id:
        # One block alert per agent/day/model-policy; repeated denials are still individually audited.
        await s.flush()
        since = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        prior = list(
            await s.scalars(
                select(Alert).where(Alert.agent_id == record.agent_id, Alert.rule_id == "DET-17", Alert.ts >= since)
            )
        )
        if not any(a.evidence.get("policy_version") == record.policy_version for a in prior):
            await raise_alert(
                c,
                s,
                "DET-17",
                "high",
                "Model request blocked by estimated daily budget",
                record.agent_id,
                {
                    "decision": record.id,
                    "root_id": record.root_id,
                    "mandate_id": record.mandate_id,
                    "trace_id": record.trace_id,
                    "reasons": record.reasons,
                    "policy_version": record.policy_version,
                    "daily_budget_eur": record.input_snapshot.get("model_policy", {}).get("daily_budget_eur"),
                    **record.input_snapshot.get("budget", {}),
                },
            )
    if record.decision == "deny" and "DLG-004" in rules and record.root_id and record.agent_id:
        await raise_alert(
            c,
            s,
            "DET-15",
            "high",
            "Delegation permission widening blocked",
            record.agent_id,
            {
                "decision": record.id,
                "root_id": record.root_id,
                "mandate_id": record.mandate_id,
                "subject": record.subject,
                "trace_id": record.trace_id,
                "reasons": record.reasons,
                **record.input_snapshot.get("delegation", {}),
            },
        )
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
        "outcome": None if d.action.startswith(("a2a:", "sts.")) else call_outcome(d),
    }


NOT_EXECUTED = {"deny": "denied", "rate_limited": "rate_limited", "require_approval": "awaiting_approval"}
FAILED = {"failed", "tool_error"}
# Most severe first: a merged graph's result node takes the colour of its worst task.
TASK_OUTCOMES = ("revoked", "failed", "blocked", "waiting", "expired", "in_progress", "completed")
TASK_LABEL = {
    "revoked": "Revoked",
    "failed": "Failed",
    "blocked": "Blocked by policy",
    "waiting": "Waiting for approval",
    "expired": "Expired",
    "in_progress": "In progress",
    "completed": "Completed",
}
CALL_LABEL = {
    "executed": "executed",
    "tool_error": "tool error",
    "failed": "failed",
    "denied": "denied",
    "rate_limited": "rate limited",
    "awaiting_approval": "held for approval",
    "not_recorded": "outcome not recorded",
}
APPROVAL_LABEL = {
    "pending": "Awaiting approval",
    "approved": "Approved by {approver}",
    "consumed": "Approved by {approver} · used",
    "rejected": "Rejected by {approver}",
    "expired": "Approval expired",
    "cancelled": "Approval cancelled",
}


def call_outcome(d: DecisionRecord) -> str:
    """What happened to one tool call. Records made before outcomes were stored say so instead of guessing."""
    if d.decision == "allow":
        return (d.input_snapshot or {}).get("outcome", "not_recorded")
    return NOT_EXECUTED.get(d.decision, d.decision)


def summarise(counts: Counter) -> str:
    return " · ".join(f"{n} {label}" for key, label in CALL_LABEL.items() if (n := counts[key]))


def task_outcome(root: Mandate, decisions: list[DecisionRecord], approvals: list[Approval]) -> tuple[str, Counter]:
    """Outcome of one task from its root Mandate, the latest outcome per tool, and its approvals.

    Only statuses and counts are used; never tool results, arguments or customer data."""
    tool_decisions = [d for d in decisions if not d.action.startswith(("a2a:", "sts."))]
    calls = Counter(call_outcome(d) for d in tool_decisions)
    latest = {d.action: call_outcome(d) for d in tool_decisions}
    expires = root.expires_at if root.expires_at.tzinfo else root.expires_at.replace(tzinfo=UTC)
    if root.status == "revoked":
        outcome = "revoked"
    elif any(a.status == "pending" for a in approvals):
        outcome = "waiting"
    elif any(o in FAILED for o in latest.values()):
        outcome = "failed"
    elif not calls["executed"] and (
        calls["denied"]
        or calls["rate_limited"]
        or any(d.action == "sts.token_exchange" and d.decision == "deny" for d in decisions)
    ):
        outcome = "blocked"
    elif root.status == "completed":
        outcome = "completed"
    elif expires <= datetime.now(UTC):
        outcome = "expired"
    else:
        outcome = "in_progress"
    return outcome, calls


def lineage_graph(
    mandates: list[Mandate],
    decisions: list[DecisionRecord],
    approvals: list[Approval],
    names: dict[str, str],
    aggregate: bool,
) -> dict:
    """User -> agents -> tools -> data -> approvals -> result. Repeated hops merge into one edge with counts.

    `aggregate` merges several tasks: approvals are grouped per tool and the result node counts task outcomes."""
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    def edge(frm: str, to: str, kind: str) -> dict:
        e = edges.setdefault((frm, to, kind), {"from": frm, "to": to, "kind": kind, "count": 0, "decisions": {}})
        e["count"] += 1
        return e

    by_id = {m.id: m for m in mandates}
    for m in mandates:
        if m.parent_id not in by_id:
            nodes.setdefault(m.subject, {"id": m.subject, "kind": "user", "label": m.subject.split(":", 1)[-1]})
        agent = f"agent:{m.agent_id}"
        node = nodes.setdefault(
            agent, {"id": agent, "kind": "agent", "label": names.get(m.agent_id, m.agent_id), "depth": m.depth}
        )
        node.update(mandate=m.id, status=m.status, intent_categories=m.intent_categories)
        node["depth"] = min(node["depth"], m.depth)
        source = f"agent:{by_id[m.parent_id].agent_id}" if m.parent_id in by_id else m.subject
        edge(source, agent, "delegated_to" if m.parent_id else "initiated")["intent"] = m.intent

    for d in decisions:
        attempt = (d.input_snapshot or {}).get("delegation", {})
        target = attempt.get("target_agent_id")
        if d.action == "sts.token_exchange" and d.decision == "deny" and target and d.agent_id:
            parent = by_id.get(d.mandate_id)
            target_node = f"agent:{target}"
            nodes.setdefault(
                target_node,
                {
                    "id": target_node,
                    "kind": "agent",
                    "label": names.get(target, target),
                    "depth": parent.depth + 1 if parent else 1,
                    "status": "attempted_only",
                },
            )
            e = edge(f"agent:{d.agent_id}", target_node, "attempted_delegation")
            e["decisions"]["deny"] = e["decisions"].get("deny", 0) + 1
            e.update(
                decision="deny",
                rules=[r.get("rule") for r in d.reasons],
                decision_id=d.id,
                reason="; ".join(r.get("message", "") for r in d.reasons),
            )

    tool_calls = [d for d in decisions if not d.action.startswith(("a2a:", "sts."))]
    for d in tool_calls:
        tool = f"tool:{d.action}"
        outcome = call_outcome(d)
        node = nodes.setdefault(tool, {"id": tool, "kind": "tool", "label": d.action, "outcomes": {}})
        node["outcomes"][outcome] = node["outcomes"].get(outcome, 0) + 1
        node["outcome"] = outcome
        e = edge(f"agent:{d.agent_id}", tool, "invoked")
        e["decisions"][d.decision] = e["decisions"].get(d.decision, 0) + 1
        e.update(decision=d.decision, rules=[r.get("rule") for r in d.reasons], decision_id=d.id)
        if d.data_class and d.decision == "allow" and outcome not in FAILED:
            data = f"data:{d.data_class}"
            nodes.setdefault(data, {"id": data, "kind": "data", "label": d.data_class})
            edge(tool, data, "read")

    for a in approvals:
        tool = f"tool:{a.tool}"
        nodes.setdefault(tool, {"id": tool, "kind": "tool", "label": a.tool, "outcomes": {}})
        key = f"approval:{a.tool}" if aggregate else f"approval:{a.id}"
        node = nodes.setdefault(key, {"id": key, "kind": "approval", "statuses": {}})
        node["statuses"][a.status] = node["statuses"].get(a.status, 0) + 1
        if not aggregate:
            node.update(
                approval_status=a.status,
                approver=a.approver,
                label=APPROVAL_LABEL.get(a.status, a.status).format(approver=a.approver or "—"),
            )
        edge(tool, key, "approval")
    if aggregate:
        for node in nodes.values():
            if node["kind"] == "approval":
                node["label"] = " · ".join(f"{n} {status}" for status, n in node["statuses"].items())

    by_root: dict[str, tuple] = {}
    for m in mandates:
        if m.parent_id is None:
            ids = {x.id for x in mandates if x.root_id == m.root_id}
            by_root[m.root_id] = task_outcome(
                m,
                [d for d in decisions if d.root_id == m.root_id],
                [a for a in approvals if a.mandate_id in ids],
            )
    if by_root:
        tasks = Counter(outcome for outcome, _ in by_root.values())
        calls = sum((c for _, c in by_root.values()), Counter())
        worst = next(o for o in TASK_OUTCOMES if tasks[o])
        if aggregate:
            result = {
                "id": "result:tasks",
                "kind": "result",
                "label": f"{sum(tasks.values())} tasks",
                "outcome": worst,
                "task_outcomes": dict(tasks),
                "detail": " · ".join(f"{tasks[o]} {TASK_LABEL[o].lower()}" for o in TASK_OUTCOMES if tasks[o]),
            }
        else:
            root = next(m for m in mandates if m.parent_id is None)
            detail = summarise(calls) or "no tool calls"
            if worst == "revoked" and root.revoked_reason:
                detail = f"{root.revoked_reason} · {detail}"
            result = {
                "id": f"result:{root.root_id}",
                "kind": "result",
                "label": TASK_LABEL[worst],
                "outcome": worst,
                "detail": detail,
            }
        result["calls"] = dict(calls)
        leaves = [n for n in nodes if n not in {f for f, _, _ in edges}]
        nodes[result["id"]] = result
        for leaf in leaves:
            edge(leaf, result["id"], "resulted_in")
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


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
        subject: str | None = None,
        hours: int | None = Query(None, ge=1, le=720),
        limit: int = 100,
        s: AsyncSession = Depends(session),
    ):
        query = select(DecisionRecord).order_by(DecisionRecord.ts.desc())
        if subject:
            query = query.where(DecisionRecord.subject == subject)
        if hours:
            query = query.where(DecisionRecord.ts >= datetime.now(UTC) - timedelta(hours=hours))
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

    async def lineage_records(s: AsyncSession, root_ids: list[str]):
        mandates = (
            await s.scalars(select(Mandate).where(Mandate.root_id.in_(root_ids)).order_by(Mandate.issued_at))
        ).all()
        decisions = (
            await s.scalars(
                select(DecisionRecord).where(DecisionRecord.root_id.in_(root_ids)).order_by(DecisionRecord.ts)
            )
        ).all()
        approvals = (
            await s.scalars(
                select(Approval).where(Approval.mandate_id.in_([m.id for m in mandates])).order_by(Approval.created_at)
            )
        ).all()
        names = await agent_names(
            s,
            [
                *[m.agent_id for m in mandates],
                *[d.input_snapshot.get("delegation", {}).get("target_agent_id") for d in decisions],
            ],
        )
        return mandates, decisions, approvals, names

    @r.get("/lineage/{root_id}")
    async def lineage(root_id: str, s: AsyncSession = Depends(session)):
        """User -> agents -> tools -> data -> approvals -> result for one task (plan §8.10)."""
        mandates, decisions, approvals, names = await lineage_records(s, [root_id])
        if not mandates:
            raise HTTPException(404, "unknown task")
        return {"root_id": root_id, **lineage_graph(mandates, decisions, approvals, names, aggregate=False)}

    @r.get("/lineage")
    async def lineage_across_tasks(
        subject: str | None = None,
        agent_id: str | None = None,
        hours: int = Query(24, ge=1, le=720),
        limit: int = Query(50, ge=1, le=200),
        s: AsyncSession = Depends(session),
    ):
        """One merged graph over recent tasks, for a user or an agent. Capped; the response says when it is."""
        since = datetime.now(UTC) - timedelta(hours=hours)
        query = select(Mandate).where(Mandate.parent_id.is_(None), Mandate.issued_at >= since)
        if subject:
            query = query.where(Mandate.subject == subject)
        if agent_id:
            involved = select(Mandate.root_id).where(Mandate.agent_id == agent_id)
            query = query.where(Mandate.root_id.in_(involved))
        roots = (await s.scalars(query.order_by(Mandate.issued_at.desc()).limit(limit + 1))).all()
        truncated = len(roots) > limit
        root_ids = [m.root_id for m in roots[:limit]]
        scope = {"subject": subject, "agent_id": agent_id, "hours": hours, "limit": limit}
        if not root_ids:
            return {"scope": scope, "tasks": 0, "truncated": False, "nodes": [], "edges": []}
        mandates, decisions, approvals, names = await lineage_records(s, root_ids)
        graph = lineage_graph(mandates, decisions, approvals, names, aggregate=True)
        return {"scope": scope, "tasks": len(root_ids), "truncated": truncated, **graph}

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
