"""Bounded evidence selection. Related context is explicit; no unrelated ledger payloads are exported."""

from datetime import UTC, datetime


def referenced(value, ids: set[str]) -> bool:
    if isinstance(value, str):
        return value in ids
    if isinstance(value, dict):
        return any(referenced(item, ids) for item in value.values())
    if isinstance(value, list):
        return any(referenced(item, ids) for item in value)
    return False


def moment(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if isinstance(value, int):
        return datetime.fromtimestamp(value / 1e9, UTC)
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def select_records(rows: dict, lower: datetime, upper: datetime, agent_id: str | None, root_id: str | None) -> dict:
    def during(row, field):
        when = moment(getattr(row, field))
        return when is not None and lower <= when < upper

    # Use historical mandates as linkage context even when a task began before this reporting period.
    related_mandates = [
        m
        for m in rows["mandates"]
        if (not agent_id or m.agent_id == agent_id or agent_id in m.chain) and (not root_id or m.root_id == root_id)
    ]
    mandate_ids = {m.id for m in related_mandates}
    roots = {m.root_id for m in related_mandates}
    scoped = bool(agent_id or root_id)
    chosen = {}
    chosen["decisions"] = [
        d
        for d in rows["decisions"]
        if during(d, "ts")
        and (
            not scoped
            or d.mandate_id in mandate_ids
            or (root_id and d.root_id == root_id)
            or (not root_id and d.agent_id == agent_id)
        )
    ]
    chosen["approvals"] = [
        a
        for a in rows["approvals"]
        if (during(a, "created_at") or during(a, "decided_at")) and (not scoped or a.mandate_id in mandate_ids)
    ]
    chosen["mandates"] = [
        m
        for m in related_mandates
        if during(m, "issued_at")
        or m.id in {d.mandate_id for d in chosen["decisions"]} | {a.mandate_id for a in chosen["approvals"]}
    ]
    # Keep ancestors needed to reconstruct lineage, but never siblings in other tasks.
    by_id = {m.id: m for m in rows["mandates"]}
    included = {m.id for m in chosen["mandates"]}
    for child in list(chosen["mandates"]):
        parent_id = child.parent_id
        visited = {child.id}
        while parent_id and parent_id not in visited:
            visited.add(parent_id)
            parent = by_id.get(parent_id)
            if parent is None or parent.root_id != child.root_id:
                break
            if parent.id not in included:
                chosen["mandates"].append(parent)
                included.add(parent.id)
            parent_id = parent.parent_id
    chosen["mandates"].sort(key=lambda m: (moment(m.issued_at), m.id))
    agents = {m.agent_id for m in chosen["mandates"]} | {d.agent_id for d in chosen["decisions"]}
    if agent_id:
        agents.add(agent_id)
    if root_id:
        agents.update(m.agent_id for m in related_mandates)
    chosen["agents"] = [a for a in rows["agents"] if not scoped or a.id in agents]
    agents.update(a.id for a in chosen["agents"])
    # Root exports require root linkage, not merely the same agent (which can have other customers' tasks).
    investigated = {e.alert_id for e in rows["case_events"] if during(e, "ts")}
    chosen["alerts"] = [
        a
        for a in rows["alerts"]
        if (during(a, "ts") or a.id in investigated)
        and (not scoped or (not root_id and a.agent_id == agent_id) or referenced(a.evidence, roots | mandate_ids))
    ]
    alert_ids = {a.id for a in chosen["alerts"]}
    chosen["cases"] = [c for c in rows["cases"] if c.alert_id in alert_ids]
    chosen["case_events"] = [e for e in rows["case_events"] if e.alert_id in alert_ids and during(e, "ts")]
    policy_ids = {d.policy_version for d in chosen["decisions"]}
    chosen["policy_state"] = rows["policy_state"] if not root_id else []
    policy_ids.update(p.active_version for p in chosen["policy_state"])
    chosen["policies"] = [p for p in rows["policies"] if p.id in policy_ids or (not scoped and during(p, "created_at"))]
    chosen["risk"] = [r for r in rows["risk"] if r.agent_id in agents]
    trace_ids = {d.trace_id for d in chosen["decisions"] if d.trace_id}
    chosen["traces"] = [t for t in rows["traces"] if during(t, "start_ns") and (not scoped or t.trace_id in trace_ids)]
    chosen["usage"] = [u for u in rows["usage"] if during(u, "ts") and (not scoped or u.mandate_id in mandate_ids)]
    capabilities = {cap for a in chosen["agents"] for cap in a.capabilities}
    capabilities.update(a.tool for a in chosen["approvals"])
    capabilities.update(d.action for d in chosen["decisions"])
    chosen["tools"] = [t for t in rows["tools"] if not scoped or t.id in capabilities]
    servers = {t.server_id for t in chosen["tools"]}
    chosen["servers"] = [s for s in rows["servers"] if s.id in servers]
    chosen["discovery"] = [
        d for d in rows["discovery"] if during(d, "last_seen") and (not scoped or d.agent_id in agents)
    ]
    ids = included | roots | alert_ids | {d.id for d in chosen["decisions"]} | {a.id for a in chosen["approvals"]}
    if not root_id:
        ids |= agents | policy_ids | capabilities | servers
    chosen["ledger"] = [
        e for e in rows["ledger"] if during(e, "ts") and (not scoped or e.subject in ids or referenced(e.payload, ids))
    ]
    # Prior checkpoint metadata is integrity context only; the export adds its own signed checkpoint.
    chosen["checkpoints"] = []
    return chosen
