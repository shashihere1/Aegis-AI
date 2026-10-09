"""Fixed, deterministic evidence queries. Evidence coverage is never a regulatory compliance verdict."""

import json
from collections import Counter
from pathlib import Path

from aegis.common.settings import REPO_ROOT

CATALOG = json.loads(Path(REPO_ROOT / "config" / "controls" / "catalog.json").read_text(encoding="utf-8"))
FRAMEWORKS = CATALOG["sources"]


def query_source(pack: dict, control: dict, key: str) -> dict:
    filters = control.get("filters", {}).get(key, {})
    rows = pack["records"][key]
    prefixes = tuple(filters.get("event_type_prefixes", []))
    if prefixes:
        rows = [row for row in rows if row.get("event_type", "").startswith(prefixes)]
    return {
        "file": f"records/{key}.json",
        "query": f"scoped_{key}",
        "filters": filters,
        "count": len(rows),
        "record_ids": [
            row.get("id", row.get("seq", row.get("agent_id", row.get("span_id", row.get("alert_id"))))) for row in rows
        ],
    }


def control_coverage(pack: dict) -> list[dict]:
    framework = pack.get("scope", {}).get("framework", "all")
    result = []
    for control in CATALOG["controls"]:
        references = [
            {
                "framework": key,
                "name": FRAMEWORKS[key]["name"],
                "reference": reference,
                "source_url": FRAMEWORKS[key]["url"],
            }
            for key, reference in control["refs"].items()
            if framework == "all" or key == framework
        ]
        if not references:
            continue
        sources = [query_source(pack, control, key) for key in control["queries"]]
        present = sum(source["count"] > 0 for source in sources)
        status = "evidence_present" if present == len(sources) else "partial_evidence" if present else "no_evidence"
        result.append(
            {
                "id": control["id"],
                "title": control["title"],
                "status": status,
                "observed_records": sum(source["count"] for source in sources),
                "sources": sources,
                "references": references,
                "limitations": control["limitations"],
                "assessment": "human_review_required",
            }
        )
    return result


def executive_summary(pack: dict, controls: list[dict]) -> str:
    decisions = Counter(row["decision"] for row in pack["records"]["decisions"])
    missing = [control["id"] for control in controls if control["status"] != "evidence_present"]
    return (
        f"The selected scope contains {pack['counts']['agents']} agents, {pack['counts']['decisions']} decisions "
        f"({decisions['deny']} denied, {decisions['require_approval']} requiring approval), "
        f"{pack['counts']['approvals']} approval records and {pack['counts']['alerts']} alerts. "
        f"Controls with absent or partial event evidence: {', '.join(missing) or 'none'}. "
        "Counts describe recorded activity, not control effectiveness or legal compliance. "
        "This summary is generated deterministically from the included records; no LLM was called."
    )
