"""Policy Decision Point (plan §8.4).

Two interchangeable engines evaluate config/policies:
- OpaEngine calls an OPA sidecar (production; the Rego files are authoritative).
- PythonEngine implements the same rules in-process (local development without an OPA binary).
tests/test_policy.py runs shared fixtures through both to keep them in step.
"""

import json
from pathlib import Path
from typing import Protocol

import httpx

from aegis.common.hashing import sha256_hex
from aegis.common.models import data_class_rank


def policy_version(policy_dir: str) -> str:
    files = sorted(Path(policy_dir).glob("*.rego")) + [Path(policy_dir) / "data.json"]
    return "rego-" + sha256_hex("".join(f.read_text(encoding="utf-8") for f in files if f.exists()))[:12]


class PolicyEngine(Protocol):
    version: str

    async def evaluate(self, policy_input: dict) -> dict: ...


class PythonEngine:
    def __init__(self, policy_dir: str, data: dict | None = None, version: str | None = None):
        self.data = (
            data if data is not None else json.loads((Path(policy_dir) / "data.json").read_text(encoding="utf-8"))
        )
        self.version = version or policy_version(policy_dir)

    async def evaluate(self, policy_input: dict) -> dict:
        return self.decide(policy_input)

    def decide(self, i: dict) -> dict:
        subject = i["subject"]
        sprops = subject.get("properties", {})
        props = i["resource"]["properties"]
        ctx = i.get("context", {})
        mandate = ctx.get("mandate", {})
        session = ctx.get("session", {})
        approval = ctx.get("approval") or {}
        tool = i["action"]["properties"]["tool"]
        args = i["action"]["properties"].get("args", {}) or {}
        approved = approval.get("status") == "approved"

        deny: list[dict] = []
        if sprops.get("status") != "active":
            deny.append({"rule": "AGT-001", "message": "Agent is not active"})
        if sprops.get("risk_tier") == "critical":
            deny.append({"rule": "RSK-001", "message": "Agent risk tier is critical"})
        if not (props.get("status") == "approved" and props.get("pinned") is True):
            deny.append(
                {"rule": "TOOL-001", "message": "Tool is not approved, or its definition changed since approval"}
            )
        if tool not in mandate.get("scopes", []):
            deny.append({"rule": "SCP-001", "message": f"Tool {tool} is not in this mandate's scope"})
        if not set(props.get("intent_tags", [])) & set(mandate.get("intent_categories", [])):
            deny.append({"rule": "PUR-001", "message": f"Tool {tool} is outside the mandate purpose"})
        required = props.get("required_entitlement")
        if required is not None and required not in mandate.get("entitlements", []):
            deny.append({"rule": "ENT-001", "message": "The initiating user lacks the entitlement this tool requires"})
        if data_class_rank(props.get("returns_data_class", "restricted")) > data_class_rank(
            mandate.get("max_data_class", "public")
        ):
            deny.append({"rule": "DAT-001", "message": "Tool returns data above the mandate's data ceiling"})
        if (
            props.get("egress") == "external"
            and session.get("tainted") is True
            and data_class_rank(session.get("max_data_class_read", "public")) >= 2
        ):
            deny.append(
                {
                    "rule": "IFC-001",
                    "message": "External egress blocked: this task ingested untrusted "
                    "content and read confidential data",
                }
            )
        if approval.get("status") == "mismatch":
            deny.append({"rule": "APR-001", "message": "Approval does not match this exact action"})

        needs: list[dict] = []
        if (
            tool == "payments.initiate_transfer"
            and float(args.get("amount", 0)) > self.data["thresholds"]["payments"]["hitl_amount_eur"]
            and args.get("new_beneficiary") is True
            and not approved
        ):
            needs.append(
                {
                    "rule": "PAY-010",
                    "message": "Transfers above the threshold to a new beneficiary require human approval",
                }
            )
        if props.get("side_effect") == "destructive" and sprops.get("env") == "PRD" and not approved:
            needs.append({"rule": "DES-001", "message": "Destructive actions in production require human approval"})
        if (
            sprops.get("risk_tier") == "high"
            and props.get("side_effect") in self.data["approval_side_effects_high_risk"]
            and not approved
        ):
            needs.append(
                {"rule": "RSK-002", "message": "High-risk agents need approval for financial or destructive actions"}
            )

        obligations: list[dict] = []
        if data_class_rank(props.get("returns_data_class", "public")) >= 2 and "pii.unmasked" not in mandate.get(
            "scopes", []
        ):
            obligations.append({"type": "redact", "entities": self.data["redact_entities"]})
        if props.get("rate_limit_per_min") is not None:
            obligations.append(
                {"type": "rate_limit", "key": f"{subject['id']}:{tool}", "limit": props["rate_limit_per_min"]}
            )

        if deny:
            return self._result("deny", deny, [])
        if needs:
            return self._result("require_approval", needs, obligations)
        return self._result("allow", [], obligations)

    def _result(self, decision: str, reasons: list[dict], obligations: list[dict]) -> dict:
        return {
            "decision": decision,
            "reasons": sorted(reasons, key=lambda r: r["rule"]),
            "obligations": obligations,
            "policy_version": self.version,
        }


class OpaEngine:
    def __init__(self, opa_url: str, policy_dir: str, http: httpx.AsyncClient):
        self.url = f"{opa_url.rstrip('/')}/v1/data/aegis/tool_call/decision"
        self.version = policy_version(policy_dir)
        self.http = http

    async def evaluate(self, policy_input: dict) -> dict:
        response = await self.http.post(self.url, json={"input": policy_input}, timeout=2.0)
        response.raise_for_status()
        result = response.json().get("result")
        if result is None:
            raise RuntimeError("OPA returned no decision")
        return {**result, "policy_version": self.version}


def make_engine(kind: str, policy_dir: str, opa_url: str, http: httpx.AsyncClient) -> PolicyEngine:
    return OpaEngine(opa_url, policy_dir, http) if kind == "opa" else PythonEngine(policy_dir)
