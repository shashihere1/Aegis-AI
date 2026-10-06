# Aegis tool-call policy (plan §8.4). Query: data.aegis.tool_call.decision
# The in-process Python engine (src/aegis/policy/engine.py) implements the same rules;
# tests/test_policy.py runs the same fixtures against both when an `opa` binary is available.
package aegis.tool_call

import rego.v1

props := input.resource.properties

mandate := input.context.mandate

session := input.context.session

tool := input.action.properties.tool

args := object.get(input.action.properties, "args", {})

data_classes := ["public", "internal", "confidential", "restricted"]

rank(c) := i if {
	some i, v in data_classes
	v == c
}

approved if input.context.approval.status == "approved"

default decision := {"decision": "deny", "reasons": [{"rule": "DEF-000", "message": "Default deny"}], "obligations": []}

# ---- deny rules -------------------------------------------------------------

deny contains {"rule": "AGT-001", "message": "Agent is not active"} if {
	input.subject.properties.status != "active"
}

deny contains {"rule": "RSK-001", "message": "Agent risk tier is critical"} if {
	input.subject.properties.risk_tier == "critical"
}

deny contains {"rule": "TOOL-001", "message": "Tool is not approved, or its definition changed since approval"} if {
	not tool_trusted
}

tool_trusted if {
	props.status == "approved"
	props.pinned == true
}

deny contains {"rule": "SCP-001", "message": sprintf("Tool %s is not in this mandate's scope", [tool])} if {
	not tool in mandate.scopes
}

deny contains {"rule": "PUR-001", "message": sprintf("Tool %s is outside the mandate purpose", [tool])} if {
	not purpose_match
}

purpose_match if {
	some tag in props.intent_tags
	tag in mandate.intent_categories
}

deny contains {"rule": "ENT-001", "message": "The initiating user lacks the entitlement this tool requires"} if {
	required := props.required_entitlement
	required != null
	not required in mandate.entitlements
}

deny contains {"rule": "DAT-001", "message": "Tool returns data above the mandate's data ceiling"} if {
	rank(props.returns_data_class) > rank(mandate.max_data_class)
}

# Lethal-trifecta breaker: untrusted content + sensitive data + external egress never co-occur in one task.
deny contains {
	"rule": "IFC-001",
	"message": "External egress blocked: this task ingested untrusted content and read confidential data",
} if {
	props.egress == "external"
	session.tainted == true
	rank(session.max_data_class_read) >= 2
}

deny contains {"rule": "APR-001", "message": "Approval does not match this exact action"} if {
	input.context.approval.status == "mismatch"
}

# ---- human approval rules ---------------------------------------------------

approval contains {
	"rule": "PAY-010",
	"message": "Transfers above the threshold to a new beneficiary require human approval",
} if {
	tool == "payments.initiate_transfer"
	args.amount > data.thresholds.payments.hitl_amount_eur
	args.new_beneficiary == true
	not approved
}

approval contains {"rule": "DES-001", "message": "Destructive actions in production require human approval"} if {
	props.side_effect == "destructive"
	input.subject.properties.env == "PRD"
	not approved
}

approval contains {"rule": "RSK-002", "message": "High-risk agents need approval for financial or destructive actions"} if {
	input.subject.properties.risk_tier == "high"
	props.side_effect in data.approval_side_effects_high_risk
	not approved
}

# ---- obligations ------------------------------------------------------------

obligations contains {"type": "redact", "entities": data.redact_entities} if {
	rank(props.returns_data_class) >= 2
	not "pii.unmasked" in mandate.scopes
}

obligations contains {
	"type": "rate_limit",
	"key": sprintf("%s:%s", [input.subject.id, tool]),
	"limit": props.rate_limit_per_min,
} if {
	props.rate_limit_per_min != null
}

# ---- combination: deny > require_approval > allow (+ obligations) ------------

decision := {"decision": "deny", "reasons": deny, "obligations": []} if {
	count(deny) > 0
}

decision := {"decision": "require_approval", "reasons": approval, "obligations": obligations} if {
	count(deny) == 0
	count(approval) > 0
}

decision := {"decision": "allow", "reasons": [], "obligations": obligations} if {
	count(deny) == 0
	count(approval) == 0
}
