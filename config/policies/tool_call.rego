# Aegis tool-call policy (plan §8.4). Query: data.aegis.tool_call.decision
#
# This Rego is the authoritative policy. It is evaluated by OPA (policy_engine=opa), in-process by regopy
# (policy_engine=rego), and mirrored by the Python engine (policy_engine=python). tests/test_policy*.py check that the
# three agree, and that this policy is never more permissive than the Python mirror, including on malformed input.
#
# Configuration (thresholds, redaction entities, ...) is the governed, approved policy version: the engines pass it as
# input.policy_data with every decision. Without it (for example `opa eval -d config/policies`) data.json applies.
#
# Fail closed: a field this policy needs that is missing or of the wrong type makes a rule deny, never silently skip.
package aegis.tool_call

import rego.v1

# ---- inputs -----------------------------------------------------------------

cfg := input.policy_data if {
	is_object(input.policy_data)
} else := {
	"thresholds": data.thresholds,
	"redact_entities": data.redact_entities,
	"approval_side_effects_high_risk": data.approval_side_effects_high_risk,
}

# obj(x) is x when it is an object, else {}: a field of the wrong type can never make a rule silently skip.
obj(x) := x if {
	is_object(x)
} else := {}

input_obj := obj(input)

subject := obj(object.get(input_obj, "subject", {}))

sprops := obj(object.get(subject, "properties", {}))

props := obj(object.get(obj(object.get(input_obj, "resource", {})), "properties", {}))

context := obj(object.get(input_obj, "context", {}))

mandate := obj(object.get(context, "mandate", {}))

session := obj(object.get(context, "session", {}))

approval_ctx := obj(object.get(context, "approval", {}))

action_props := obj(object.get(obj(object.get(input_obj, "action", {})), "properties", {}))

tool := object.get(action_props, "tool", null)

raw_args := object.get(action_props, "args", {})

args := raw_args if {
	is_object(raw_args)
} else := {}

approved if approval_ctx.status == "approved"

data_classes := ["public", "internal", "confidential", "restricted"]

# Rank of a data class; anything unknown counts as above "restricted" (as the Python engine does).
rank(c) := i if {
	some i, v in data_classes
	v == c
} else := 4

# A mandate's data ceiling; an unknown ceiling counts as "public" (stricter than the Python engine, never looser).
ceiling(c) := i if {
	some i, v in data_classes
	v == c
} else := 0

default decision := {"decision": "deny", "reasons": [{"rule": "DEF-000", "message": "Default deny"}], "obligations": []}

# ---- malformed input --------------------------------------------------------

deny contains {"rule": "INP-001", "message": "Malformed policy input"} if not well_formed

well_formed if {
	is_object(input.subject)
	is_object(input.resource.properties)
	is_object(input.action.properties)
	is_string(tool)
	is_string(subject.id)
	is_object(object.get(subject, "properties", {}))
	is_object(object.get(input_obj, "context", {}))
	is_object(object.get(context, "mandate", {}))
	is_object(object.get(context, "session", {}))
	approval_acceptable
}

# No approval (null, false, 0, "", [], {}) or an approval object; anything else is malformed.
approval_acceptable if is_object(object.get(context, "approval", {}))

approval_acceptable if object.get(context, "approval", {}) in [null, false, 0, "", []]

# The governed configuration must be complete, or the rules that read it could silently not fire.
deny contains {"rule": "CFG-001", "message": "Malformed governed policy configuration"} if not cfg_ok

cfg_ok if {
	is_number(cfg.thresholds.payments.hitl_amount_eur)
	is_array(cfg.redact_entities)
	count(cfg.redact_entities) > 0
	every entity in cfg.redact_entities {
		is_string(entity)
	}
	is_array(cfg.approval_side_effects_high_risk)
}

# ---- deny rules -------------------------------------------------------------

deny contains {"rule": "AGT-001", "message": "Agent is not active"} if {
	object.get(sprops, "status", null) != "active"
}

deny contains {"rule": "RSK-001", "message": "Agent risk tier is critical"} if {
	object.get(sprops, "risk_tier", null) == "critical"
}

deny contains {"rule": "TOOL-001", "message": "Tool is not approved, or its definition changed since approval"} if {
	not tool_trusted
}

tool_trusted if {
	props.status == "approved"
	props.pinned == true
}

deny contains {"rule": "SCP-001", "message": sprintf("Tool %v is not in this mandate's scope", [tool])} if {
	not tool_in_scope
}

tool_in_scope if {
	is_array(mandate.scopes)
	tool in mandate.scopes
}

deny contains {"rule": "PUR-001", "message": sprintf("Tool %v is outside the mandate purpose", [tool])} if {
	not purpose_match
}

purpose_match if {
	is_array(props.intent_tags)
	is_array(mandate.intent_categories)
	some tag in props.intent_tags
	tag in mandate.intent_categories
}

deny contains {"rule": "ENT-001", "message": "The initiating user lacks the entitlement this tool requires"} if {
	required := object.get(props, "required_entitlement", null)
	required != null
	not entitled(required)
}

entitled(required) if {
	is_array(mandate.entitlements)
	required in mandate.entitlements
}

deny contains {"rule": "DAT-001", "message": "Tool returns data above the mandate's data ceiling"} if {
	rank(object.get(props, "returns_data_class", "restricted")) > ceiling(object.get(mandate, "max_data_class", "public"))
}

# Lethal-trifecta breaker: untrusted content + sensitive data + external egress never co-occur in one task.
deny contains {
	"rule": "IFC-001",
	"message": "External egress blocked: this task ingested untrusted content and read confidential data",
} if {
	props.egress == "external"
	session.tainted == true
	rank(object.get(session, "max_data_class_read", "public")) >= 2
}

deny contains {"rule": "APR-001", "message": "Approval does not match this exact action"} if {
	approval_ctx.status == "mismatch"
}

# A transfer whose amount is not a number (for example the text "25000") is refused rather than compared, so a model
# cannot skip the approval threshold by changing the argument's type.
deny contains {"rule": "ARG-001", "message": "Transfer amount must be a number"} if {
	tool == "payments.initiate_transfer"
	not is_number(object.get(args, "amount", 0))
}

deny contains {"rule": "ARG-001", "message": "Transfer amount must be a number"} if {
	tool == "payments.initiate_transfer"
	not is_object(raw_args)
}

# ---- human approval rules ---------------------------------------------------

approval contains {
	"rule": "PAY-010",
	"message": "Transfers above the threshold to a new beneficiary require human approval",
} if {
	tool == "payments.initiate_transfer"
	amount := object.get(args, "amount", 0)
	is_number(amount)
	amount > cfg.thresholds.payments.hitl_amount_eur
	args.new_beneficiary == true
	not approved
}

approval contains {"rule": "DES-001", "message": "Destructive actions in production require human approval"} if {
	props.side_effect == "destructive"
	sprops.env == "PRD"
	not approved
}

approval contains {"rule": "RSK-002", "message": "High-risk agents need approval for financial or destructive actions"} if {
	sprops.risk_tier == "high"
	props.side_effect in cfg.approval_side_effects_high_risk
	not approved
}

# ---- obligations ------------------------------------------------------------

obligations contains {"type": "redact", "entities": cfg.redact_entities} if {
	rank(object.get(props, "returns_data_class", "public")) >= 2
	not unmasked_allowed
}

unmasked_allowed if {
	is_array(mandate.scopes)
	"pii.unmasked" in mandate.scopes
}

obligations contains {
	"type": "rate_limit",
	"key": sprintf("%v:%v", [subject.id, tool]),
	"limit": props.rate_limit_per_min,
} if {
	object.get(props, "rate_limit_per_min", null) != null
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
