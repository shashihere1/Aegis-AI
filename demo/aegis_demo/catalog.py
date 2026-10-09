"""Tool classifications, personas and agent manifests for the demo bank ("agents and tools as code")."""

from aegis.common.investigation import ENTITLEMENT, INTENT, SERVER, TOOLS

TOOL_CLASSIFICATION = {
    "core-banking.get_balance": {
        "intent_tags": ["customer.inquiry.read"],
        "side_effect": "read",
        "returns_data_class": "confidential",
        "required_entitlement": "own_accounts.read",
    },
    "payments.initiate_transfer": {
        "intent_tags": ["payments.transfer.initiate"],
        "side_effect": "financial",
        "egress": "internal",
        "returns_data_class": "confidential",
        "required_entitlement": "own_accounts.transfer",
        "rate_limit_per_min": 5,
    },
    "payments.get_payment_status": {
        "intent_tags": ["payments.status.read", "payments.transfer.initiate"],
        "side_effect": "read",
        "returns_data_class": "internal",
    },
    "kyc.verify_document": {
        "intent_tags": ["customer.kyc.verify"],
        "side_effect": "write",
        "returns_data_class": "confidential",
        "required_entitlement": "own_kyc",
    },
    "kyc.get_kyc_status": {
        "intent_tags": ["customer.kyc.verify"],
        "side_effect": "read",
        "returns_data_class": "internal",
    },
    "docs.read_document": {
        "intent_tags": ["customer.kyc.verify", "customer.profile.update", "customer.inquiry.read"],
        "side_effect": "read",
        "returns_data_class": "confidential",
        "untrusted_content": True,
    },
    "crm.get_customer": {
        "intent_tags": ["customer.profile.read", "customer.profile.update"],
        "side_effect": "read",
        "returns_data_class": "confidential",
    },
    "crm.update_address": {
        "intent_tags": ["customer.profile.update"],
        "side_effect": "write",
        "returns_data_class": "internal",
        "required_entitlement": "own_profile.update",
    },
    "notify.send_email": {
        "intent_tags": ["comms.external.send"],
        "side_effect": "write",
        "egress": "external",
        "returns_data_class": "internal",
    },
    "notify.send_app_message": {
        "intent_tags": ["comms.customer.notify.internal", "customer.profile.update"],
        "side_effect": "write",
        "egress": "internal",
        "returns_data_class": "internal",
    },
    "fx-rates.get_rate": {
        "intent_tags": ["customer.inquiry.read"],
        "side_effect": "read",
        "egress": "external",
        "returns_data_class": "public",
    },
}
TOOL_CLASSIFICATION.update(
    {
        f"{SERVER}.{name}": {
            "intent_tags": [INTENT],
            "side_effect": "read",
            "egress": "none",
            "returns_data_class": "confidential",
            "required_entitlement": ENTITLEMENT,
            "rate_limit_per_min": 30,
        }
        for name in TOOLS
    }
)

# Fictional personas (plan §13.2). Jan is a retail customer; the others are bank staff.
PERSONAS = [
    (
        "jan.devries",
        "Jan de Vries",
        ["customer"],
        ["own_accounts.read", "own_accounts.transfer", "own_profile.update", "own_kyc"],
    ),
    ("priya.raman", "Priya Raman", ["agent-developer", "policy-author"], []),
    ("niels.vandijk", "Niels van Dijk", ["agent-owner"], []),
    ("sanne.bakker", "Sanne Bakker", ["risk-approver"], []),
    ("mark.jansen", "Mark Jansen", ["soc-analyst"], []),
    ("fatima.elamrani", "Fatima El Amrani", ["security-approver", "policy-approver"], []),
    ("eva.visser", "Eva Visser", ["auditor"], []),
    ("admin", "Platform Admin", ["admin"], []),
]

AGENTS = {
    "investigation-copilot": {
        "name": "Aegis-Investigation-Copilot",
        "purpose": "Explain recorded agent activity to authorized investigators using cited read-only evidence.",
        "intent_categories": [INTENT],
        "framework": "azure-tool-calling",
        "autonomy": "L0",
        "max_data_class": "confidential",
        "max_depth": 0,
        "capabilities": [f"{SERVER}.{name}" for name in TOOLS],
    },
    "kyc-agent": {
        "name": "KYC-Verification-Agent",
        "purpose": "Verify customer identity documents for KYC refresh and address changes.",
        "intent_categories": ["customer.kyc.verify"],
        "framework": "microsoft-agent-framework",
        "autonomy": "L1",
        "max_data_class": "confidential",
        "capabilities": ["kyc.verify_document", "kyc.get_kyc_status", "docs.read_document"],
    },
    "payments-agent": {
        "name": "Payments-Agent",
        "purpose": "Initiate and track customer payments on the customer's instruction.",
        "intent_categories": ["payments.transfer.initiate", "payments.status.read"],
        "framework": "python-mcp",
        "autonomy": "L1",
        "max_data_class": "confidential",
        "capabilities": ["payments.initiate_transfer", "payments.get_payment_status"],
    },
    "ava": {
        "name": "Ava-Customer-Service-Agent",
        "purpose": "Help retail customers with profile changes, document questions and payments.",
        "intent_categories": [
            "customer.profile.read",
            "customer.profile.update",
            "customer.inquiry.read",
            "customer.kyc.verify",
            "payments.transfer.initiate",
            "comms.external.send",
            "comms.customer.notify.internal",
        ],
        "framework": "langgraph",
        "autonomy": "L1",
        "max_data_class": "confidential",
        "customer_facing": True,
        "capabilities": [
            "docs.read_document",
            "crm.get_customer",
            "crm.update_address",
            "notify.send_email",
            "notify.send_app_message",
            "core-banking.get_balance",
        ],
    },
}
