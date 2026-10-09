"""Reserved, read-only investigation service and its gateway-brokered credential."""

SERVER = "aegis-investigate"
INTENT = "governance.investigate.read"
ENTITLEMENT = "investigation.read"
ROLES = ("soc-analyst", "auditor")
TOOLS = {
    "search_decisions": "Find recorded allow, deny, approval and rate-limit decisions with their rule reasons.",
    "get_agent": "Find agent registry metadata by ID or name. Current status is not historical proof.",
    "get_trace_timeline": "Read stored trace spans for an exact trace_id. Missing spans mean incomplete tracing.",
    "get_delegation_chain": "Read Mandates for an exact root_id, including parent IDs and initiating users.",
    "list_alerts": "Find recorded detection alerts. Alert metadata is not proof that a bank action succeeded.",
    "usage_summary": "Read individual model usage receipts. Costs are configured estimates, not Azure invoices.",
    "get_lineage": "Read recorded Mandates and decisions for an exact root_id; not a reconstructed execution claim.",
    "get_policy_version": (
        "Read an exact stored policy version by record_id or content hash; "
        "do not use current policy to explain old decisions."
    ),
    "search_approvals": "Read approval status, approver and times. Approval alone does not prove execution.",
}


def upstream_headers(settings, server_id: str, url: str) -> dict[str, str]:
    # Never send this credential to a registry-controlled URL, redirect or lookalike server.
    expected = f"{settings.control_url.rstrip('/')}/demo/mcp/{SERVER}/mcp"
    if server_id == SERVER and url == expected:
        return {"x-aegis-investigation": settings.investigation_token}
    return {}
