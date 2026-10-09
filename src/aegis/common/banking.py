"""Credentials only for the five built-in sandbox endpoints, never arbitrary registry URLs."""

SERVERS = frozenset({"core-banking", "payments", "kyc", "docs", "crm"})


def upstream_headers(settings, server_id: str, url: str, claims: dict | None = None) -> dict[str, str]:
    expected = f"{settings.control_url.rstrip('/')}/demo/mcp/{server_id}/mcp"
    if not settings.bank_sandbox_enabled or server_id not in SERVERS or url != expected:
        return {}
    headers = {"x-aegis-bank-key": settings.bank_sandbox_token}
    if claims:
        mandate = claims["aegis"]
        headers.update(
            {
                "x-aegis-bank-root": mandate["root_id"],
                "x-aegis-bank-mandate": mandate["mandate_id"],
                "x-aegis-bank-subject": claims["sub"],
                "x-aegis-bank-agent": claims["azp"],
            }
        )
    return headers
