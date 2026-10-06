# Security and Responsible AI notes

## Threat model summary
Aegis is a security control, so it is designed to fail closed:
- **No standing privilege.** Agents only act with a Mandate (default TTL 5 minutes, tier-capped at 2–15).
- **Deterministic enforcement.** Allow/deny comes from policy rules; ML and LLMs only add signals.
- **One chokepoint.** Upstream MCP servers must be reachable only from the Gateway (internal ingress in Azure);
  agent tokens are never forwarded upstream.
- **Containment.** Critical detections suspend the agent, revoke every mandate in its chains and disable its
  IdP identity. Revocation is checked on every request.
- **Evidence.** Every decision, approval and admin action is appended to a hash-chained ledger
  (`GET /v1/ledger/verify` detects tampering).

The attack suite in `tests/test_scenarios.py` is mapped to the OWASP Top 10 for Agentic Applications.

## Development-only components — never deploy as-is
- **Dev IdP** (`/idp/login`) has no passwords. Replace with Keycloak or Microsoft Entra Agent ID.
- **Ephemeral signing keys** are generated at start-up. Use Azure Key Vault keys in any shared environment.
- **Internal API token** (`AEGIS_INTERNAL_TOKEN`) protects Gateway → control-plane calls locally; use
  workload identity (managed identity / mTLS) in Azure.
- The demo returns an agent's private key once at approval, for the demo runtime. In production it is delivered
  to the agent's secret store, never to a person.

## Secrets
No secret is committed. Configuration names are listed in `.env.example` with placeholder values only.
Run a secret scan (e.g. gitleaks) and `pip-audit` before every submission push.

## Data
Synthetic data only (`demo/aegis_demo/data.py`). No client code, client systems, PII, PCI or PHI.
Only the OneStop-approved Azure OpenAI deployment may be configured as the live LLM, and the Gateway redacts
PII from confidential tool output before agents (and therefore the LLM) see it.

## Responsible AI minimums (Makeathon handbook)
- **Human review:** high-impact actions require a human approval bound to the exact action; AI-generated code in
  this repository must be reviewed by the team before use.
- **Grounding:** policy decisions are rule-based with reason codes and a policy version; no model output decides.
- **Fairness and privacy:** PII is redacted by policy obligation; no sensitive personal attributes are used.
- **Accountability:** tool calls, delegations, decisions and approvals are retained in the ledger, and LLM usage
  (tokens, cost, latency per agent and mandate) is recorded. Prompt text itself is not stored.

## Reporting
Report suspected vulnerabilities or incidents immediately to the team lead and the STG Core Team / ISG channel
(see the Makeathon participant handbook's escalation matrix). Do not investigate a security incident on your own.
