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

## Service and transport security
- **No shared service secret.** The data plane (Gateway) authenticates to the control plane with a signed
  ES256 assertion (`private_key_jwt`, RFC 7523), verified with the Gateway's public key — the same asymmetric
  model agents use to sign in. There is no static header secret whose leak would let either side forge the other.
- **Transport.** All inter-service and browser traffic runs over TLS; set `AEGIS_TLS_CERT_FILE` / `AEGIS_TLS_KEY_FILE`
  for direct termination, or terminate at a reverse proxy / Azure Container Apps ingress. Upstream MCP servers and the
  control plane are reachable only from the Gateway (internal ingress); data-plane ↔ control-plane uses mTLS in Azure.
- **CORS.** The APIs send CORS headers only for the exact origins in `AEGIS_CORS_ORIGINS` (no wildcards). Set this to
  the console's deployed URL; a cross-origin site cannot read API responses or send credentialed requests.
- **CSRF.** Operator and agent calls authenticate by `Authorization: Bearer` only — never by cookie — so a forged
  cross-site request carries no credential. Browser tokens live in `sessionStorage`, not cookies. Do not introduce
  cookie-based sessions for state-changing endpoints without also adding `SameSite=Strict` and a CSRF token.

## Development-only components — never deploy as-is
- **Dev IdP** (`/idp/login`) has no passwords. For any shared environment set `AEGIS_ENABLE_DEV_LOGIN=false` (login and
  persona list return 403 and persona tokens are rejected) and configure an OpenID Connect provider (`AEGIS_OIDC_*`,
  see the README). Agents' own identities come from the dev IdP unless `AEGIS_AGENT_IDP=keycloak`.
- **Keycloak agent identities** (`AEGIS_AGENT_IDP=keycloak`):
  - Aegis holds one credential for Keycloak, the `aegis-control-plane` client secret (`AEGIS_KEYCLOAK_ADMIN_CLIENT_SECRET`;
    a Key Vault reference in Azure). It can manage clients in the `aegis` realm and nothing else: no users, groups, realm
    settings, other realms. It *can* change any client in that realm, so Aegis refuses to touch its own and Keycloak's
    built-in clients; restrict it further with Keycloak's fine-grained admin permissions in production.
  - Keycloak stores only each agent's public key. It also keeps an unused internal client secret on every confidential
    client; the signed-JWT authenticator refuses sign-in with it (tested), so no shared secret can act as an agent.
  - The agent's private key is returned once at approval. The demo runtime additionally keeps a copy under
    `AEGIS_IDENTITY_STATE_DIR` (git-ignored) so a restarted demo can reuse it; never do this in production.
  - An identity token is valid for 5 minutes. Aegis re-confirms that the client is enabled at most every 10 seconds, and
    immediately after Aegis itself disables it. A token issued before a suspension is also useless because the STS refuses
    agents that are not active.
  - Failure behaviour: if Keycloak cannot be reached, approvals, resumes and Mandate requests fail with 503 (nothing is
    half-done, no Mandate is issued). Suspension is the exception: it always succeeds in Aegis, records
    `identity_disable_failed` in the ledger, and `POST /v1/identity/reconcile` (admin / security approver) disables the
    identity once Keycloak is back. Start-up also reconciles.
- **Built-in OIDC provider** (`--sso`, `/oidc`) is for demos: one shared password, ephemeral signing keys, no MFA.
  Never enable `AEGIS_BUILTIN_OIDC` outside a laptop.
- **SSO checks:** only asymmetric algorithms are accepted (no `none`/HS256 key confusion), issuer, audience and expiry are
  enforced, discovery must repeat the configured issuer, and unknown key IDs can trigger at most one key-set download per
  30 seconds. Anyone the provider authenticates but who has no mapped role gets no operator access (roles come only from
  the token). Browser tokens live in `sessionStorage` (gone when the tab closes), so a script injected into the console
  could read them: keep the console's content-security policy strict when deploying.
- **Local signing keys** persist in the protected `.local/keys` folder for the PostgreSQL console. Test keys are
  ephemeral. Neither approach is a production key store; use Azure Key Vault in a shared environment.
- **Gateway → control-plane identity** is asymmetric, not a shared secret. The Gateway signs a short-lived
  (60 s) ES256 assertion for each internal call with its own private key (`AEGIS_GATEWAY_SERVICE_KEY_PATH`;
  a Key Vault reference in Azure); the control plane verifies it with the Gateway's public key only
  (`AEGIS_GATEWAY_SERVICE_PUBLIC_KEY_PATH`), so it holds nothing that could forge a Gateway token. Locally
  the pair is generated in-process. The control plane fails closed (503) if the public key is absent. In Azure,
  pin this to the Gateway's workload identity (managed identity) and run data-plane ↔ control-plane over mTLS.
- The demo returns an agent's private key once at approval, for the demo runtime. In production it is delivered
  to the agent's secret store, never to a person.

## Secrets
No secret is committed. Configuration names are listed in `.env.example` with placeholder values only.
Run a secret scan (e.g. gitleaks) and `pip-audit` before every submission push.

The local PostgreSQL setup restricts `.local/` to the Windows user and SYSTEM. Database credentials and the
internal API token are user-bound encrypted in `credentials.clixml`; the application reads plaintext secrets
from the protected, Git-ignored `connection.json`. Do not expose the passwordless UI outside loopback.

## Policy, investigation and telemetry safeguards

Policy configurations are immutable through the API. Replay precedes submission, a different person approves,
and activation checks the expected current version. Configuration/evaluator hashes must match before use.
An independent approver may reject a submitted proposal with a required justification; it cannot then activate.
Supported configuration changes execute in the Python PDP; this is not an arbitrary-Rego publishing pipeline.
Replay evaluates recorded context only, without invoking tools, payment execution, counters or approvals.

SOC assignments must name active analysts. Case transitions are validated; resolution/false-positive status
requires a note. Notes and evidence links are appended to the audit ledger. PostgreSQL triggers reject direct
UPDATE/DELETE of ledger and case-event rows, and transaction-scoped advisory locks serialize ledger appends.
Database-owner/admin privileges can bypass those controls: this is not externally anchored, tamper-proof storage.

Adaptive risk uses recorded decisions and alerts, with a documented warm-up and active-minute median/MAD
baseline. No training history or scores are fabricated. Effective enforcement cannot reduce inherent risk.
Span attributes use a positive metadata-only whitelist, and outgoing correlation excludes arbitrary W3C baggage.
Span export excludes request bodies, tokens, prompts, SQL and exception text; local span retention still needs
a production policy. The current exporter writes to PostgreSQL, not an external OTLP/SIEM service.

On restart with a volatile hot store, old Mandates are revoked and pending approvals cancelled, with evidence
retained. This avoids allowing tasks to continue after their taint/rate-limit state has disappeared. A durable
hot store plus an actual resumable agent runtime is needed for continuity across production restarts.

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
