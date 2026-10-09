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
- **One identity per role** (`AEGIS_OIDC_ONE_ROLE_PER_ACCOUNT=true`, set by the Keycloak env script): a sign-in whose
  token maps to more than one Aegis role is refused, so conflicting duties (registering and approving an agent,
  authoring and approving policy) cannot sit on one login. Aegis still checks separation of duties per action on top of
  this. It does not apply to the passwordless dev IdP.
- **One person, many accounts** (`AEGIS_OIDC_PERSON_CLAIM`, `AEGIS_PERSON_LINKS`): every separation-of-duties check
  (registrant/owner cannot approve an agent, the initiator or an owner cannot approve an action, a policy's author cannot
  review or activate it) compares the *person* behind an account, not the username, so one human's role accounts cannot be
  used to approve their own work. An account's person comes from the trusted `AEGIS_PERSON_LINKS` directory (JSON
  `{"account": "person"}`, wins), else from the token claim named by `AEGIS_OIDC_PERSON_CLAIM` (for example
  `employee_id`), else it is the account name alone. When the claim is configured, a staff login without it (and without a
  link) is refused, because it could not be tied to a person. Each sign-in records account → person, so a name stored on
  a record (an agent's owner) resolves even when that person is not signed in; an owner who has never signed in and has no
  link resolves to their own name only. The `keycloak_setup env` script sets `AEGIS_PERSON_LINKS` for the demo's role accounts.
- **Ownership re-attestation** (`ownership.py`): owners must periodically confirm each active agent. Every confirmation is
  the ledger entry `attestation.confirmed`, so "last attested" is provable from the tamper-evident ledger. A background job
  (`AEGIS_ATTESTATION_INTERVAL_DAYS`, default 90; 0 = manual only) marks an agent due when its last confirmation or
  activation is older than the interval and gives the owner `AEGIS_ATTESTATION_GRACE_DAYS` (default 14). An overdue agent
  raises alert DET-14 once per due date; with `AEGIS_ATTESTATION_AUTO_ENFORCE=true` it is also suspended (default off, so a
  person decides before a live agent stops). A new campaign never extends a deadline that is already running.
  *Hand-over:* `POST /v1/agents/{id}/owner` moves an agent to a new owner (the current owner, a risk-approver or an admin);
  it clears the orphaned flag, starts the grace period for the new owner, and is recorded as `agent.owner_reassigned`.
  The new owner must not have left, may not be the same person as the old owner, and a person cannot make themselves the
  owner (SOD-004). A leaver orphans their suspended agents as well as their active ones. Limits: the job runs in every
  control-plane process (a pass is idempotent, so a second process only repeats work); it does not start on an in-memory
  database (use `POST /v1/attestations/run`); a leaver is matched by exact owner name, so only the dev IdP can mark a
  person as having left (with SSO, report them with `POST /v1/idp-events/leaver`).
- **Agents are managed only by their owner:** suspend, modify, submit, retire and attest act on an agent only for its
  owner (under any of their accounts). The `agent-owner` role alone grants nothing over other people's agents. The
  exceptions are deliberate: `soc-analyst` and `risk-approver` can suspend any agent (the kill switch must not wait for an
  owner), `admin` can modify, submit and retire any agent, and the registrant can modify and submit the agent they
  registered (changes to an active agent still force re-approval). Denials return `OWN-001`.
- **Local signing keys** persist in the protected `.local/keys` folder for the PostgreSQL console. Test keys are
  ephemeral. Neither approach is a production key store; use Azure Key Vault in a shared environment.
  - *Explicit creation, strict startup.* Persistent keys are created once, out of band, with
    `python -m aegis.keys init` (atomic `O_CREAT|O_EXCL` write at mode 0600; concurrent starts converge on one key).
    Normal startup then only *loads* them: a configured key that is missing or malformed raises `SigningKeyError`
    and stops the service, instead of silently minting a new identity that would invalidate every issued token and
    break evidence verification. Empty paths keep the old ephemeral behaviour for tests and laptop demos.
  - *Fingerprints, never private keys.* `python -m aegis.keys show` and the startup log print only the public-key
    RFC 7638 fingerprint. Record it, restart, and confirm it is unchanged to verify persistence. Private PEMs are
    never logged (even `repr(SigningKey)` shows only the kid and fingerprint).
  - *Backup and recovery.* Back up `AEGIS_SIGNING_KEY_PATH` and `AEGIS_IDP_KEY_PATH` (default `.local/keys/*.pem`)
    to an encrypted, access-controlled location; they are the signing identity. To recover, restore the files to the
    same paths and run `python -m aegis.keys show`; the fingerprints must match the recorded values. The keys stay
    out of Git (`.local/`, `*.pem`, `*.key` are ignored). Production uses Azure Key Vault instead of files.
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

Policy versions are immutable through the API. Replay precedes submission, a different person approves,
and activation checks the expected current version. Configuration/evaluator hashes must match before use.
An independent approver may reject a submitted proposal with a required justification; it cannot then activate.

**Rego is part of the version** (`policy_bundles`, hash-verified on every load). The `rego` / `opa` engines evaluate
the active version's stored Rego, so a file edit, a bad deploy or a tampered checkout cannot change a running decision;
it only shows up as "the repository differs". A proposed rule change must pass `rules_check.py` before it is saved:
module names and sizes are bounded, every runtime module must be in package `aegis.tool_call` (so a policy module can
never declare a `system.*` package, which OPA treats as server configuration), network, introspection and
non-deterministic builtins are refused anywhere in the text (comments included, so a comment-stripping bug cannot let
one through), it must compile and return a well-formed verdict, and every test case must still pass. A rule change
always needs a security sign-off (`security-approver`) in addition to the policy approval, from a different person than
both the author and the policy approver (`SEC-001` blocks activation until then); so does a configuration change whose
replay shows any decision becoming more permissive (a higher decision, less redaction or a looser rate limit). Replay
covers recorded traffic only, which is why rule changes need the sign-off regardless of what replay found. Rollback
returns to a version that was fully approved when it ran and needs no new sign-off. Limits: proposed Rego is compiled
and evaluated in the control-plane process (regopy) by people holding `policy-author`; size limits bound it, but treat
that role as privileged. The python engine is a fixed mirror and accepts configuration changes only.

**Pushing to OPA** (`AEGIS_OPA_PUSH_POLICY`, default on): on activation and rollback Aegis replaces OPA's modules
through its policy API (unknown modules removed first, OPA's compiler checks each write) and verifies the result before
committing; if OPA refuses, the previous Rego is put back and nothing is activated. At start-up it pushes the active
version, and it restores an OPA that restarted empty. It never silently overwrites an OPA that runs other Rego: that
fails closed until a policy approver, security approver or admin calls `POST /v1/policies/opa/sync` (recorded in the
ledger). Run OPA so that only the control plane can write to its policy API.

**Policy decision point, fail closed.** Any engine error, timeout (`AEGIS_OPA_TIMEOUT_SECONDS`, whole request),
unexpected answer (unknown decision or obligation, a deny without a reason) or an OPA that runs different Rego than
the approved policy becomes a recorded deny (`PDP-001`); there is no path where a PDP problem allows a call. OPA's
loaded modules are compared with the local Rego at most every 30 seconds (`/v1/policies`); a server that is changed
between checks can answer for up to that long, so restrict who can write to OPA (its policy API, or bundles
signed and served from a trusted location in production). Put an authenticating proxy in front of OPA (Aegis sends `AEGIS_OPA_TOKEN` as a bearer token; OPA's own token
authorization needs a system.authz policy, which the loaded-policy check refuses as an extra module) when it
is reachable by anything but the gateway. The governed configuration is sent with every decision and always
overwrites any `policy_data` a caller may have put into the input. The Rego is hardened to deny malformed input,
and differential tests check it is never more permissive than the Python mirror. A governed configuration missing a
field denies (`CFG-001`). Before any engine runs, the gateway refuses tool arguments that are too large or deep, or
contain NaN/infinity (also as text) or numbers too precise to compare reliably (`ARG-002`, recorded). Rego is compared
with OPA's loaded modules with line endings normalised, and `.gitattributes` keeps `.rego` files LF. regopy is native code: after any
native error its interpreter is discarded and rebuilt.
Replay evaluates recorded context only, without invoking tools, payment execution, counters or approvals.

SOC assignments must name active analysts. Case transitions are validated; resolution/false-positive status
requires a note. Notes and evidence links are appended to the audit ledger. PostgreSQL triggers reject direct
UPDATE/DELETE of ledger and case-event rows, and transaction-scoped advisory locks serialize ledger appends.
Database-owner/admin privileges can bypass those triggers, but not the signed evidence checkpoints: a rewritten
history no longer matches them unless the evidence key itself is also stolen. Keep that key in an HSM-backed Key
Vault in production. Deleting the most recent checkpoints is detectable only against an earlier exported pack.

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
