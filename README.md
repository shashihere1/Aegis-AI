# Aegis AI — governance and identity for autonomous AI agents

**STG Makeathon Edition #21 · Problem Statement PS-1 "Agentic AI Governance Framework"**
Team: **Zero_Trust_Architechture (ZTA)** · Members and primary contact: `<fill in before submission>`

> *Aegis AI gives every AI agent a passport, every action a purpose, and every decision a receipt.*

Agents hold **zero standing privileges**. For each task an agent exchanges its identity (and the user's
token) at the Aegis STS for a short-lived, purpose-bound **Mandate** (OAuth 2.0 Token Exchange, RFC 8693,
with the intent as a Rich Authorization Request, RFC 9396). Every MCP tool call, agent-to-agent delegation
and LLM call goes through the **Aegis Gateway**, where a policy decision point returns
*allow / deny / require approval / redact / rate-limit*, and every decision is written to a
**hash-chained evidence ledger**.

## What works today

| Capability (PS-1) | Status | Where |
|---|---|---|
| Agent registry, lifecycle (register → approve → suspend → retire), risk tiering, signed passport | ✅ | `src/aegis/control/registry.py` |
| Segregation of duties (registrant/owner cannot approve; approver ≠ initiator/owner) | ✅ | `registry.py`, `approvals.py` |
| IdP integration seam + dev IdP; agents authenticate with `private_key_jwt` (no shared secrets) | ✅ | `src/aegis/control/identity/idp.py` |
| **Every agent's own identity in Keycloak**: a per-agent client registered with the agent's public key only, signed-JWT sign-in, short-lived tokens checked on every Mandate request, kill switch that disables the identity, drift repair, shadow-identity discovery | ✅ (tested against a real Keycloak 26.2.5 and a fake; Entra Agent ID not built) | `agent_identity.py`, `identity_sync.py` |
| JIT, task-scoped, purpose-bound Mandates; agent ∩ user ∩ purpose ("intersection rule") | ✅ | `src/aegis/control/identity/sts.py` |
| A2A delegation with attenuation, nested `act` chain, depth/cycle/pair rules | ✅ | `sts.py`, `src/aegis/gateway/app.py` |
| Central PDP: allow / deny / require-approval / redact / rate-limit, policy version on every decision | ✅ | `config/policies/`, `src/aegis/policy/engine.py` |
| Human approval bound to the exact action (hash of tool + arguments + mandate), single use | ✅ | `approvals.py`, gateway |
| MCP server & tool registry, definition pinning (rug-pull quarantine), poisoning scan | ✅ | `src/aegis/control/tools_registry.py` |
| Tool-level authorization; unauthorised tools hidden from `tools/list` | ✅ | gateway |
| Prompt-injection detection + session taint + **lethal-trifecta breaker** (IFC-001) | ✅ | `src/aegis/guard/`, policies |
| PII redaction (BSN 11-proof, IBAN, e-mail, phone) as a policy obligation | ✅ | `src/aegis/guard/pii.py` |
| SOC detections, auto-suspend playbook, **cascade revocation** across delegated mandates | ✅ | `src/aegis/control/soc.py` |
| Shadow-agent discovery (Gateway traffic + IdP scan), claim / quarantine | ✅ | `src/aegis/control/discovery.py` |
| Re-attestation campaign, leaver → orphaned agents | ✅ (basic) | `registry.py` |
| Lineage graph user → agents → tools → data | ✅ | `soc.py` (`/v1/lineage/{root}`) |
| Auditor-only demo evidence pack: HTML report, JSON records, SHA-256 manifest and offline verifier | ✅ (local demo) | `src/aegis/control/evidence.py` |
| LLM proxy (OpenAI-compatible → approved Azure OpenAI) with token, cost and latency capture | ✅ | gateway |
| Versioned policy configuration: draft, replay, separate approval, activation and rollback | ✅ (Python PDP configuration) | `src/aegis/control/policies.py` |
| Policy-only time machine over recorded inputs; never executes tools or payments | ✅ (compatible evaluator versions) | `policies.py` |
| Shared OpenTelemetry trace across SDK, gateway, delegated agents and MCP; PostgreSQL exporter and UI waterfall | ✅ (local exporter, not cloud OTLP) | `src/aegis/telemetry.py` |
| SOC case assignments, notes, evidence links, validated statuses and append-only history | ✅ | `src/aegis/control/investigations.py` |
| Explainable adaptive risk from actual recorded traffic and security alerts | ✅ (statistical baseline, not an ML model) | `src/aegis/control/risk.py` |
| React console in the prototype's look (live data, persona switcher, Bank Assistant and Investigation Copilot) | ✅ | `web/` |
| Sign-in for people through any OpenID Connect provider (Keycloak, Microsoft Entra ID, Okta...): authorization code + PKCE, signature/issuer/audience/expiry checks, provider roles mapped to Aegis roles; dev login can be switched off | ✅ (tested against a fake provider and a built-in one; not yet against a live Keycloak or Entra tenant) | `src/aegis/control/identity/oidc.py`, `users.py`, `web/src/lib/auth.ts` |
| Natural-language investigation Copilot (PS G2), investigator RBAC, read-only MCP evidence and verified citation IDs | Implemented; offline regression coverage, live Azure acceptance pending | `src/aegis/control/investigation.py`, `demo/aegis_demo/copilot.py` |
| **Three policy engines on one governed policy**: the Python mirror, the authoritative Rego in-process (regopy), and an OPA server that must run exactly the approved Rego; any engine failure is a recorded deny | ✅ (OPA server tested against a fake OPA here; the real-OPA tests run in CI) | `src/aegis/policy/engines.py`, `config/policies/` |
| Regulatory-grade evidence packs, Azure deployment, Microsoft Entra Agent ID provisioning of agent identities, publishing Rego *source* changes through governance | ⏳ remaining | — |


## Persistent synthetic banking sandbox

The normal app no longer seeds thousands of inventory rows, constructs scripted Ava, exposes scripted
scenario/reset routes, or mounts the fake LLM. Five MCP services operate on PostgreSQL-backed synthetic
records: core-banking, payments, KYC, documents and CRM. The obsolete notification and poisoned FX fixture
servers are retired on upgrade; their registry/audit records are preserved and hidden from the active tools UI.
Only the explicit `aegis_demo.testing` fixture world retains the old servers and security scenarios.

- Transfers lock the two accounts in a fixed order, debit and credit in one transaction, write two balanced
  entries and a durable payment receipt, and append an audit event in the same commit. Insufficient funds,
  unknown recipients and audit failures roll back all effects.
- A unique task-root/tool operation key prevents duplicate execution. A repeated identical authorized call
  returns the original receipt; changed arguments under the same key are refused. This is local transaction
  idempotency, not a guarantee about external banking settlement.
- Document checks validate stored ownership, supported type and expiry and retain a result. They do **not**
  establish document authenticity or verify a real person's identity. Address changes require a successful
  check for the same customer in the same task, plus the assistant's explicit customer confirmation.
- The customer UI shows the current stored balance, address and recent committed payments without an Azure
  request. MCP endpoints reject direct callers; a process-local, gateway-brokered credential is sent only
  to the exact built-in endpoints, with the verified task's subject/root/agent. This is not enterprise bank IAM.

Tables: `bank_customers`, `bank_accounts`, `bank_documents`, `bank_operations`, `bank_payments`, `bank_entries`.
Synthetic starter records are inserted once; startup never resets an existing balance or address. Old in-memory
fixture transfers cannot be recovered as settled database payments and are not fabricated during migration.

On first upgraded startup, changed payment/KYC definitions are imported and **remain quarantined until
independent review**. As Fatima El Amrani, open **MCP Servers & Tools**, review the updated definitions and
approve `payments.initiate_transfer`, `kyc.verify_document` and `kyc.get_kyc_status`. The assistant displays any
other tool requiring review. Do not use a poisoning override for this migration. Existing agent suspensions,
classification edits, approvals, audit records and signing keys are not reset.

For targeted registry cleanup (never a database reset):

```powershell
.\.venv\Scripts\python -m aegis_demo.registry_cleanup --check
.\.venv\Scripts\python -m aegis_demo.registry_cleanup --apply
# Recovery, if required: use the batch_id printed by --apply
.\.venv\Scripts\python -m aegis_demo.registry_cleanup --restore-batch '<batch_id>'
```

Only original `registered_by="seed"` scale-test rows without credentials, capabilities, activity or delegation
references are eligible. Snapshots remain in `registry_seed_archive`; genuine/user-created agents and evidence
are retained. There is no automatic seed inventory creation on normal startup.

## The console

A React + TypeScript console in the look of the Fabric Vibe Studio prototype, on the live API:

| Page | What it shows |
|---|---|
| Agent Registry / agent detail | Functional registered agents only (Ava, KYC, Payments, Investigation Copilot by default), with filters and CSV export; Passport, explained risk score, capabilities, delegation rules, lifecycle trail, kill switch with blast-radius preview |
| Shadow Agents · Re-attestation | Findings from Gateway traffic and IdP scans (claim / quarantine); attestation campaigns, enforcement, leaver handling |
| Activity · SOC Dashboard · Alerts | Live decision stream; decisions-per-minute chart, top denied agents, playbook actions; triage drawer with evidence |
| Agent Lineage | Registry lineage graph plus real OpenTelemetry execution timings, service names and shared trace IDs |
| Prompt Injection · Usage & Cost | Detections with highlighted payloads and a scan playground; tokens, cost and latency per agent |
| Access Control · Approvals | Live Mandates with countdowns and revoke; approval cards bound to the exact action (amount, IBAN, chain) |
| MCP Servers & Tools · Policy Governance · Audit Ledger | Tool classification and pins; approved configuration versions, replay and rollback; reference Rego source; hash-chain verification and evidence export |
| Investigation Copilot (also the floating bot for investigators) | Real Azure tool selection through Aegis; cited, redacted excerpts from recorded decisions, alerts, traces and other audit records; read-only |

### Investigation Copilot (PS good-to-have G2)

This is separate from Ava's banking assistant. Start the updated server using your existing Azure configuration,
then open **http://127.0.0.1:8000/ui/copilot**. In development, select **Mark Jansen (SOC analyst)** or
**Eva Visser (auditor)**. Other roles and anonymous callers cannot use the investigation API. With OIDC,
the verified role mapping must grant `soc-analyst` or `auditor`; the server derives `investigation.read`
only for those roles. A caller-supplied entitlement alone cannot grant investigation access.

Confirm that the question and records are synthetic and that you authorize paid Azure inference, then ask:

- “Why was Ava blocked in the last 24 hours?”
- “Which agents acted for jan.devries in the last week?”
- “What alerts were raised in the last 24 hours?”
- “Show approvals of at least EUR 10,000 approved by sanne.bakker in the last week.”
- “Show the recorded timeline for trace `<exact trace ID from Activity or Lineage>`.”

Azure selects up to three fixed read-only tools on the `aegis-investigate` MCP server, then produces a
structured cited answer. The registered `Aegis-Investigation-Copilot` obtains its own purpose-bound Mandate
on behalf of the investigator. The existing gateway handles tool approval/pins, scope, entitlements,
revocation and model budget/data-class/processing-scope checks. No new provider, package or cloud resource
is required, and there is no fake-model fallback. Startup onboards this agent and its tools using the
existing development bootstrap approval flow; this is not a new enterprise approval process.

The tools are `search_decisions`, `get_agent`, `get_trace_timeline`, `get_delegation_chain`, `list_alerts`,
`usage_summary`, `get_lineage`, `get_policy_version` and `search_approvals`. There is **no arbitrary SQL,
bank action, policy change, approval mutation or containment tool**. Query arguments are typed and bounded.
The upstream MCP endpoint requires a random gateway-only credential, never the browser's token. The broker
sends it only to the exact reserved local URL; it is not forwarded to other registry-controlled destinations.
For separately deployed services, configure the same protected `AEGIS_INVESTIGATION_TOKEN` on both sides;
the current composition shares it in memory. This is not workload identity or a vault integration.

Every factual statement must cite an ID actually retrieved in that investigation. Open a source to see
the server-generated record ID, console link and redacted excerpt. Invalid/missing citations, malformed
responses and incomplete completions are rejected. Citation checking establishes **provenance, not factual
correctness of model reasoning**; review the source records. Empty results explicitly report missing evidence.
Queries default to 24 hours UTC, allow at most 31 days and return at most five rows per model call; exact ID
lookups and lineage are separate. Truncation and query filters are shown. This is not exhaustive search or
a regulatory investigation report. Missing traces cannot be reconstructed as proof of execution.

Raw prompts, tool arguments/results, alert payloads and trace attributes are not sent to Azure. Typed payment
amounts are exposed without beneficiary details for approval investigations. Pattern-based secret/PII masking
is an additional safeguard, not complete DLP. Do not use real customer records in this synthetic-only console.

Question/answer snapshots, citation excerpts, query coverage and usage metadata persist in the configured
database's **`copilot_runs`** table (PostgreSQL in the normal local setup). Startup creates the new table;
no manual SQL is needed. Starts/finishes are recorded in the hash-chain ledger; model and tool decisions
appear under the Copilot's own root Mandate in Activity/Lineage. Histories are private to each investigator.
Bearer tokens and keys are not stored in history. Request UUIDs prevent the same request from triggering
another paid call. The single-process console serializes admission; production multi-worker admission would
need additional coordination. Interrupted runs are marked interrupted on restart, never resumed or replayed.

The UI requires explicit consent, never automatically retries a paid request, and resets on persona changes.
Up to four Azure completions can incur charges per investigation; all costs shown are configured estimates,
not Azure invoices. OPA remains unchanged. This initial implementation returns a complete answer, not a
streaming token response, and cannot recover records that were never collected.

Offline verification (does not call Azure):

```powershell
.\.venv\Scripts\python -m pytest tests/test_copilot.py -q -p no:cacheprovider
cd web
npm run build
```

The structured-answer and function-call contracts follow the existing Chat Completions gateway and the
[official structured-output guidance](https://developers.openai.com/api/docs/guides/structured-outputs).

The header's persona switcher logs in as Mark (SOC), Sanne (risk approver), Priya (developer), Fatima (security),
Eva (auditor) or the admin, and buttons a persona may not use are disabled with the required role in the tooltip,
so segregation of duties is visible on screen.

```powershell
cd web
npm install          # uses your npm config, which on Infosys laptops points at the Infy Artifactory mirror
npm run build        # writes web/dist, which the demo server serves at /ui
cd ..
.\deployment\local-postgres.ps1 -Action Start       # start the project-local persistent database
.venv\Scripts\python -m aegis_demo.serve            # then open http://127.0.0.1:8000/ui/
# UI development with hot reload: keep the server running, then in web/: npm run dev -> http://127.0.0.1:5173/ui/
```

Suggested demo order: Bank Assistant → account inquiry → document D-77 → confirmed address change →
EUR 25,000 synthetic transfer → switch to Sanne and approve → return to Jan and Resume →
inspect the changed stored balance, payment ID, lineage and audit → Investigation Copilot as Mark.
Approval alone does not execute a transfer; the customer explicitly resumes it.

For the evidence finale, switch to **Eva Visser (Auditor)**, open **Audit Ledger**, and download the evidence pack.
Open `report.html` in the ZIP for the readable story. Extract `verify_pack.py` and run
`python .\verify_pack.py "C:\path\to\aegis-evidence-....zip"` to recompute its file hashes and ledger chain. The export is
auditor-only and refuses to download if ledger verification fails. It contains synthetic demo records,
including approval arguments and policy inputs, so treat the ZIP as confidential. Its manifest is not
externally signed or timestamped, and the local role gate uses the passwordless dev IdP; this is **not**
a certified regulatory report or production access control.

## Run it (Windows, Python 3.14; no Docker needed)

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock      # through the Infy Artifactory mirror
.venv\Scripts\python -m pip install --no-build-isolation --no-deps -e .
.\deployment\local-postgres.ps1 -Action Start                 # uses installed PostgreSQL 18; loopback port 55432
.venv\Scripts\python -m pytest                                 # tests needing a real OPA binary skip without one (CI has it)
.venv\Scripts\python -m aegis_demo.run                         # optional offline security fixture driver, not the app
.venv\Scripts\python -m aegis_demo.serve                       # console /ui, API docs /docs and /gw/docs (--port to change)
```

The browser server now uses **persistent PostgreSQL**, not SQLite, by default. On this laptop the existing
PostgreSQL 18 binaries are used to run a separate project cluster; no Docker, cloud database or Windows service
is required. The setup script creates a non-superuser application login, random credentials and a random internal
service credentials. Secrets and signing keys live in the ACL-restricted, Git-ignored `.local/` folder. Do not print, share,
delete or commit `.local/connection.json`; it contains the database connection secret.

To use a deliberately disposable SQLite demo, explicitly add `--ephemeral`. The narrated command and ordinary
unit tests remain disposable. The server refuses to silently substitute SQLite when PostgreSQL is not configured.
Database status and stop commands: `deployment/local-postgres.ps1 -Action Status` and `-Action Stop`.

On the Infosys network add `--proxy ""` to pip if the configured proxy fails.
The normal app runs the control plane, Gateway, five persistent synthetic-bank MCP servers (official MCP
SDK), a read-only investigation MCP server and four functional agents in one process. Ava uses Azure tool calling
and LangGraph; KYC executes Microsoft Agent Framework; Payments is a deterministic transactional specialist. Personas log in through the dev IdP
(`POST /idp/login {"username": "mark.jansen"}`); the persona list is in `demo/aegis_demo/catalog.py`.

## Sign in with SSO (OpenID Connect)

People sign in at an identity provider, never with a password typed into Aegis. The console runs the standard
authorization-code flow with PKCE and sends the resulting access token as a bearer token; the control plane checks
its signature against the provider's published keys (JWKS), its issuer, audience and expiry, then maps the provider's
roles or groups to Aegis roles. Agents are separate: each authenticates with its own `private_key_jwt` identity, see
[Agent identities in Keycloak](#agent-identities-in-keycloak).

```powershell
# Try it on a laptop, nothing to install: also starts a small built-in OIDC provider at /oidc (demo only)
.venv\Scripts\python -m aegis_demo.serve --sso          # prints this run's password for the demo accounts
# open http://127.0.0.1:8000/ui -> header menu -> "Sign in with SSO" -> e.g. sanne.bakker + the printed password
```

| Setting | Keycloak | Microsoft Entra ID |
|---|---|---|
| `AEGIS_OIDC_ISSUER` | `https://<host>/realms/<realm>` | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `AEGIS_OIDC_CLIENT_ID` | public client with PKCE (S256) | SPA app registration's client ID |
| `AEGIS_OIDC_AUDIENCE` | client ID (default) or an audience mapper | `api://<client-id>` if you expose an API |
| `AEGIS_OIDC_ROLES_CLAIM` | `realm_access.roles` | `roles` (app roles) |
| `AEGIS_OIDC_ROLE_MAP` | `{"aegis-approver":"risk-approver", ...}` | `{"Aegis.Approver":"risk-approver", ...}` |

Set `AEGIS_ENABLE_DEV_LOGIN=false` to turn the passwordless persona switcher off (its tokens are then rejected too);
the Aegis roles to map are `OPERATORS` in `src/aegis/control/auth.py` (plus `customer`). Add the console's callback
URL (`<console origin>/ui/auth/callback`) to the provider's redirect URIs. Details of what is and is not covered:
[`SECURITY.md`](SECURITY.md).

### Real Keycloak on a laptop (no Docker)

Keycloak 26 runs from its zip with Java 21. On Infosys laptops the zip comes through Artifactory (Maven coordinates
`org.keycloak:keycloak-quarkus-dist`, e.g. `.../artifactory/maven-remote/org/keycloak/keycloak-quarkus-dist/26.2.5/`);
save it as `Downloads\keycloak\keycloak-quarkus-dist-26.2.5.zip`. `JAVA_HOME` must point to a Java 21 JDK.

```powershell
.venv\Scripts\python -m aegis_demo.keycloak_setup start     # unpacks to .local/keycloak, imports the `aegis` realm
. .\.local\keycloak\aegis-env.ps1                            # sets AEGIS_OIDC_* for this PowerShell window
.venv\Scripts\python -m aegis_demo.serve --ephemeral          # then: header menu -> Sign in with SSO
.venv\Scripts\python -m aegis_demo.keycloak_setup stop        # also: status | env | reset
```

The realm is generated from the demo personas. **Every Aegis role has its own account and no account holds two roles**:
a person who acts in several roles gets one login per role (for example `priya.raman` registers agents and
`priya.raman.policy-author` drafts policy), so duties cannot be combined on one identity. All accounts share one generated
password, printed by `start` and kept in `.local/keycloak/credentials.json` (git-ignored). The `aegis-console` client
is public with S256 PKCE and exact redirect URIs. Stop the built-in `--sso` server first if it is using port 8000.

| Account | Aegis role | Person |
|---|---|---|
| `priya.raman` | agent-developer | Priya Raman |
| `priya.raman.policy-author` | policy-author | Priya Raman |
| `niels.vandijk` | agent-owner | Niels van Dijk |
| `sanne.bakker` | risk-approver | Sanne Bakker |
| `mark.jansen` | soc-analyst | Mark Jansen |
| `fatima.elamrani` | security-approver | Fatima El Amrani |
| `fatima.elamrani.policy-approver` | policy-approver | Fatima El Amrani |
| `eva.visser` | auditor | Eva Visser |
| `admin` | admin | Platform Admin |

**Changing role means signing in as the other account.** Use the header menu: **Switch account** (or **Sign in with SSO**) first ends your Keycloak session, then shows a fresh login form, so you pick the account. (Keycloak otherwise keeps you signed in and would silently log you straight back in as the previous account, and even `prompt=login` only re-asks that same user's password.) Choosing a demo persona from the menu while signed in with SSO also ends the Keycloak session. Token expiry renews silently. For a fast demo keep two browser windows, one signed in per role, or use the persona switcher.

The env script sets `AEGIS_OIDC_ONE_ROLE_PER_ACCOUNT=true`: Aegis then **refuses any sign-in whose token holds more than
one Aegis role** (with a message telling the user to use a separate account per role). The demo personas of the built-in
dev IdP are unaffected. `keycloak_setup accounts` prints this directory; `keycloak_setup ensure-role-identities` upgrades
an already running realm to it (`start` does this too, and repeating it is safe).

### Agent identities in Keycloak

By default agents get their identity from the built-in demo IdP. With `AEGIS_AGENT_IDP=keycloak`, **every approved agent
becomes its own Keycloak client** and Keycloak (not Aegis) issues its identity token:

| Step | What happens |
|---|---|
| Approval | Aegis creates the client `agent-<agent id>` through Keycloak's Admin API: signed-JWT sign-in only, no flows, no scopes, and **only the agent's public key** (as a JWKS). The private key is returned once in the approval response for the agent's own secret store. |
| Each task | The agent signs a 60-second note with its private key and gets a 5-minute token from Keycloak, addressed to `aegis-sts`. It exchanges that for a purpose-bound Mandate, as before. |
| Every exchange | Aegis checks the token against the realm's published keys (issuer, audience, expiry, token type) and that the client still exists and is enabled (cached for at most 10 s). If Keycloak cannot be asked, no Mandate is issued. |
| Suspend / retire / quarantine | The identity is disabled in Keycloak at once, in addition to revoking Mandates. The kill switch does **not** depend on Keycloak: if it is down, the agent is still suspended, the failure is written to the ledger, and `POST /v1/identity/reconcile` repairs the provider side later. |
| Discovery | The scan lists the realm's machine identities and flags any that no registry agent stands behind (shadow) or whose agent no longer exists (orphaned). |

Aegis manages Keycloak as a **least-privilege service account** (`aegis-control-plane`): it may manage clients in the `aegis`
realm and nothing else; it cannot read users, change realm settings or touch other realms (verified by the tests).

```powershell
.venv\Scripts\python -m aegis_demo.keycloak_setup start              # also creates the control-plane client (safe to repeat)
. .\.local\keycloak\aegis-agent-idp-env.ps1                          # AEGIS_AGENT_IDP=keycloak and the admin client's settings
.venv\Scripts\python -m aegis_demo.serve --ephemeral
.venv\Scripts\python -m aegis_demo.keycloak_setup clean-agents        # remove identities left by earlier demo runs
```

With a disposable (`--ephemeral`) demo every start creates new agents, so old identities pile up in Keycloak and the scan reports them
as orphaned; `clean-agents` clears them. Tests: `tests/test_agent_identity.py` (fake Keycloak), `tests/test_agent_identity_world.py`
(whole system with a fake), and `tests/test_keycloak_agent_identity_live.py` / `tests/test_keycloak_world_live.py` (a real Keycloak,
skipped when it is not running).

### Policy engines: Python, Rego, OPA

The tool-call policy is written in Rego (`config/policies/tool_call.rego`, the authoritative version). Three engines
can make decisions with it, chosen by `AEGIS_POLICY_ENGINE`:

| Engine | What evaluates the policy | Needs |
|---|---|---|
| `python` (default) | An in-process Python mirror of the Rego (`src/aegis/policy/engine.py`) | nothing |
| `rego` | **The Rego itself**, in-process, through regopy (Microsoft's rego-cpp) | `regopy` (in `requirements.lock`) |
| `opa` | **The Rego in an Open Policy Agent server** over its REST API | an OPA server (`AEGIS_OPA_URL`) |

All three use the same governed policy: each decision carries the active, approved configuration (`input.policy_data`)
and is recorded with that version id, so the Policy Governance lifecycle (draft, replay, approve, activate, rollback)
works with every engine. With OPA, Aegis first checks that the server runs **exactly** the approved Rego (it compares
OPA's loaded modules with the local ones) and refuses to use it otherwise. If an engine is down, slow, returns
something unexpected, or runs different Rego, the call is **denied** (`PDP-001`) and the refusal is recorded; nothing is
ever allowed by default. Switching engine on an existing database needs one newly approved policy version, because a
version is bound to the evaluator that was approved (`rules_hash`).

The Rego is hardened to fail closed: missing or wrong-typed fields deny, an unknown data ceiling counts as `public`, and
a transfer amount that is not a number (for example the text `"25000"`) is refused (`ARG-001`) instead of compared.

```powershell
$env:AEGIS_POLICY_ENGINE = 'rego'; .venv\Scripts\python -m aegis_demo.serve --ephemeral      # the Rego, no binary
# with an OPA binary (AEGIS_OPA_BINARY, `opa` on PATH, or Downloads\opa\opa_windows_amd64.exe):
.venv\Scripts\python -m aegis_demo.opa_setup start          # OPA on http://127.0.0.1:8181 serving config/policies
. .\.local\opa\aegis-opa-env.ps1; .venv\Scripts\python -m aegis_demo.serve --ephemeral
.venv\Scripts\python -m aegis_demo.opa_setup test           # opa test config/policies (the generated Rego unit tests)
```

How it is kept honest: `tests/policy_cases.py` holds the shared cases. They run through the Python mirror, the Rego via
regopy and a real OPA, which must agree exactly; they also generate `config/policies/tool_call_test.rego` for
`opa test`. `tests/test_policy_differential.py` runs 4,800 generated inputs: well-formed ones must agree exactly and,
on malformed or hostile ones, the Rego must never be more permissive than the Python mirror. CI
(`.github/workflows/ci.yml`) installs OPA and runs `opa check`, `opa test` and the full suite.

## Architecture

```
 Personas ──► Control plane (FastAPI)  registry · STS · approvals · discovery · SOC · ledger
                    ▲ internal API                       │ policies (Rego / Python engine)
 Agents ──MCP/A2A/LLM + Mandate──► Aegis Gateway (PEP) ──┴──► MCP servers · agents · Azure OpenAI
                    revocations / taint / rate limits: hot store (memory locally, Valkey in Azure)
```
See `demo/aegis_demo/world.py` for the full wiring and [`docs/demo-flow.md`](docs/demo-flow.md) for the
scene-by-scene flow.

## Local defaults vs. deployment (honest list)

| Concern | Local / tests | Azure deployment (planned) |
|---|---|---|
| Identity provider | Built-in dev IdP (no passwords — never expose); optional built-in OIDC demo provider (`--sso`) | People: any OIDC provider (Keycloak, Entra ID...) through `AEGIS_OIDC_*`. Agent identities: Keycloak (`AEGIS_AGENT_IDP=keycloak`, built and tested); Microsoft Entra Agent ID not built |
| Policy engine | `AEGIS_POLICY_ENGINE=python` (default), `rego` (the Rego itself, in-process) or `opa` (local OPA via `aegis_demo.opa_setup`) | OPA sidecar with the same Rego, checked against the approved Rego before every use |
| Database | Persistent PostgreSQL for `serve`; SQLite only for tests/narration/explicit `--ephemeral` | Managed PostgreSQL, migration/backup/retention procedures still required |
| Hot store | In-memory | Valkey (`ValkeyHotStore`, extra `valkey`) |
| Signing keys | Persisted in protected `.local/keys` for the PostgreSQL console; ephemeral in unit tests | Azure Key Vault |
| LLM | Normal app: Azure only, no fake fallback. Missing configuration disables live tasks. Offline test fixtures are explicit | Entra/key-vault credential integration and cloud operations remain planned |

## One real Azure model call

See [Azure setup and smoke-call instructions](docs/azure-openai.md). The local console can call one explicitly
configured Azure OpenAI deployment through a fresh Ava Mandate, recording returned usage, measured latency
and a prompt-free authorization receipt. A configured Azure failure does not fall back to the fake model.

```powershell
# Against a running console loaded with the updated code and Azure settings:
.\.venv\Scripts\python -m aegis_demo.llm_smoke --check   # configuration only; no Azure call
.\.venv\Scripts\python -m aegis_demo.llm_smoke --call    # one explicit, paid synthetic inference request
```

The command never starts/restarts the console or asks for its Azure key. The server automatically reads
repository-root `.env` and `.env.local`; process environment variables take priority. Use `.env.azure.example`
as an Azure-only template, and keep actual keys in Git-ignored local files or server environment variables,
not in source or command-line arguments. The narrated test driver remains an explicit scripted/offline fixture. Scripted Studio routes and the fake model
are not mounted in the normal app; its Studio UI and launchers have been removed.
The smoke call checks inference only. For actual framework execution, use the separate
[live Bank Assistant](docs/live-agents.md), with installed agent extras and explicit model-processing controls.

## Live Bank Assistant

Open `/ui/assistant`, act as synthetic customer Jan, select a purpose and authorize paid synthetic inference.
Ava uses a real LangGraph graph with Azure-selected tools. KYC uses a real Microsoft Agent Framework workflow.
Transfers and address changes pause for exact-argument confirmation; policy-driven risk approval remains separate.
Model deployment, declared processing geography, data ceiling and per-agent daily estimated budgets are enforced
in Python. Run histories and budget reservations persist in PostgreSQL. OPA and enterprise IAM remain separate work.
See [configuration, launch commands, demonstration and limitations](docs/live-agents.md).

## API (selection)

`POST /v1/agents` · `POST /v1/agents/{id}/approve|suspend|resume|retire` · `GET /v1/agents/{id}/blast-radius` ·
`POST /sts/token` (RFC 8693) · `GET /.well-known/jwks.json` · `POST /v1/mcp/servers/{id}/import` ·
`POST /v1/tools/{id}/approve` · `GET|POST /v1/approvals…` · `GET /v1/alerts` · `GET /v1/decisions` ·
`GET /v1/lineage/{root}` · `GET /v1/ledger/verify` · Gateway: `POST /gw/mcp/{server}`, `POST /gw/a2a/{agent}`,
`POST /gw/llm/v1/chat/completions`, `GET /gw/.well-known/oauth-protected-resource/mcp/{server}` (RFC 9728).

Auditor-only export: `GET /v1/evidence/summary` · `GET /v1/evidence/pack` (ZIP attachment).

Policy lifecycle: `GET|POST /v1/policies/versions` ·
`POST /v1/policies/{id}/replay|submit|approve|reject|activate|rollback`.
Investigations: `GET|PATCH /v1/alerts/{id}/case`. Risk: `GET /v1/risk/{agent_id}`.
Measured traces: `GET /v1/traces?root_id=...` or `?trace_id=...`.

## Demonstrate the new features

1. In Bank Assistant, request a EUR 5,000 transfer to the existing synthetic landlord, explicitly indicating
   an existing beneficiary. Confirm the exact proposal. With a EUR 10,000 threshold and otherwise permitting
   policy, it can execute without risk approval. This moves synthetic funds; use separate task IDs for comparisons.
2. Switch to **Priya Raman**, open **Policy Governance**, enter threshold `2000` and a justification,
   save the draft, replay recent decisions, and submit it. Replay does not execute another transfer.
3. Switch to **Fatima El Amrani**, select that version, add a review justification, approve, then activate.
   The author cannot self-approve, even if they have both roles. Activation rejects a stale active-version pointer.
   Fatima can also **reject with justification**; a rejected proposal cannot be activated. Both review outcomes
   retain the reviewer and reason. Replay shows obligation/redaction changes as well as allow/deny changes.
4. Request the same EUR 5,000 transfer as a new task and confirm it. It now waits for human approval. Switch to
   **Sanne Bakker**, approve the exact request, return to Jan and Resume. As Fatima, roll back to the original
   superseded policy version; a new equivalent task no longer needs the threshold approval.
5. Open **Agent Lineage** for the new task to see real spans. Older records without traces are not reconstructed
   into fake timings. When a suspicious request raises an alert, switch to **Mark Jansen**, assign it, add notes and link
   decision evidence. Resolution and false-positive transitions require a justification.
   Saved evidence links retain the decision's task, trace and policy version, and open that exact task directly.
6. Open an agent detail page for its adaptive risk explanation. A baseline needs 20 historical calls across five
   completed active minutes. It honestly displays **warming up** until there is enough traffic; no history is seeded.
7. As **Eva Visser**, export the evidence pack. It now also includes policy versions, the active pointer, SOC case
   history, recorded risk scores and execution spans.

PostgreSQL keeps the registry, policy changes, cases, evidence, synthetic profiles, balances, payments and
idempotency receipts across restarts. There is no Studio run log in the normal app. Because the local hot store is
volatile, restart revokes old task Mandates and cancels pending approvals instead of restoring access with lost
taint/rate-limit state. Start a fresh task after restarting. Resolving an alert does not automatically resume an agent.

This workflow edits supported configuration (thresholds, redaction entities, approval side effects), whichever policy
engine runs. Rego *source* is not edited through the console: changing the Rego, the Python evaluator or the engine
requires a newly reviewed policy version; older incompatible inputs are skipped during replay. Production
authentication and cloud telemetry export remain separate work.

## Tests and evidence

Standalone SDK users must configure an OpenTelemetry SDK provider/exporter for SDK spans; the demo supplies its
local provider. W3C trace context is explicitly carried by the SDK and gateway clients, not dependent on the
demo's HTTP hook. Arbitrary baggage, prompts and exception text are not exported as trace attributes.

`tests/` covers the PII and injection detectors, every policy rule, the ledger's tamper detection, and
end-to-end scenes S1–S4 plus attacks A3, A4, A6, A7, A10, A11, A12, A16, A17, rate limiting, material-change
re-approval and leaver handling. Latest results: [`docs/test-evidence/pytest.txt`](docs/test-evidence/pytest.txt);
narrated run: [`docs/test-evidence/demo-run.txt`](docs/test-evidence/demo-run.txt); console screenshots:
[`docs/test-evidence/console/`](docs/test-evidence/console/).

## Responsible AI, security and limitations

See [`SECURITY.md`](SECURITY.md). Known limitations: the dev IdP has no passwords (switch it off with `AEGIS_ENABLE_DEV_LOGIN=false`); SSO has been tested only against a fake provider and the built-in one, not a live Keycloak/Entra tenant; the Python policy engine
mirrors the Rego (kept in step by exact and differential tests); a real OPA binary has not been run on the
development laptop (no approved download route yet), so the real-OPA tests run only in CI; scripted security scenes exist only in explicit offline fixtures, while the
[Bank Assistant](docs/live-agents.md) uses real LangGraph/Azure planning and a Microsoft Agent Framework KYC workflow;
governed editing changes supported configuration, not Rego source; Microsoft Entra Agent ID provisioning and
Azure deployment are not built yet; Keycloak agent identities have been run
only on a local single-node Keycloak (no clustering, TLS or secret manager). Adaptive risk is an explainable
statistical baseline, not a trained model. Single-process hot-store and pending workflow state remain volatile;
banking balances/receipts, governance and evidence records persist in PostgreSQL.

## Transparency: what was built when, and AI assistance

Per the participant handbook, see [`docs/progress.md`](docs/progress.md). This increment was prepared in the
permitted pre-event window **with AI coding assistance (Claude Code)** and must be reviewed by the team before
it is relied on or demonstrated. All data is synthetic; no client code, systems or data are used.

Third-party licences: [`LICENSES.md`](LICENSES.md).
