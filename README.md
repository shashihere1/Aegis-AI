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

## What works today (increment 1: the governed-transaction core)

| Capability (PS-1) | Status | Where |
|---|---|---|
| Agent registry, lifecycle (register → approve → suspend → retire), risk tiering, signed passport | ✅ | `src/aegis/control/registry.py` |
| Segregation of duties (registrant/owner cannot approve; approver ≠ initiator/owner) | ✅ | `registry.py`, `approvals.py` |
| IdP integration seam + dev IdP; agents authenticate with `private_key_jwt` (no shared secrets) | ✅ | `src/aegis/control/identity/idp.py` |
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
| LLM proxy (OpenAI-compatible → approved Azure OpenAI) with token, cost and latency capture | ✅ | gateway |
| OpenTelemetry spans with GenAI + `aegis.*` attributes | ✅ (SDK spans; exporter by env) | gateway |
| React console in the prototype's look (17 screens, live data, persona switcher, Demo Studio) | ✅ | `web/` |
| Policy time-machine, evidence packs, Copilot, Azure deployment, Keycloak/Entra/OPA adapters | ⏳ next increments | — |

## The console

A React + TypeScript console in the look of the Fabric Vibe Studio prototype, on the live API:

| Page | What it shows |
|---|---|
| Agent Registry / agent detail | 1,247 agents with filters and CSV export; Passport, explained risk score, capabilities, delegation rules, lifecycle trail, kill switch with blast-radius preview |
| Shadow Agents · Re-attestation | Findings from Gateway traffic and IdP scans (claim / quarantine); attestation campaigns, enforcement, leaver handling |
| Activity · SOC Dashboard · Alerts | Live decision stream; decisions-per-minute chart, top denied agents, playbook actions; triage drawer with evidence |
| Agent Lineage | Interactive graph user → agents → tools → data for every task, with each decision and rule |
| Prompt Injection · Usage & Cost | Detections with highlighted payloads and a scan playground; tokens, cost and latency per agent |
| Access Control · Approvals | Live Mandates with countdowns and revoke; approval cards bound to the exact action (amount, IBAN, chain) |
| MCP Servers & Tools · Policy Editor · Audit Ledger | Tool classification, pins and poisoning findings; the live Rego bundle and rule catalogue; hash-chain verification |
| Demo Studio (also the floating button) | Runs scenes S2–S5 and A4 against the real APIs, with a step-by-step run log and a reset |

The header's persona switcher logs in as Mark (SOC), Sanne (risk approver), Priya (developer), Fatima (security),
Eva (auditor) or the admin, and buttons a persona may not use are disabled with the required role in the tooltip,
so segregation of duties is visible on screen.

```powershell
cd web
npm install          # uses your npm config, which on Infosys laptops points at the Infy Artifactory mirror
npm run build        # writes web/dist, which the demo server serves at /ui
cd ..
.venv\Scripts\python -m aegis_demo.serve            # then open http://127.0.0.1:8000/ui
# UI development with hot reload: keep the server running, then in web/: npm run dev -> http://127.0.0.1:5173/ui
```

Suggested demo order: Demo Studio → S2 → open Agent Lineage → S3 → switch to Sanne and approve in Approvals (the
payment then executes by itself) → S4 → SOC Dashboard and Alerts → Reset.

## Run it (Windows, Python 3.14; no Docker needed)

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock      # through the Infy Artifactory mirror
.venv\Scripts\python -m pip install --no-build-isolation --no-deps -e .
.venv\Scripts\python -m pytest                                 # 44 tests (11 OPA-conformance tests need an opa binary)
.venv\Scripts\python -m aegis_demo.run                         # narrated demo of scenes S0-S5, S8
.venv\Scripts\python -m aegis_demo.serve                       # console /ui, API docs /docs and /gw/docs (--port to change)
```

On the Infosys network add `--proxy ""` to pip if the configured proxy fails.
The demo runs everything in one process: control plane, Gateway, seven mock-bank MCP servers (official MCP
SDK), the KYC and Payments agents (A2A) and Ava, with synthetic data only. Personas log in through the dev IdP
(`POST /idp/login {"username": "mark.jansen"}`); the persona list is in `demo/aegis_demo/catalog.py`.

## Architecture

```
 Personas ──► Control plane (FastAPI)  registry · STS · approvals · discovery · SOC · ledger
                    ▲ internal API                       │ policies (Rego / Python engine)
 Agents ──MCP/A2A/LLM + Mandate──► Aegis Gateway (PEP) ──┴──► MCP servers · agents · Azure OpenAI
                    revocations / taint / rate limits: hot store (memory locally, Valkey in Azure)
```
See `demo/aegis_demo/world.py` for the full wiring and `demo/aegis_demo/run.py` for the scene-by-scene flow.

## Local defaults vs. deployment (honest list)

| Concern | Local / tests | Azure deployment (planned) |
|---|---|---|
| Identity provider | Built-in dev IdP (no passwords — never expose) | Keycloak adapter / Microsoft Entra Agent ID adapter (not built yet) |
| Policy engine | In-process Python engine implementing `config/policies/tool_call.rego` | OPA sidecar with the same Rego; `tests/test_policy.py` checks both agree when `opa` is installed |
| Database | SQLite (`aiosqlite`) | PostgreSQL (`asyncpg`, extra `postgres`) |
| Hot store | In-memory | Valkey (`ValkeyHotStore`, extra `valkey`) |
| Signing keys | Generated at start-up | Azure Key Vault |
| LLM | Deterministic fake endpoint (`demo/aegis_demo/fake_llm.py`) | OneStop-approved Azure OpenAI (`AEGIS_AZURE_OPENAI_*`) |

## API (selection)

`POST /v1/agents` · `POST /v1/agents/{id}/approve|suspend|resume|retire` · `GET /v1/agents/{id}/blast-radius` ·
`POST /sts/token` (RFC 8693) · `GET /.well-known/jwks.json` · `POST /v1/mcp/servers/{id}/import` ·
`POST /v1/tools/{id}/approve` · `GET|POST /v1/approvals…` · `GET /v1/alerts` · `GET /v1/decisions` ·
`GET /v1/lineage/{root}` · `GET /v1/ledger/verify` · Gateway: `POST /gw/mcp/{server}`, `POST /gw/a2a/{agent}`,
`POST /gw/llm/v1/chat/completions`, `GET /gw/.well-known/oauth-protected-resource/mcp/{server}` (RFC 9728).

## Tests and evidence

`tests/` covers the PII and injection detectors, every policy rule, the ledger's tamper detection, and
end-to-end scenes S1–S4 plus attacks A3, A4, A6, A7, A10, A11, A12, A16, A17, rate limiting, material-change
re-approval and leaver handling. Run `pytest -v` to reproduce the results, and `python -m aegis_demo.run` for a
narrated run of the storyline.

## Responsible AI, security and limitations

See [`SECURITY.md`](SECURITY.md). Known limitations: the dev IdP has no passwords; the Python policy engine
must be kept in step with the Rego (conformance tests); scripted planners stand in for LLM planning in the
demo; the Policy Editor is read-only (simulation comes next); OPA/Keycloak/Entra adapters and the Azure
deployment are not built yet; the demo's data lives in memory and resets when the server restarts.

## Transparency: what was built when, and AI assistance

Per the participant handbook, this increment was prepared in the permitted pre-event window **with AI coding
assistance (Claude Code)** and must be reviewed by the team before it is relied on or demonstrated. A day-by-day
log of what was built when is kept by the team internally. All data is synthetic; no client code, systems or
data are used.

Third-party licences: [`LICENSES.md`](LICENSES.md).
