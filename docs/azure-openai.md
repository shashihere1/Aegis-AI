# One real Azure model call through Aegis

This describes the gateway connection and single-call smoke check, not the separate
[live LangGraph / Microsoft Agent Framework assistant](live-agents.md). Neither feature implements
live banking, enterprise user authentication or Azure application hosting.
Use only approved model deployments and synthetic data. Global Standard may process prompts globally;
resource location alone does not establish processing-location approval.

## Configure locally

The server automatically reads `.env` and `.env.local` at the repository root when it starts. You can skip
the PowerShell key prompt entirely. Create or edit `.env` locally with just these Azure settings:

```dotenv
AEGIS_AZURE_OPENAI_ENDPOINT=https://aegis-test-1435115.openai.azure.com
AEGIS_AZURE_OPENAI_DEPLOYMENT=aegis-chat
AEGIS_AZURE_OPENAI_API_VERSION=2025-01-01-preview
AEGIS_AZURE_OPENAI_API_KEY=replace-with-your-resource-key
```

The gateway now also enforces Python model controls on all Azure requests, including the smoke call.
Set the actual deployment processing footprint and its permitted scope as described in
[live-agents.md](live-agents.md#configuration-and-launch). Unknown geography fails closed; the server
does not infer processing permission from a region. For your Global Standard deployment, `global` must
be explicitly permitted for approved synthetic inference. Budget holds and policy snapshots persist.

Replace the last value with Key 1 or Key 2 from the approved **aegis-test-1435115** Azure OpenAI resource.
Do not use a key for another resource or paste the key into chat. `.env.azure.example` is an Azure-only
template with an intentionally blank key; the app does not read example files. Never add real secrets to
tracked examples. Do not copy the full `.env.example` unchanged: its database settings override your local
PostgreSQL configuration. Keep existing unrelated settings intact if you already have a local dotenv file.

Precedence (highest first): process environment, `.env.local`, `.env`, protected `.local/connection.json`,
then built-in defaults. File values do not change the terminal's environment. Keys are read literally, with
no `${...}` substitution. `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT` and
`AZURE_OPENAI_API_VERSION` are also accepted; an `AEGIS_*` name wins over its alias within the same source.

If you previously entered an incorrect key through the PowerShell helper, remove its process override
from the terminal you will use to start the server so the new dotenv value can take effect:

```powershell
Remove-Item Env:AEGIS_AZURE_OPENAI_API_KEY,Env:AZURE_OPENAI_API_KEY -ErrorAction SilentlyContinue
```

This clears only the current terminal's key variables; it does not delete your dotenv file or update a running
server. Configuration and keys are captured at server startup, so load the updated console yourself when
ready. If the key is supplied only by the process environment, skip this removal step and no dotenv is needed.

### Optional: hidden-prompt setup instead of a dotenv file

If you prefer not to store a local plaintext key file, the existing PowerShell helper still works:

```powershell
.\deployment\local-azure-openai.ps1 `
    -Endpoint 'https://aegis-test-1435115.openai.azure.com' `
    -Deployment 'aegis-chat' `
    -ApiVersion '2025-01-01-preview'
```

These are the deployment details supplied during setup, not a hard-coded allowlist shared with every user.
Substitute your own approved deployment if needed. The API version above is preview; confirm it is permitted
and supported. The helper only changes this terminal's process environment; it does not call Azure, persist
the key, modify PostgreSQL credentials or restart anything. If company policy blocks the script, ask your
administrator for the approved configuration method; do not bypass execution policy.

The endpoint must be the base `https://<resource>.openai.azure.com` (or Azure's
`https://<resource>.services.ai.azure.com`), not the full chat URL or Foundry project endpoint. The gateway
builds the deployment-specific path with `api-version`. Other hosts, plaintext HTTP, alternate ports,
embedded credentials, redirects and a request-supplied alternate deployment are rejected. Network proxies
and trusted-certificate environment settings are respected; TLS verification stays enabled.

Do not print or share `.env`, `.env.local`, `.local/connection.json`, API keys, tokens or environment dumps.
The dotenv files are Git-ignored but plaintext, not encrypted. Neither a local file nor a process environment
variable is a production secret vault. No key is sent to the browser or saved to PostgreSQL by this setup.
The current Azure branch supports key authentication, not Entra bearer authentication.
The proxy preserves the [documented Chat Completions response](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
and reads its returned `prompt_tokens` / `completion_tokens`; it does not invent live usage.

When you choose to load the updated app, launch it from the repository root. If using process variables or
the helper, use the same configured terminal:

```powershell
.\deployment\local-postgres.ps1 -Action Start
.\.venv\Scripts\python -m aegis_demo.serve
```

An already-running server keeps its previous code/settings until you restart it yourself. Neither the helper
nor the smoke command restarts it. Do not use `--ephemeral`: that mode intentionally ignores dotenv, persisted and
environment settings. Azure configuration takes precedence over the offline upstream; an Azure failure
never silently falls back to the fake model. The narrated `aegis_demo.run` still uses its explicit offline model.

## Check, then explicitly call

In a second terminal at the repository root:

```powershell
# Configuration check only; no inference, connectivity test or bank action.
.\.venv\Scripts\python -m aegis_demo.llm_smoke --check

# Explicitly send ONE short synthetic prompt to Azure; incurs normal inference charges.
.\.venv\Scripts\python -m aegis_demo.llm_smoke --call
```

Use `--base-url http://127.0.0.1:8001` if the console is on another port. Only loopback URLs are accepted.
The command logs in as synthetic customer Jan through the development IdP, then calls the running console's
authenticated smoke API. The API uses Ava's private-key identity and the initiating user's token to obtain
a new purpose-bound Mandate. It calls `Task.chat()` through `/gw/llm/v1/chat/completions`, which validates
the Mandate, audience, expiry, revocation and `llm.chat` scope before sending the brokered Azure credential.
No raw model prompts, user tokens or Azure keys are written into execution-span attributes.

This is deliberately a fixed prompt, not a generic customer-data upload endpoint. No MCP tools, payments,
document reads or emails execute. One request is allowed in flight; no automatic inference retries are made.
The Mandate is completed in a `finally` block, including when Azure fails. An attack-suspended Ava is refused;
this command does not automatically resume it or weaken governance to obtain a response.

Success output contains the model reply, deployment, completion ID, optional Azure request ID, Mandate/root
IDs, returned token counts, measured latency and the configured cost estimate. Look in **Usage & Cost**,
**Activity**, **Access Control** and the task's **Agent Lineage** for the resulting usage, receipt and trace.
The receipt records gateway authorization, not an OPA evaluation of the LLM request.

Readiness means configuration is present and syntactically valid; it does not prove permission, connectivity,
quota, API compatibility or organizational approval. Only the explicit live call verifies inference.
Price defaults are indicative: set `AEGIS_LLM_PRICE_IN_PER_1K` and `AEGIS_LLM_PRICE_OUT_PER_1K` to reviewed
EUR rates per thousand tokens before interpreting cost. The estimate is not an Azure billing record and does
not separately price cached tokens. `llm_max_output_tokens` (default 1024), `llm_max_request_chars` (16000),
and `llm_timeout_seconds` (30) bound gateway requests; smoke output is capped at 128 tokens.

## Failures

- Missing/old smoke endpoint: load the updated console yourself when ready.
- Missing key: set it in repository-root `.env` / `.env.local`, or the terminal that starts the server.
  Loading a key only in the smoke-command terminal does not change the server's key.
- Authentication/access errors: configuration readiness means a key is present, not that Azure accepts it.
  Check the matching resource's current key, any higher-priority stale environment override, key-auth policy
  and network configuration. Reading from dotenv cannot fix an incorrect or revoked credential.
- Deployment/API errors: check the exact deployment name and the supported API version.
- Network errors: check approved VPN, proxy, private-endpoint DNS and firewall access; never disable TLS.
- Rate limiting: inspect Azure quota and wait before retrying.
- Timeout, interrupted call, missing usage or cleanup failure: the request may already have reached Azure.
  Inspect Aegis usage and Azure diagnostics before retrying; successful inference could still be billable.

The passwordless development IdP and demo routes remain localhost-only demonstration conveniences,
not production authentication. Never expose this console or its smoke API publicly.
