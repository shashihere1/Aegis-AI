# Live banking assistant: real frameworks, synthetic banking

The **Bank Assistant** screen at `/ui/assistant` is the normal customer experience. Scripted Demo Studio
and fake model routes are no longer mounted in the normal app.
Ava executes a real LangGraph state graph: Azure chooses a function, validated code dispatches it through
Aegis, and the tool result returns to the graph. KYC executes a two-executor Microsoft Agent Framework
workflow (verification then receipt). KYC does not use an LLM; its verification data is synthetic.
Payments is a deterministic Python A2A specialist. Its MCP backend transactionally updates PostgreSQL-backed
synthetic balances and payment records. Accounts and document records are synthetic; payments are not real
settlement and document checks are not genuine KYC. See the README's persistent sandbox/migration section.

There is no OPA implementation change in this feature. Existing MCP policy enforcement still runs through
the selected gateway engine. The new model controls are explicitly Python-enforced, not Rego execution.

## Configuration and launch

Your successful package checks establish that the frameworks are installed, not that a workflow ran.
For a new environment, use the approved package source:

```powershell
.\.venv\Scripts\python -m pip install -r requirements-agents.txt
.\.venv\Scripts\python -m pip check
```

Keep your existing Azure credentials in `.env` / `.env.local` or process environment. Do not share keys.
The deployed `aegis-chat` resource was reported as **Global Standard**. East US is its resource region,
not a guarantee that inference stays in the US. If globally processed **synthetic** inference is approved,
add these non-secret settings to your existing local dotenv file:

```dotenv
AEGIS_LLM_PROCESSING_SCOPE=global
AEGIS_LLM_ALLOWED_PROCESSING_SCOPE=global
AEGIS_LLM_DAILY_BUDGET_EUR=1.00
AEGIS_LLM_MAX_DATA_CLASS=confidential
```

Do not set `eu` for a Global Standard deployment. That would misdescribe its processing footprint.
For EU-only processing you need an actually approved EU processing deployment, then both scope settings
must be `eu`. The scope is declared configuration, not remotely attested proof of Azure residency or
organizational approval. Unknown or disallowed geography is rejected **before** a request reaches Azure.
These controls also apply to the existing smoke endpoint; previous credential readiness is insufficient.

Review `AEGIS_LLM_PRICE_IN_PER_1K` / `AEGIS_LLM_PRICE_OUT_PER_1K` against approved deployment rates.
These are EUR per thousand tokens, not prices supplied by Azure. Defaults are illustrative estimates.

When you choose to load the updated app, run from the repository root:

```powershell
.\deployment\local-postgres.ps1 -Action Start
.\.venv\Scripts\python -m aegis_demo.serve
```

The UI bundle is built in `web/dist`. For later frontend changes:

```powershell
Push-Location web
npm run build
Pop-Location
```

The running console is not restarted by editing code. `--ephemeral` intentionally ignores local Azure
configuration and is not the mode for this live feature. Keep the console on localhost.

## UI demonstration

Open <http://127.0.0.1:8000/ui/assistant> and choose **Jan de Vries** in the persona switcher (or click
"Act as Jan"). Staff can inspect runs but cannot initiate or confirm paid customer tasks on Jan's behalf.
The top card shows dependency versions, configured deployment, declared processing footprint and budget.
It does not call Azure or prove connectivity. All live submissions require synthetic-data/paid-call consent.

1. **Account inquiry:** ask "What is my account balance?" Azure should choose `get_balance`. The gateway
   checks the signed Mandate, tool scope, approved schema, policy and ownership before returning the synthetic
   account's balance. The UI separately labels model prose and verified tool results.
2. **Document verification:** ask to verify `D-77`. Ava delegates through A2A to KYC. The resulting receipt
   is labelled `microsoft-agent-framework`, because that workflow actually executed.
3. **Address change:** select Address change and use the example. KYC must succeed first. Review the exact
   proposed address, then confirm. The write ends with the tool's receipt rather than an invented model answer.
4. **Transfer:** select **Make a transfer**, then ask to transfer EUR 25,000 to the demo landlord as a new beneficiary.
   In the right-hand **Live workflow & receipts** panel, review the exact amount, IBAN and reference in
   **Review before execution**, then click **Confirm this synthetic action**. The Azure consent checkbox is not
   payment confirmation. Under the default EUR 10,000 policy this additionally waits for risk approval. Switch to
   **Sanne Bakker**, approve that matching request in Approvals, return to **Jan** and click Resume. An expired,
   rejected, revoked or consumed approval cannot execute the payment. Approval thresholds follow your active
   existing tool policy; altered policy versions can change this outcome.
5. As staff, inspect **Activity**, **Usage & Cost**, **Agent Lineage**, **Access Control** and the audit ledger.
   The assistant's model and tool events are recorded separately. View the exact run's root ID to inspect lineage.

Transfer and address tasks require structured function selection (`tool_choice="required"`); the write functions
prepare a proposal without executing it. An explicit `explain_without_action` control function lets the model exit
without a write for missing details, informational questions, declined requests or unavailable operations.
A text-only response on these paths is **No action prepared**, never a completed change or a confirmation button.
There is no automatic paid re-planning retry, and no application-generated payment from model prose.
Historic completed action runs without a change receipt display a warning; they are not reopened or replayed.
Committed sandbox operations return a PII-safe verification hash binding the exact normalized arguments, tool and
task root. The assistant verifies this instead of comparing redacted IBAN/address strings with their original values.
This hash is local transaction evidence, not an external signature. A mismatched write receipt is **Execution uncertain**;
inspect the stored account and Activity before another write.

Azure output is non-deterministic: it can ask for missing details or fail argument validation. That is not
replaced with a fake success. At most six bounded model calls are allowed per task; parallel tool dispatch,
arbitrary functions, arbitrary model URLs, customer-ID selection, and a second write in one task are refused.
The customer selects a purpose before submission, narrowing the root Mandate and available operations.
The directory binds Jan's signed identity to `C-1001` and its documents. A gateway call selecting another
customer is denied even if a model invents an ID. The gateway directory is synthetic, not enterprise ownership integration. The banking repository also
checks the signed initiating subject against the stored customer owner, independently of model-supplied IDs. Untrusted documents still pass through Aegis's injection/taint checks.

## Persistence and budget behavior

In the configured PostgreSQL database `aegis`, inspect:

| Table | Stores |
| --- | --- |
| `bank_customers`, `bank_accounts`, `bank_documents` | Persistent synthetic profiles, balances and documents; starter records are never reset. |
| `bank_operations`, `bank_payments`, `bank_entries` | Idempotency results, payment receipts and balanced debit/credit records. |
| `agent_runs` | Run status, proposals, verified results and display history; no model API key or bearer token. |
| `llm_reservations` | Budget holds, returned-token cost estimates, deployment, UTC day and model-policy snapshot/version. |
| `usage` | Actual returned token counts and measured latency with estimated cost. |
| `decisions` | Gateway allow/deny records. |
| `approvals`, `mandates`, `ledger_entries` | Existing authorization and tamper-evident audit records. |

Model policy configuration is server-owned in local dotenv/environment settings. It is not editable from
the Policy Governance screen. The exact policy snapshot/version used for each allowed external request is
retained with its reservation. Budget holds are committed before Azure calls; PostgreSQL transaction locks
serialize concurrent reservations. The per-agent daily limit includes outstanding holds and all configured
Azure deployments used by that agent. Settlement and usage insertion are atomic and idempotent per hold.

Input bytes plus protocol overhead and bounded output conservatively estimate the hold. This is a configured
cost control, not a guarantee against Azure billing overruns: actual tokenization, pricing, cached-token
discounts and provider billing can differ. Failed/uncertain requests retain the entire hold, even an Azure
authentication failure; holds are not automatically forgiven. A successful response replaces the hold with
its returned-token estimate. The budget resets by UTC request-start day, not by deleting history.

Bank balances, address changes, payment records, verification results and idempotency receipts persist alongside
run history, budgets and governance records. Active framework state and Mandate tokens stay only in memory.
Restart revokes local tasks,
cancels pending approvals and marks their run histories interrupted; pending writes are never auto-replayed.
Paid calls have no automatic retry, and duplicate run request IDs return the original history. The local
runtime supports one open run per customer and one console process, not multi-worker resumable orchestration.

## What is still outside this implementation

Real bank services, enterprise account directories, Keycloak/Entra authentication, production credentials
and authorization, verified cloud/network residency controls, full OPA publishing/activation, and durable
multi-worker workflow recovery remain separate work. Never use real customer data or expose the development
persona login publicly. Sandbox checks execute real MCP, LangGraph and Microsoft Agent Framework through
the UI's HTTP routes, using explicit offline model responses (not paid Azure). Transactional banking tests
also run against isolated local PostgreSQL schemas. These checks do not restart the user's console or claim
live Azure acceptance of the updated workflow. See `tests/test_bank_sandbox.py`, `tests/test_agent_runtime.py`
and `tests/test_model_controls.py`.

API references: [LangGraph graph API](https://docs.langchain.com/oss/python/langgraph/graph-api),
[Microsoft Agent Framework executors](https://learn.microsoft.com/en-us/agent-framework/concepts/workflows/executors),
[Chat Completions tool-call contract](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
