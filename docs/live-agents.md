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

## Connected two-agent security walkthrough

Open `/ui/walkthrough` (Security Walkthrough in either sidebar). This controlled security test uses
the real registry, token service, gateway, MCP banking tools and audit records. It is not the retired
scripted Studio and never fabricates a denial, alert, approval or execution receipt.

1. As **Priya**, enter a unique pair-name prefix and click **Register and submit two agents**.
   A is a new LangGraph/Azure coordinator instance; B is a separate SDK/MCP Payments specialist.
   Both are DEV/on-prem runtimes owned by Niels. Permissions, delegation relationships and the local
   endpoint are configured before review. Existing Ava/KYC/Payments are not replaced.
2. As **Sanne**, review A and B through the registry links, enter an independent reason and click
   **Approve reviewed pair**. Normal registry separation-of-duties checks apply.
3. As **Priya** or owner **Niels**, click **Connect approved runtime templates**. Both must be active.
   The local development IdP supplies protected keys server-side, never to browser/run-history storage.
   This managed local connection is not enterprise IAM or arbitrary agent-code deployment.
4. As **Jan**, select that pair, check synthetic/paid-inference consent and run an account inquiry.
   The actual Azure-selected tool receipt and user-to-agent-to-tool lineage appear live.
5. Check consent again and click **Attempt forbidden permission widening**. A fresh valid payment
   Mandate authorizes the configured A-to-B pair. B's real token exchange additionally asks for
   `payments.status.read`, registered for B but excluded from this parent task. Expect **DLG-004**,
   a linked **DET-15** alert, a red dashed attempted delegation, no child Mandate and no banking call.
   This bounded challenge makes no Azure request.
6. Prepare a transfer above the displayed threshold to the specified new beneficiary. Review the
   exact proposal and click **Confirm this synthetic action** as Jan. Execution pauses at **Risk
   approval required**; customer confirmation alone must not change balance/payment records.
7. As **Sanne**, open the ordinary **Approvals** inbox and approve the matching approval ID with a
   justification. The same customer-confirmed action resumes automatically once. Expect one verified
   receipt and one committed payment. Rejection/expiry prevents continuation instead.
8. Prepare and customer-confirm a second transfer, leaving it awaiting risk approval. As **Mark**,
   review the blast radius, enter a reason, explicitly confirm suspension and click **Suspend A and
   revoke delegated work**. Expect **Stopped by governance**, descendant Mandates revoked and pending
   approval cancelled, with no second payment. B's identity stays active; its affected session dies.
9. Select each recorded run and open **complete audit and traces** as Mark/Eva. Root task, agent IDs,
   originating Jan identity, reasons and trace IDs correlate. Resume A only through its normal registry
   controls; old revoked tasks never revive.

Each case has a fresh task: an inquiry's permissions are never silently expanded into a payment.
Runtime connections and pending credentials stay in memory. After restart, reconnect approved pairs
and start fresh tasks; historical pending work remains interrupted/non-resumable. No uncertain writes
are automatically retried. The local bank orders suspension against transactional commits: uncommitted
work can be stopped, but committed payments are not undone. This does not claim process termination or
rollback of already-forwarded external banking/model requests.

Offline coverage (fixture model responses; no paid Azure or live database calls):

```powershell
.\.venv\Scripts\python -m pytest tests/test_security_walkthrough.py tests/test_scenarios.py tests/test_lineage.py tests/test_agent_runtime.py -q
```

## Configuration and launch

### Bank Assistant with your registered pair

Register, independently approve and connect A/B once in Security Walkthrough, as above. Then open
`/ui/assistant` as Jan and choose your pair under **Executing agent pair**. Normal requests now use
that exact coordinator and specialist, not the default Ava identities. These templates support
inquiry/transfer only; choose default Ava for KYC/address tasks. The runtime/budget header is for the
selected coordinator. Recorded runs label their actual coordinator and expose live lineage and linked
alerts. Staff can open **this coordinator / staff kill switch** directly from the selected run.

For the negative case, explicitly tick **Enable bounded permission-widening security test**, use:

```text
Test whether Payments can request payments.status.read beyond the permissions of this payment task.
```

Tick test consent and click **Run permission-widening test**. This selected mode invokes the existing
real token-exchange challenge; it does not ask Azure to interpret the prompt or invent an attack.
Normal requests never silently enable it. Expect DLG-004, DET-15, no child credentials and no bank call.
Disable test mode for a normal balance/transfer prompt. Pair transfers resume automatically after
customer confirmation and separate approval; default Ava retains its explicit resume button.

### Independent mock SIEM and real alert forwarding

From the repository root, after local PostgreSQL setup has protected `.local`, provision once:

```powershell
.\.venv\Scripts\python -m aegis_demo.siem --init
```

This creates a stable ingestion credential and connector settings in Git-ignored `.local/siem`.
It never prints the credential, overwrites an existing one, or restarts a running service. Windows
protection relies on the inherited `.local` ACLs from `local-postgres.ps1`; POSIX uses private modes.
Dotenv/process settings override this connector configuration. Set `AEGIS_SIEM_ENABLED=false` to disable.

Terminal 1 (separate receiver):

```powershell
.\.venv\Scripts\python -m aegis_demo.siem
```

Terminal 2 (restart Aegis only after finishing/cancelling pending work):

```powershell
.\.venv\Scripts\python -m aegis_demo.serve
```

Open `http://127.0.0.1:8011/` beside Bank Assistant. Trigger the permission-widening test again.
The receiver should show the same alert ID/rule as Aegis. As Mark, **Alert Management** shows
pending/sending/delivered/failed, attempt counts and measured alert-to-acknowledgement milliseconds.
Healthy delivery targets the plan's <5s window; inspect the measured value rather than assume it.

Alerts and outbox entries commit together in PostgreSQL (`siem_deliveries`). A separate worker sends
real authenticated HTTP requests, then records delivery only when the receiver acknowledges the event
ID and payload hash. Bounded retry/backoff, crash-recoverable leases and receiver ID deduplication avoid
silent loss and duplicate displayed alerts. A stopped receiver does not stop policy enforcement.
After retry exhaustion Mark can click **Retry delivery**; no banking action is retried. Only new alerts
raised while forwarding is enabled are queued; old history is not automatically exported.

The receiver independently stores minimized envelopes in `.local/siem/received.sqlite3` (not the banking
database). Prompts, raw evidence/tool arguments, bank details and credentials are not exported. Alert
titles use trusted detection labels. The local read-only viewer is unauthenticated and loopback-only;
never expose it publicly. This is an OCSF-inspired JSON demo receiver, not certified OCSF, Sentinel or
Splunk. A real SIEM needs its own destination/authentication/acknowledgement adapter.

### Enforced budget policy and a no-spend denial test

The Python model-policy engine already reserved an estimated daily allowance **before** Azure calls.
The completed presentation now includes per-agent holds/headroom/blocked requests in **Usage & Cost**,
one DET-16 warning at 80% per agent/day/policy version, and a correlated DET-17 alert on budget denial.
An over-limit next request returns `LLM-BUDGET` and never reaches Azure. This blocks further model calls,
not the agent's registration, and does not undo prior actions. OPA/tool policies were not changed.

To demonstrate blocking without burning credit, finish pending tasks and stop Aegis. In its terminal:

```powershell
$env:AEGIS_LLM_DAILY_BUDGET_EUR = '0.000001'
.\.venv\Scripts\python -m aegis_demo.serve
```

As Jan, select a connected pair, **disable security-test mode**, choose Account inquiry and ask
`What is my account balance?`, with Azure consent. Expect **Blocked / LLM-BUDGET**, zero model calls,
no banking receipt, an actual deny decision and DET-17 in both Aegis and the enabled mock SIEM.
This is real enforcement under an explicitly lowered demo limit, not fabricated spending.

Afterwards stop Aegis and restore the process setting (or remove it to use your existing dotenv limit):

```powershell
Remove-Item Env:AEGIS_LLM_DAILY_BUDGET_EUR
.\.venv\Scripts\python -m aegis_demo.serve
```

Reconnect approved pairs after either restart. Existing usage and uncertain holds are preserved.
The cost policy is configured estimation, not an Azure billing guarantee. Holds can block a request
before recorded usage reaches 100%, because the next call must fit in the remaining allowance.

Offline regression command (fixture Azure only; separate temporary receiver/database):

```powershell
.\.venv\Scripts\python -m pytest tests/test_siem.py tests/test_security_walkthrough.py tests/test_model_controls.py -q
```

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
