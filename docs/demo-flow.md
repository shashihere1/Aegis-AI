# Demo flow

Run `python -m aegis_demo.run` for the narrated version of scenes S0–S5 and a ledger-only S8 (output:
`docs/test-evidence/demo-run.txt`). The full 8-minute storyline is described scene by scene below.

| Scene | What happens | What it proves | Code / test |
|---|---|---|---|
| S0 | Registry with 1,247 agents; filtered query in ~10 ms | Inventory at enterprise scale (D1.1, M2) | `registry.py` |
| S1 | Priya registers agents, Sanne approves; a user holding both roles cannot approve their own agent (SOD-001); identities get private_key_jwt keys; signed passport | Lifecycle, unique identity, SoD (M1, M4, M12) | `test_s1_…` |
| S2 | Jan asks Ava to change his address. Ava gets a 5-minute Mandate for *customer.kyc.verify + customer.profile.update*, delegates to the KYC agent over A2A (purpose narrowed to *customer.kyc.verify*, nested `act` chain), KYC's result reaches Ava with BSN/IBAN/e-mail redacted, Ava updates the address and closes the task | JIT purpose-bound access, delegation chain, redaction, lineage, automatic revocation (M5, M7, M10, D2.3) | `test_s2_…` |
| S3 | A €25,000 transfer to a new beneficiary is held (PAY-010). Sanne approves; re-using the approval for €45,000 is denied (APR-001); the original executes once | Human approval bound to the exact action (M6) | `test_s3_…`, `test_approval_is_single_use` |
| S4 | A poisoned rental contract tells Ava to e-mail all records to an external address. The Guard flags the injection and taints the task; the e-mail is denied (IFC-001, lethal-trifecta breaker); DET-02 fires; the playbook suspends Ava and cascade-revokes the KYC agent's delegated mandate within the same request; no e-mail leaves | Prompt-injection controls, SOC alerting, immediate suspension and cascade revocation (M11, M13, M14) | `test_s4_…` |
| S5 | A scraper with a static API key hits the CRM through the Gateway; an identity created directly in the IdP is found by an IdP scan; both become findings; one is quarantined, the other claimed into a draft registration | Shadow-agent discovery (M3, D1.3) | `test_a12_…` |
| S7 | A EUR 5,000 transfer initially passes at threshold EUR 10,000; Priya drafts threshold EUR 2,000 and replays; Fatima separately approves and activates; the same transfer requires approval; rollback restores the original policy | Governed configuration changes and policy-only historical replay, not arbitrary Rego execution | `src/aegis/control/policies.py`, Policy Governance UI |
| S8 | Eva opens Audit Ledger, verifies the chain, downloads the auditor-only evidence pack, opens its HTML report and runs the offline verifier over the ZIP | Portable, tamper-evident demo records, including policies, cases, risk and traces (not a certified regulatory report) | `tests/test_evidence.py`, `test_every_decision_is_evidence` |

For S8 in the UI, first complete S2/S3/S4 so the pack contains approvals and alerts. Switch to **Eva Visser**
using the persona selector, open **Audit Ledger**, and click **Download evidence pack**. The ZIP includes
`report.html`, structured JSON, a SHA-256 manifest and `verify_pack.py`. After extracting the verifier, run
`python .\verify_pack.py "C:\path\to\aegis-evidence-....zip"`. Only explicit ephemeral mode resets its database;
download the pack before stopping that mode. The PostgreSQL console retains governance records
across restarts; its Studio log and bank effects remain volatile. The export is restricted to the Auditor role and fails closed if the
ledger hash chain is broken.

For S7, use **Demo Studio > EUR 5,000 policy threshold comparison**. Run it before creating the draft so replay
has compatible input records. Then **Priya > Policy Governance > Save immutable draft > Replay > Submit**;
**Fatima > select version > justification > Approve > Activate**. Run the scene again, approve the held transfer
as Sanne, then roll back to the original version as Fatima. Other security restrictions still apply: a suspended
agent or high-risk financial action is not made safe by raising the payment threshold. Reset the attack demo
and use healthy agents for this walkthrough.

On **Agent Lineage**, select a new task to see measured, shared-trace spans below the registry graph. For SOC,
**Mark > Alerts > select alert > assign analyst / add note / link decision**, then progress through investigation.
A resolution note is required. The agent detail page explains risk signals and shows baseline warm-up honestly
until sufficient actual traffic exists (20 calls across five completed active minutes).

Extra attack tests: A3 poisoned tool cannot be approved without override, A4 rug pull quarantines the tool,
A6 unauthorised tools are hidden and uncallable, A7/A8 delegation cannot widen purpose or skip the registry,
A10 audience misuse, A16 expired mandate, A17 agent cannot exceed the user it acts for, rate limiting,
material change forces re-approval, leaver orphans agents.
