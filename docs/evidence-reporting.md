# Automated evidence and reports

This implements the problem statement's Good-to-Have **automated regulatory evidence and report generation**
and supports its **compliance-ready logs and reports** deliverable. It builds on the existing dedicated ES256
evidence signing key and checkpoint API; those were already implemented in main.

## What runs

- A versioned [15-control catalog](../config/controls/catalog.json), aligned with plan Appendix D (AEG-C01–C15).
  Each control has fixed evidence queries and record/file citations, with relevant event filters for ownership,
  oversight, segregation of duties and reporting. Generic logs cannot stand in for an attestation event.
  There is no generated SQL or LLM inference.
- EU AI Act, DORA and GDPR reference mappings; NIST AI RMF 1.0 function-level and ISO/IEC 42001 **indicative**
  management-system alignment. Official source links are shipped in the catalog and coverage output.
- A deterministic executive summary, decision statistics, HTML report (printable to PDF), JSON evidence and
  spreadsheet-safe CSV. Counts distinguish recorded evidence from legal compliance or control effectiveness.
- SHA-256 member hashes, a dedicated-key ES256 manifest signature and a signed source-ledger checkpoint.
- Date, agent and task-root scoping. Defaults are the last seven inclusive UTC calendar days, all agents.
  Framework selection changes the mapping, not which underlying activity records are selected.
- Selected ledger payloads plus Merkle inclusion proofs; unrelated history is not shipped just to verify a chain.
  The server verifies the complete source chain before signing. The offline verifier verifies selected entries'
  inclusion against the signed root, **not undisclosed chain contents or completeness of the source system**.
- Current related inventory, risk/tool state and active/referenced policy versions are labelled as context,
  not reconstructed historical state. Required parent mandates and prior alerts investigated during the period
  are retained and explicitly listed under `scope.prior_context_records`.
- Saved ZIP bytes, hashes, signing-key fingerprints and report metadata in `evidence_reports`; schedules in
  `evidence_schedules`. PostgreSQL triggers reject rewriting/deleting report content and signed checkpoints.
  The first auditor review is separately ledgered and cannot rewrite either the ZIP or a prior review.
- Hourly/daily/weekly rolling-interval reporting, pause/resume and a manual due-worker check. The worker polls
  every 60 seconds by default, also creates due hourly checkpoints, and is stopped cleanly on shutdown.
  Reporting is disabled for in-memory SQLite. File-backed SQLite supports a single process; PostgreSQL row locks
  and unique slot keys coordinate multiple workers. Artifact/checkpoint/audit/next-slot advancement commit together.
  Downtime catches up one interval per schedule per worker pass. Failures remain visible and do not produce a ZIP;
  a failed slot can be regenerated as an on-demand report for the same dates. No failed slot is silently called ready.

## Try it through the UI

1. Start PostgreSQL if needed, then start the updated backend (stop the old backend with Ctrl+C first):

   ```powershell
   .\deployment\local-postgres.ps1 -Action Start
   .\.venv\Scripts\python -m aegis_demo.serve
   ```

   Startup adds tables/triggers without resetting bank balances, policies, identities or the audit ledger.
   The normal console uses its existing persistent evidence key. Never delete/replace keys for this feature.

2. Open `http://127.0.0.1:8000/ui/evidence`, switch to **Eva Visser**, and find
   **Compliance evidence & signed reports**. Choose dates, an agent/task (optional) and a framework.
3. Inspect coverage: **evidence present**, **partial evidence** and **no evidence** describe included records,
   not pass/fail regulatory verdicts. Empty approvals can simply mean no approval-requiring action occurred.
4. Click **Generate & download scoped report**. The report is saved before download. Inspect `report.html`,
   `control_coverage.json`, `report.json`, `records/`, `csv/`, `ledger_proofs.json` and `manifest.json`.
5. Verify with the fingerprint from `/v1/evidence/key`, recorded through a trusted channel:

   ```powershell
   .\.venv\Scripts\python -m aegis.control.evidence_verify .\aegis-evidence-rpt_example.zip --key '<fingerprint>'
   ```

   Or extract `verify_pack.py` and run it with Python plus `cryptography`. Unpinned verification proves
   self-consistency, not the signer's identity. The verifier still supports older full-chain V2 packs.
6. Select **Daily** or **Hourly**, then **Create schedule**. Fixed date inputs are intentionally not used for
   schedules: each report covers its scheduled rolling interval. The first interval runs on the next worker pass;
   **Run due schedules now** runs it immediately. Observe **Saved report history**, then pause/resume if needed.
   Creating a schedule delegates generation to a system worker; it does not retain your bearer token.
7. Inspect a saved report and record an auditor review. That review is an additional audit event linked to the
   artifact hash, not a claim embedded retroactively into an already signed ZIP. Scheduled reports do not pretend
   to have been human-reviewed. Refresh/restart: saved reports, schedules and next-run positions remain.

## API

All report/control/schedule APIs require the auditor role. Existing ledger/checkpoint role rules are unchanged.

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/evidence/summary?from=YYYY-MM-DD&to=YYYY-MM-DD&agent_id=…&root_id=…&framework=dora` | Preview selected records, coverage, signing key and worker readiness |
| `GET /v1/evidence/pack` | Compatible quick export, now scoped and saved in history |
| `GET /v1/evidence/controls` | Versioned control/query/source catalog |
| `POST /v1/evidence/reports` | Generate and persist; JSON fields `from`, `to`, `agent_id`, `root_id`, `framework` |
| `GET /v1/evidence/reports` | Saved metadata, without loading ZIP blobs |
| `GET /v1/evidence/reports/{id}/download` | Revalidate hash/signature/proofs before download |
| `POST /v1/evidence/reports/{id}/review` | Record one auditor review (`note`, minimum 10 characters) |
| `POST /v1/evidence/schedules` | `name`, `interval_hours` (1/24/168), and `scope` (no fixed dates) |
| `GET /v1/evidence/schedules` | Persistent schedule list |
| `PATCH /v1/evidence/schedules/{id}` | Set `enabled` true/false |
| `POST /v1/evidence/schedules/run` | Process due slots now, not future slots |

Settings: `AEGIS_EVIDENCE_AUTOMATION_ENABLED`, `AEGIS_EVIDENCE_CHECK_SECONDS`,
`AEGIS_EVIDENCE_CHECKPOINT_SECONDS`, and optional `AEGIS_EVIDENCE_KEY_PATH` (defaults beside the STS key).
Automatic schedules require a persistent database and key. None are seeded without an auditor creating them.
No email, Azure storage, paid inference or submission to a regulator occurs.

## Regulatory and security boundaries

The problem statement asks for generating evidence, not certifying compliance. The catalog is engineering
traceability that Compliance/Legal must validate, including applicability to each AI system and financial entity.
It deliberately calls out missing incident-classification/submission templates, complete processing registers,
organization-wide governance documentation, disclosure evidence and regulator-prescribed retention assurance.
An alert or approval record does not prove an entire statutory obligation is satisfied.

The signature uses a local PEM key, not an HSM, qualified certificate or externally trusted timestamp.
Reports contain **synthetic application evidence**; selected arguments/inputs can still be confidential.
Schedules are governed system reporting jobs, not unattended reuse of user credentials. Known development
persona departures/role removals stop their schedules; enterprise IAM entitlement revalidation remains part of
the enterprise identity integration. ZIP downloads remain auditor-only regardless of who created a schedule.
No automatic purge changes original audit retention, and no WORM/cloud deployment is claimed.

Official references: [EU AI Act](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689),
[DORA](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng),
[GDPR](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679),
[NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/),
[ISO/IEC 42001 overview](https://www.iso.org/standard/42001).
