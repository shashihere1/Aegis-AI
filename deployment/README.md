# Deployment

**Today:** the APIs and demo agents run in one application process backed by a real, project-local PostgreSQL
cluster. No cloud account or Docker is needed; installed PostgreSQL binaries are required.

From the repository root in PowerShell:

```powershell
.\deployment\local-postgres.ps1 -Action Start
.\.venv\Scripts\python -m aegis_demo.serve
```

Open `http://127.0.0.1:8000/ui/`. PostgreSQL listens only on `127.0.0.1:55432`, using database `aegis`
and a non-superuser application role. This does not alter or stop any PostgreSQL service using port 5432.
The script defaults to `C:\Program Files\PostgreSQL\18\bin`; use `-BinaryDirectory` when different.
If PowerShell blocks the script, follow your organization's approved script-execution process; do not bypass controls.

`-Action Status` reports the project cluster. `-Action Stop` stops only this cluster, preserving its data.
Stop the Aegis application before stopping the database. All local state is under `.local/`, restricted to the
Windows user and SYSTEM and excluded from Git. Administrative/app credentials and the internal token are also
saved using Windows user-bound encryption; the runtime connection file contains their plaintext values inside
that protected folder. Never copy credentials into README files, command arguments, logs or Git.

Registry entries, decisions, approvals, policies, investigations, risk snapshots and spans persist. Synthetic
bank effects, Studio run logs and the hot store do not. Old task permissions/pending approvals are revoked or
cancelled at restart when volatile security state is lost. This is a local single-process deployment, not HA or
a production secret store. Database-owner privileges can bypass database triggers; the ledger is not externally anchored.

Explicit disposable mode: `python -m aegis_demo.serve --ephemeral`. This uses in-memory SQLite and is not the
default persistence path. The Azure deployment below is still planned, not implemented.

**Next increment (plan §16):** Azure Container Apps in the team's Makeathon sandbox — control plane, Gateway with
an OPA sidecar (start it with the same Rego; Aegis checks the loaded modules match the approved Rego), PostgreSQL Flexible Server, a Valkey container, Key Vault for signing keys, and the
OneStop-approved Azure OpenAI deployment. Images are built through the approved Artifactory route.
Bicep / `azd` templates will live in `deployment/azure/`.
