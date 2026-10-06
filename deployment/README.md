# Deployment

**Today:** the whole system runs in one process with no external services
(`python -m aegis_demo.serve`, see the root README). This is also the fallback for demo day.

**Next increment (plan §16):** Azure Container Apps in the team's Makeathon sandbox — control plane, Gateway with
an OPA sidecar, PostgreSQL Flexible Server, a Valkey container, Key Vault for signing keys, and the
OneStop-approved Azure OpenAI deployment. Images are built through the approved Artifactory route.
Bicep / `azd` templates will live in `deployment/azure/`.
