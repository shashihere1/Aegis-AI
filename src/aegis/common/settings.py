"""Runtime configuration, read from environment variables (see .env.example)."""

import json
import os
from pathlib import Path

from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseModel):
    # Public base URLs. In local single-process mode these are virtual hosts routed in-process.
    control_url: str = "http://control.aegis"
    gateway_url: str = "http://gateway.aegis"

    database_url: str = Field(default="sqlite+aiosqlite:///./aegis.db", repr=False)
    database_schema: str = ""  # optional isolated PostgreSQL namespace (also used by integration tests)
    # PEM file for the STS signing key. Empty -> an ephemeral key is generated at start-up (dev only).
    signing_key_path: str = ""
    idp_key_path: str = ""
    identity_state_dir: str = ""  # local development identities; never a production secret store

    policy_engine: str = "python"  # "python" (in-process) or "opa" (OPA sidecar REST API)
    opa_url: str = "http://localhost:8181"
    policy_dir: str = str(REPO_ROOT / "config" / "policies")

    hotstore_url: str = ""  # "redis://..." for Valkey; empty -> in-memory (single process only)

    # --- Sign-in for people (agents always authenticate with private_key_jwt through the IdP) ---
    # The persona switcher (POST /idp/login) has no passwords. Turn it off everywhere except demos.
    enable_dev_login: bool = True
    # Standard OpenID Connect provider: Keycloak, Microsoft Entra ID, Okta, Auth0 ... Empty issuer = no SSO.
    oidc_issuer: str = ""  # e.g. https://login.microsoftonline.com/<tenant>/v2.0 or http://host:8080/realms/aegis
    oidc_client_id: str = ""  # the console's public (PKCE) client; also the default expected audience
    oidc_audience: str = ""  # expected `aud` in the bearer token, if different from the client id
    oidc_jwks_url: str = ""  # override the discovered jwks_uri (rarely needed)
    oidc_algorithms: str = "RS256,ES256"
    oidc_username_claim: str = "preferred_username"
    oidc_name_claim: str = "name"
    oidc_roles_claim: str = "roles"  # dotted path: Keycloak realm roles are "realm_access.roles"
    oidc_entitlements_claim: str = "entitlements"
    # JSON object mapping provider roles/groups to Aegis roles, e.g. {"Aegis.Approver": "risk-approver"}.
    # Empty = provider roles are used as Aegis roles unchanged. Non-empty = only mapped roles are granted.
    oidc_role_map: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_clock_skew: int = 60
    # Comma-separated callback URLs the console may use (built-in provider only; real providers hold their own).
    oidc_redirect_uris: str = (
        "http://127.0.0.1:8000/ui/auth/callback,http://localhost:8000/ui/auth/callback,"
        "http://127.0.0.1:5173/ui/auth/callback,http://localhost:5173/ui/auth/callback"
    )
    # A small standards-compliant OIDC provider (authorization code + PKCE) at /oidc so SSO can be shown on a laptop
    # with nothing installed. Demo only: one shared password, ephemeral keys.
    builtin_oidc: bool = False
    builtin_oidc_password: str = Field(default="", repr=False)

    mandate_default_ttl: int = 300
    max_delegation_depth: int = 3
    approval_ttl: int = 900
    approval_hold_seconds: float = 0.0  # how long the gateway holds a call waiting for approval
    auto_suspend_on_critical: bool = True

    # Shared secret for gateway -> control-plane internal calls (Key Vault reference in Azure).
    internal_token: str = Field(default="dev-internal-token", repr=False)

    # Gateway caches (seconds). 0 disables caching, which tests use for determinism.
    cache_seconds: float = 2.0

    # Any OpenAI-compatible upstream (used by tests); when empty the Azure OpenAI settings are used.
    llm_upstream_url: str = ""
    # Indicative price per 1,000 tokens (EUR); set to the approved deployment's actual rates.
    llm_price_in_per_1k: float = 0.0025
    llm_price_out_per_1k: float = 0.01

    # OneStop-approved Azure OpenAI deployment used by the LLM proxy.
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = Field(default="", repr=False)
    azure_openai_deployment: str = ""
    azure_openai_api_version: str = "2024-10-21"

    @classmethod
    def from_env(cls) -> Settings:
        values = {}
        local = REPO_ROOT / ".local" / "connection.json"
        if local.exists():
            values.update(json.loads(local.read_text(encoding="utf-8-sig")))
        for name in cls.model_fields:
            env = os.environ.get(f"AEGIS_{name.upper()}")
            if env is not None:
                values[name] = env
        return cls(**values)
