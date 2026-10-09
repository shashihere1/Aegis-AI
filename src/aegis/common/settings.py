"""Runtime configuration from local defaults, repository dotenv files and process environment."""

import json
import os
import secrets
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parents[3]
AZURE_ENV_ALIASES = {
    "azure_openai_endpoint": "AZURE_OPENAI_ENDPOINT",
    "azure_openai_api_key": "AZURE_OPENAI_API_KEY",
    "azure_openai_deployment": "AZURE_OPENAI_DEPLOYMENT",
    "azure_openai_api_version": "AZURE_OPENAI_API_VERSION",
}


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

    # python: in-process mirror of the Rego. rego: the Rego itself, in-process via regopy (no binary needed).
    # opa: the Rego in an OPA server (AEGIS_OPA_URL); Aegis checks the server runs exactly the approved Rego.
    policy_engine: Literal["python", "rego", "opa"] = "python"
    opa_url: str = "http://localhost:8181"
    opa_timeout_seconds: float = Field(default=2.0, gt=0, le=30)  # whole request; a slow OPA fails closed
    opa_token: str = Field(default="", repr=False)  # bearer token for an authenticating proxy in front of OPA
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
    # Separation of duties by identity: refuse any login that holds more than one Aegis role. A person who acts in
    # several roles uses a separate account for each (see keycloak_setup `accounts`).
    oidc_one_role_per_account: bool = False
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

    # --- Where agents get their identity ---
    # "dev": the built-in demo identity provider. "keycloak": every approved agent becomes its own Keycloak client
    # that signs in with a private key (private_key_jwt); Aegis manages it through a least-privilege admin client.
    agent_idp: Literal["dev", "keycloak"] = "dev"
    keycloak_url: str = ""  # base URL, e.g. http://127.0.0.1:8080 (the realm's public URL is {url}/realms/{realm})
    keycloak_realm: str = "aegis"
    keycloak_admin_client_id: str = "aegis-control-plane"  # service account holding manage-clients / view-clients
    keycloak_admin_client_secret: str = Field(default="", repr=False)  # Key Vault reference in Azure
    agent_token_ttl: int = 300  # seconds an agent's identity token lives (Keycloak enforces it per client)

    mandate_default_ttl: int = 300
    max_delegation_depth: int = 3
    approval_ttl: int = 900
    approval_hold_seconds: float = 0.0  # how long the gateway holds a call waiting for approval
    auto_suspend_on_critical: bool = True

    # One-process demo shares this random capability. Separate services must configure a protected shared value.
    investigation_token: str = Field(default_factory=lambda: secrets.token_urlsafe(32), repr=False, min_length=32)

    # Gateway → control-plane service identity (asymmetric; no shared secret).
    # The Gateway signs each internal call with its private ES256 key; the control plane verifies with
    # the public half only, so it cannot forge Gateway tokens. Private key in Key Vault in Azure.
    # Both empty in local single-process mode: an ephemeral key pair is generated and wired in-process.
    gateway_service_key_path: str = ""  # Gateway side: the private signing key (PEM).
    gateway_service_public_key_path: str = ""  # Control side: the Gateway's public key (PEM) to verify.

    # CORS: comma-separated origins the browser console is served from.
    # In production set this to the exact frontend URL (no trailing slash, no wildcards).
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000"

    # TLS: paths to a PEM certificate and private key for direct uvicorn TLS termination.
    # Leave empty when TLS is handled by a reverse proxy or Azure Container Apps ingress (recommended).
    tls_cert_file: str = ""
    tls_key_file: str = ""

    # Gateway caches (seconds). 0 disables caching, which tests use for determinism.
    cache_seconds: float = 2.0

    # Any OpenAI-compatible upstream (used by tests); when empty the Azure OpenAI settings are used.
    llm_upstream_url: str = ""
    # Indicative price per 1,000 tokens (EUR); set to the approved deployment's actual rates.
    llm_price_in_per_1k: float = Field(default=0.0025, gt=0, allow_inf_nan=False)
    llm_price_out_per_1k: float = Field(default=0.01, gt=0, allow_inf_nan=False)
    llm_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    llm_max_output_tokens: int = Field(default=1024, ge=1, le=8192)
    llm_max_request_chars: int = Field(default=16000, ge=1000, le=100000)

    # OneStop-approved Azure OpenAI deployment used by the LLM proxy.
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = Field(default="", repr=False)
    azure_openai_deployment: str = ""
    azure_openai_api_version: str = "2024-10-21"

    # Declared processing footprint, NOT inferred from the resource's region. Unknown fails closed.
    llm_processing_scope: Literal["unknown", "global", "eu", "us"] = "unknown"
    llm_allowed_processing_scope: Literal["global", "eu", "us"] = "eu"
    llm_max_data_class: Literal["public", "internal", "confidential", "restricted"] = "confidential"
    llm_daily_budget_eur: float = Field(default=1.0, gt=0, le=100, allow_inf_nan=False)
    # Trusted resource ownership directory. The local bank supplies synthetic fixture ownership.
    resource_owners: dict[str, dict[str, str]] = Field(default_factory=dict)

    @classmethod
    def from_env(cls) -> Settings:
        """Precedence: defaults < connection.json < .env < .env.local < process environment.

        Only files at REPO_ROOT are read; never search parent/home directories or execute their contents.
        Parsing does not change os.environ, and interpolation is off so secrets are read literally.
        AEGIS_* names win over Azure aliases within the same source, including explicit empty values.
        """
        values = {}
        local = REPO_ROOT / ".local" / "connection.json"
        if local.exists():
            values.update(json.loads(local.read_text(encoding="utf-8-sig")))
        sources = []
        for filename in (".env", ".env.local"):
            env_file = REPO_ROOT / filename
            if env_file.is_file():
                sources.append(dotenv_values(env_file, encoding="utf-8-sig", interpolate=False))
        sources.append(os.environ)
        for source in sources:
            for name in cls.model_fields:
                value = source.get(f"AEGIS_{name.upper()}")
                if value is None and name in AZURE_ENV_ALIASES:
                    value = source.get(AZURE_ENV_ALIASES[name])
                if value is not None:
                    values[name] = json.loads(value) if name == "resource_owners" else value
        return cls(**values)
