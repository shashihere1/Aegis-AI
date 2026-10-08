"""Runtime configuration from local defaults, repository dotenv files and process environment."""

import json
import os
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

    policy_engine: str = "python"  # "python" (in-process) or "opa" (OPA sidecar REST API)
    opa_url: str = "http://localhost:8181"
    policy_dir: str = str(REPO_ROOT / "config" / "policies")

    hotstore_url: str = ""  # "redis://..." for Valkey; empty -> in-memory (single process only)

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
