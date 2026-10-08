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
