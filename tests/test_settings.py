"""Offline configuration coverage; no real environment files, keys, database or Azure calls."""

import json
import os

import pytest

from aegis.common import settings as settings_module
from aegis.common.settings import AZURE_ENV_ALIASES, Settings


@pytest.fixture
def settings_repo(monkeypatch, tmp_path):
    monkeypatch.setattr(settings_module, "REPO_ROOT", tmp_path)
    for name in Settings.model_fields:
        monkeypatch.delenv(f"AEGIS_{name.upper()}", raising=False)
    for name in AZURE_ENV_ALIASES.values():
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def test_missing_dotenv_files_keep_defaults(settings_repo):
    assert Settings.from_env().azure_openai_api_key == ""


def test_dotenv_reads_quotes_bom_and_literal_key_without_changing_environment(settings_repo):
    fake_key = "offline-${UNCHANGED}-key#literal"
    (settings_repo / ".env").write_text(
        f'AEGIS_AZURE_OPENAI_API_KEY="{fake_key}"\n'
        "AEGIS_AZURE_OPENAI_DEPLOYMENT='aegis-chat' # a comment\n"
        "UNRELATED_SETTING=ignored\n",
        encoding="utf-8-sig",
    )
    loaded = Settings.from_env()
    assert loaded.azure_openai_api_key == fake_key
    assert loaded.azure_openai_deployment == "aegis-chat"
    assert "AEGIS_AZURE_OPENAI_API_KEY" not in os.environ
    assert "UNRELATED_SETTING" not in os.environ
    assert fake_key not in repr(loaded)


def test_azure_only_dotenv_preserves_local_postgres_config(settings_repo):
    local = settings_repo / ".local"
    local.mkdir()
    database_url = "postgresql+asyncpg://offline:fixture@localhost:55432/aegis"
    (local / "connection.json").write_text(json.dumps({"database_url": database_url}), encoding="utf-8")
    (settings_repo / ".env").write_text("AEGIS_AZURE_OPENAI_API_KEY=offline-key\n", encoding="utf-8")
    loaded = Settings.from_env()
    assert loaded.database_url == database_url
    assert loaded.azure_openai_api_key == "offline-key"


def test_dotenv_local_overrides_dotenv_and_process_environment_wins(settings_repo, monkeypatch):
    (settings_repo / ".env").write_text("AEGIS_AZURE_OPENAI_API_KEY=dotenv-key\n", encoding="utf-8")
    (settings_repo / ".env.local").write_text("AEGIS_AZURE_OPENAI_API_KEY=local-key\n", encoding="utf-8")
    assert Settings.from_env().azure_openai_api_key == "local-key"
    monkeypatch.setenv("AEGIS_AZURE_OPENAI_API_KEY", "process-key")
    assert Settings.from_env().azure_openai_api_key == "process-key"


def test_azure_aliases_are_supported_and_aegis_name_wins_within_one_source(settings_repo, monkeypatch):
    (settings_repo / ".env").write_text(
        "AZURE_OPENAI_API_KEY=alias-key\n"
        "AZURE_OPENAI_ENDPOINT=https://offline.openai.azure.com\n"
        "AZURE_OPENAI_DEPLOYMENT=offline-deployment\n"
        "AZURE_OPENAI_API_VERSION=2025-01-01-preview\n",
        encoding="utf-8",
    )
    loaded = Settings.from_env()
    assert loaded.azure_openai_api_key == "alias-key"
    assert loaded.azure_openai_endpoint == "https://offline.openai.azure.com"
    assert loaded.azure_openai_deployment == "offline-deployment"
    assert loaded.azure_openai_api_version == "2025-01-01-preview"
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "process-alias-key")
    monkeypatch.setenv("AEGIS_AZURE_OPENAI_API_KEY", "process-aegis-key")
    assert Settings.from_env().azure_openai_api_key == "process-aegis-key"


def test_process_alias_overrides_aegis_name_from_file(settings_repo, monkeypatch):
    (settings_repo / ".env").write_text("AEGIS_AZURE_OPENAI_API_KEY=file-key\n", encoding="utf-8")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "process-alias-key")
    assert Settings.from_env().azure_openai_api_key == "process-alias-key"


def test_explicit_empty_key_does_not_fall_back_to_file_or_alias(settings_repo, monkeypatch):
    (settings_repo / ".env").write_text("AEGIS_AZURE_OPENAI_API_KEY=file-key\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_AZURE_OPENAI_API_KEY", "")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "process-alias-key")
    assert Settings.from_env().azure_openai_api_key == ""


def test_unassigned_key_does_not_replace_lower_priority_value(settings_repo):
    (settings_repo / ".env").write_text("AEGIS_AZURE_OPENAI_API_KEY=file-key\n", encoding="utf-8")
    (settings_repo / ".env.local").write_text("AEGIS_AZURE_OPENAI_API_KEY\n", encoding="utf-8")
    assert Settings.from_env().azure_openai_api_key == "file-key"


def test_does_not_load_dotenv_from_current_working_directory(settings_repo, monkeypatch):
    unrelated = settings_repo / "unrelated"
    unrelated.mkdir()
    (unrelated / ".env").write_text("AEGIS_AZURE_OPENAI_API_KEY=wrong-directory-key\n", encoding="utf-8")
    monkeypatch.chdir(unrelated)
    assert Settings.from_env().azure_openai_api_key == ""
