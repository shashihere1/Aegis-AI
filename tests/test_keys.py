"""Increment 1: persistent signing-key hardening (explicit creation, strict fail-closed startup)."""

import pytest

from aegis import keys
from aegis.common.crypto import SigningKey, SigningKeyError
from aegis.common.settings import Settings


def test_empty_path_is_ephemeral_and_changes_each_start():
    first = SigningKey.ensure("", "sts-1")
    second = SigningKey.ensure("", "sts-1")
    assert first.fingerprint != second.fingerprint  # no path -> a new identity every start


def test_create_then_strict_load_preserves_identity(tmp_path):
    path = str(tmp_path / "sts.pem")
    created = SigningKey.ensure(path, "sts-1", create=True)  # explicit provisioning
    reloaded = SigningKey.ensure(path, "sts-1")  # normal startup, strict load (create defaults False)
    assert reloaded.fingerprint == created.fingerprint
    assert reloaded.public_pem == created.public_pem


def test_missing_key_fails_closed_on_startup(tmp_path):
    with pytest.raises(SigningKeyError, match="missing"):
        SigningKey.ensure(str(tmp_path / "absent.pem"), "sts-1")


def test_deleting_a_required_key_is_a_clear_failure_not_a_new_identity(tmp_path):
    path = str(tmp_path / "sts.pem")
    original = SigningKey.ensure(path, "sts-1", create=True)
    (tmp_path / "sts.pem").unlink()
    with pytest.raises(SigningKeyError):
        SigningKey.ensure(path, "sts-1")  # must not silently mint a different signing identity
    # and re-provisioning makes a genuinely new key (proving the old one was not resurrected)
    replacement = SigningKey.ensure(path, "sts-1", create=True)
    assert replacement.fingerprint != original.fingerprint


def test_create_file_is_atomic_and_idempotent(tmp_path):
    path = str(tmp_path / "sts.pem")
    first = SigningKey.create_file(path, "sts-1")
    second = SigningKey.create_file(path, "sts-1")  # loses the race -> loads the same key
    assert first.fingerprint == second.fingerprint


def test_malformed_key_is_rejected(tmp_path):
    bad = tmp_path / "sts.pem"
    bad.write_text("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    with pytest.raises(SigningKeyError):
        SigningKey.load_file(str(bad), "sts-1")


def test_private_key_never_appears_in_repr(tmp_path):
    key = SigningKey.ensure(str(tmp_path / "sts.pem"), "sts-1", create=True)
    text = repr(key)
    assert "PRIVATE KEY" not in text and key.private_pem not in text
    assert key.fingerprint in text


def test_fingerprint_is_distinct_from_the_kid_label(tmp_path):
    key = SigningKey.ensure(str(tmp_path / "sts.pem"), "sts-1", create=True)
    assert key.kid == "sts-1"  # stable human label used in JWKS and token headers
    assert key.fingerprint != key.kid  # content-derived thumbprint


def test_provision_creates_then_restart_loads_identical_fingerprints(tmp_path):
    settings = Settings(
        signing_key_path=str(tmp_path / "sts.pem"),
        idp_key_path=str(tmp_path / "idp.pem"),
        identity_state_dir=str(tmp_path / "identities"),
    )
    created = keys.provision(settings, create=True)  # `python -m aegis.keys init`
    loaded = keys.provision(settings, create=False)  # a later restart
    assert created["sts"]["fingerprint"] == loaded["sts"]["fingerprint"]
    assert created["idp"]["fingerprint"] == loaded["idp"]["fingerprint"]
    assert (tmp_path / "identities").is_dir()
    for info in loaded.values():  # report carries public info only
        assert "PRIVATE" not in str(info)


def test_provision_fails_closed_when_a_key_is_lost(tmp_path):
    settings = Settings(signing_key_path=str(tmp_path / "sts.pem"))
    keys.provision(settings, create=True)
    (tmp_path / "sts.pem").unlink()
    with pytest.raises(SigningKeyError):
        keys.provision(settings, create=False)


def test_keys_cli_init_then_show(tmp_path, capsys, monkeypatch):
    sts, idp = tmp_path / "sts.pem", tmp_path / "idp.pem"
    monkeypatch.setenv("AEGIS_SIGNING_KEY_PATH", str(sts))
    monkeypatch.setenv("AEGIS_IDP_KEY_PATH", str(idp))

    assert keys.main(["init"]) == 0
    init_out = capsys.readouterr().out
    assert sts.exists() and idp.exists()
    assert "fingerprint=" in init_out and "PRIVATE" not in init_out

    assert keys.main(["show"]) == 0  # strict load succeeds after init
    assert "fingerprint=" in capsys.readouterr().out


def test_keys_cli_show_without_keys_exits_nonzero(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("AEGIS_SIGNING_KEY_PATH", str(tmp_path / "missing.pem"))
    monkeypatch.setenv("AEGIS_IDP_KEY_PATH", "")
    assert keys.main(["show"]) == 2  # fails closed with a clear message on stderr
    assert "error:" in capsys.readouterr().err
