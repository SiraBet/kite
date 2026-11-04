"""
_read_credential() reads os.environ fresh on every call (it's not
cached at import time the way the Settings dataclass fields are), so it
can be tested directly with monkeypatch without needing to reimport the
whole app under a different environment.
"""
from app.config import _read_credential


def test_no_credentials_directory_returns_empty(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    assert _read_credential("enroll_secret") == ""


def test_missing_specific_credential_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert _read_credential("enroll_secret") == ""


def test_present_credential_is_read_and_stripped(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    (tmp_path / "enroll_secret").write_text("shhh-its-a-secret\n")
    assert _read_credential("enroll_secret") == "shhh-its-a-secret"


# ---------------------------------------------------------------------
# Persisted auto-generated secrets.
#
# STATE_DIR is resolved once at import time, so these drive the resolver
# functions with a patched STATE_DIR rather than reimporting the module
# — same approach as _read_credential above, for the same reason.
# ---------------------------------------------------------------------
import stat  # noqa: E402

from app import config  # noqa: E402


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATE_DIR", tmp_path)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.delenv("KITE_ENROLL_SECRET", raising=False)
    monkeypatch.delenv("KITE_SECRET_KEY", raising=False)


def test_generated_secrets_are_reused_on_the_next_start(monkeypatch, tmp_path):
    """
    The whole point: these used to be regenerated every start, which made
    a saved Proxmox token undecryptable after any restart.
    """
    _isolate(monkeypatch, tmp_path)

    enroll_first, new_first, persisted = config._resolve_enroll_secret()
    key_first, key_new, key_persisted = config._resolve_secret_key()
    assert (new_first, persisted) == (True, True)
    assert (key_new, key_persisted) == (True, True)

    enroll_again, new_again, _ = config._resolve_enroll_secret()
    key_again, key_new_again, _ = config._resolve_secret_key()

    assert enroll_again == enroll_first
    assert key_again == key_first
    # Not reported as newly generated the second time — that flag is what
    # decides whether the startup banner shouts about it.
    assert new_again is False and key_new_again is False


def test_persisted_secrets_are_owner_readable_only(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    config._resolve_secret_key()
    mode = stat.S_IMODE((tmp_path / "secret_key").stat().st_mode)
    assert mode == 0o600, oct(mode)


def test_an_explicitly_configured_secret_still_wins(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    config._persist("enroll_secret", "persisted-value")
    monkeypatch.setenv("KITE_ENROLL_SECRET", "pinned-value")

    value, newly_generated, _ = config._resolve_enroll_secret()

    assert value == "pinned-value"
    assert newly_generated is False


def test_an_unwritable_state_dir_still_boots(monkeypatch, tmp_path):
    """
    Falling back to a per-process secret is worse, but refusing to start
    is worse still — the caller says so in the startup banner.
    """
    _isolate(monkeypatch, tmp_path / "does" / "not" / "exist")
    monkeypatch.setattr(config.Path, "mkdir", _raise_oserror)

    value, newly_generated, persisted = config._resolve_enroll_secret()

    assert value and newly_generated is True
    assert persisted is False


def _raise_oserror(*args, **kwargs):
    raise OSError("read-only filesystem")


def test_persist_reports_failure_rather_than_raising(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(config.Path, "mkdir", _raise_oserror)
    assert config._persist("enroll_secret", "x") is False


def test_generated_tokens_never_start_with_a_hyphen():
    """
    Every generated secret reaches a command line somewhere
    (`enroll.py --secret <value>`, the Fleet page's install one-liner,
    the .env line the startup banner says to paste). `token_urlsafe`
    starts a token with '-' roughly 1 in 32 times, and argparse then
    reads it as the next flag: "argument --secret: expected one
    argument", with nothing explaining why that install failed.

    Found by drawing one for real during a container enrollment.
    """
    from app import security

    for _ in range(2000):
        for token in (security.cli_safe_token(24), security.generate_secret(),
                      security.generate_enrollment_token(), security.generate_session_token()):
            assert not token.startswith("-"), token


def test_cli_safe_token_still_has_full_length_and_variety():
    """Rejecting bad draws must not have turned into truncating them."""
    from app import security

    tokens = {security.cli_safe_token(24) for _ in range(200)}
    assert len(tokens) == 200                      # no collisions, still random
    assert all(len(t) >= 30 for t in tokens)       # 24 bytes -> 32 urlsafe chars
