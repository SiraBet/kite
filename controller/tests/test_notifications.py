import ssl
from unittest.mock import patch

import pytest

from app import notifications, audit
from app.settings_store import set_secret, set_setting


@pytest.fixture(autouse=True)
def _clean_notify_settings(db):
    """Every test below sets exactly the channel(s) it wants to test and
    nothing else -- since Setting rows aren't rolled back between tests
    in this suite (see other test files' notes on this), a channel a
    prior test configured would otherwise still be 'on' here too."""
    for name in ("notify_generic_webhook", "notify_slack_webhook", "notify_smtp_password"):
        set_secret(db, name, "")
    for key in ("notify_smtp_host", "notify_smtp_to", "notify_smtp_username", "notify_smtp_use_tls", "notify_smtp_verify_cert",
                "notify_on_success"):
        set_setting(db, key, "")
    yield


# ---------- notify_if_relevant dispatch ----------

def test_notify_skips_when_no_channel_configured(db):
    with patch("app.notifications.requests.post") as mock_post, \
         patch("app.notifications.smtplib.SMTP") as mock_smtp:
        notifications.notify_if_relevant(db, "stage_failed", "job 1 failed", "danger")
    mock_post.assert_not_called()
    mock_smtp.assert_not_called()


def test_notify_ignores_actions_outside_the_notify_set(db):
    set_secret(db, "notify_generic_webhook", "https://example.invalid/hook")
    with patch("app.notifications.requests.post") as mock_post:
        notifications.notify_if_relevant(db, "setting_changed", "require_ticket = false", "neutral")
    mock_post.assert_not_called()


def test_notify_generic_webhook_fires_for_always_notify_action(db):
    set_secret(db, "notify_generic_webhook", "https://example.invalid/hook")
    # example.invalid deliberately never resolves (RFC 2606) -- bypass the
    # real SSRF resolve-and-check (see test_webhook_url_is_blocked below
    # for that logic's own coverage) so this test exercises dispatch, not DNS.
    with patch("app.notifications._webhook_url_is_blocked", return_value=False), \
         patch("app.notifications.requests.post") as mock_post:
        notifications.notify_if_relevant(db, "stage_failed", "job 1 failed", "danger")
    assert mock_post.call_count == 1
    args, kwargs = mock_post.call_args
    assert args[0] == "https://example.invalid/hook"
    assert kwargs["json"]["action"] == "stage_failed"
    assert kwargs["timeout"] == notifications.WEBHOOK_TIMEOUT


def test_notify_generic_webhook_failure_is_swallowed(db):
    import requests
    set_secret(db, "notify_generic_webhook", "https://example.invalid/hook")
    with patch("app.notifications.requests.post", side_effect=requests.RequestException("boom")):
        notifications.notify_if_relevant(db, "stage_failed", "job 1 failed", "danger")  # must not raise


def test_notify_slack_webhook_fires_and_formats_message(db):
    set_secret(db, "notify_slack_webhook", "https://hooks.slack.example/services/x")
    with patch("app.notifications._webhook_url_is_blocked", return_value=False), \
         patch("app.notifications.requests.post") as mock_post:
        notifications.notify_if_relevant(db, "host_offline", "web-04 offline", "warning")
    assert mock_post.call_count == 1
    args, kwargs = mock_post.call_args
    assert args[0] == "https://hooks.slack.example/services/x"
    assert "host_offline" in kwargs["json"]["text"]
    assert "web-04 offline" in kwargs["json"]["text"]


def test_notify_run_completed_is_opt_in(db):
    set_secret(db, "notify_generic_webhook", "https://example.invalid/hook")
    with patch("app.notifications._webhook_url_is_blocked", return_value=False), \
         patch("app.notifications.requests.post") as mock_post:
        notifications.notify_if_relevant(db, "run_completed", "job 1 done", "success")
    mock_post.assert_not_called()

    set_setting(db, "notify_on_success", "true")
    with patch("app.notifications._webhook_url_is_blocked", return_value=False), \
         patch("app.notifications.requests.post") as mock_post:
        notifications.notify_if_relevant(db, "run_completed", "job 1 done", "success")
    mock_post.assert_called_once()


def test_notify_email_sends_via_smtp(db):
    set_setting(db, "notify_smtp_host", "smtp.example.invalid")
    set_setting(db, "notify_smtp_to", "ops@example.invalid")
    set_setting(db, "notify_smtp_username", "kite")
    set_secret(db, "notify_smtp_password", "smtp-pass")

    with patch("app.notifications.smtplib.SMTP") as mock_smtp_cls:
        mock_server = mock_smtp_cls.return_value.__enter__.return_value
        notifications.notify_if_relevant(db, "stage_stuck", "job 2 stuck on reboot", "warning")

    mock_server.starttls.assert_called_once()
    # The login must only go to a server that proved who it is.
    context = mock_server.starttls.call_args.kwargs["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    mock_server.login.assert_called_once_with("kite", "smtp-pass")
    assert mock_server.sendmail.call_count == 1
    args = mock_server.sendmail.call_args[0]
    assert args[1] == ["ops@example.invalid"]


def test_notify_email_skips_tls_when_disabled(db):
    set_setting(db, "notify_smtp_host", "smtp.example.invalid")
    set_setting(db, "notify_smtp_to", "ops@example.invalid")
    set_setting(db, "notify_smtp_use_tls", "false")

    with patch("app.notifications.smtplib.SMTP") as mock_smtp_cls:
        mock_server = mock_smtp_cls.return_value.__enter__.return_value
        notifications.notify_if_relevant(db, "stage_failed", "job 3 failed", "danger")

    mock_server.starttls.assert_not_called()


def test_notify_email_certificate_check_can_be_turned_off(db):
    """For a relay with a self-signed certificate: still encrypted, by explicit choice unverified."""
    set_setting(db, "notify_smtp_host", "smtp.example.invalid")
    set_setting(db, "notify_smtp_to", "ops@example.invalid")
    set_setting(db, "notify_smtp_verify_cert", "false")

    with patch("app.notifications.smtplib.SMTP") as mock_smtp_cls:
        mock_server = mock_smtp_cls.return_value.__enter__.return_value
        notifications.notify_if_relevant(db, "stage_failed", "job 5 failed", "danger")

    context = mock_server.starttls.call_args.kwargs["context"]
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_smtp_certificate_setting_only_takes_true_or_false(client, logged_in):
    logged_in(role="admin", username="smtp-cert-admin")
    assert client.put("/settings/notify_smtp_verify_cert", json={"value": "no"}).status_code == 400
    assert client.put("/settings/notify_smtp_verify_cert", json={"value": "false"}).status_code == 200


def test_notify_email_failure_is_swallowed(db):
    set_setting(db, "notify_smtp_host", "smtp.example.invalid")
    set_setting(db, "notify_smtp_to", "ops@example.invalid")
    with patch("app.notifications.smtplib.SMTP", side_effect=OSError("connection refused")):
        notifications.notify_if_relevant(db, "stage_failed", "job 4 failed", "danger")  # must not raise


# ---------- audit.log() actually triggers dispatch ----------

def test_audit_log_triggers_notification_for_relevant_action(db):
    set_secret(db, "notify_generic_webhook", "https://example.invalid/hook")
    with patch("app.notifications._webhook_url_is_blocked", return_value=False), \
         patch("app.notifications.requests.post") as mock_post:
        audit.log(db, actor="system", role="controller", action="stage_failed", detail="job X failed", tone="danger")
    mock_post.assert_called_once()


def test_audit_log_does_not_notify_for_irrelevant_action(db):
    set_secret(db, "notify_generic_webhook", "https://example.invalid/hook")
    with patch("app.notifications.requests.post") as mock_post:
        audit.log(db, actor="admin", role="admin", action="user_created", detail="bob (operator)")
    mock_post.assert_not_called()


# ---------- _webhook_url_is_blocked (SSRF guard) ----------

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",  # cloud instance metadata
    "http://127.0.0.1:8000/internal",
    "http://localhost/x",
    "http://[::1]/x",
    "http://[::ffff:169.254.169.254]/x",          # IPv4-mapped IPv6 metadata trick
    "not-a-url",
    "http://this-does-not-resolve.invalid/x",
])
def test_webhook_url_is_blocked_for_unsafe_targets(url):
    assert notifications._webhook_url_is_blocked(url) is True


@pytest.mark.parametrize("url", [
    "http://10.0.0.5:9000/webhook",   # RFC1918 -- deliberately allowed, see
    "http://192.168.1.50/hook",       # _webhook_url_is_blocked's docstring:
    "http://93.184.216.34/hook",      # kite's own deployment model is "on a private network"
])
def test_webhook_url_is_blocked_allows_private_and_public_targets(url):
    assert notifications._webhook_url_is_blocked(url) is False
