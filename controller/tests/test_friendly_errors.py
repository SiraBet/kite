"""
app/friendly_errors.py: what the console says when Proxmox or a
vulnerability source fails -- a plain sentence and the next step, never
the raw exception.
"""
from unittest.mock import patch

import pytest
import requests
from urllib3.exceptions import ConnectTimeoutError, MaxRetryError, NewConnectionError

from app import friendly_errors, proxmox, proxmox_inventory
from app.friendly_errors import describe

RAW_MARKERS = ("HTTPSConnectionPool", "Max retries", "object at 0x", "Caused by", "urllib3")


def _timeout():
    """The exception requests raises when a host doesn't answer: the one behind the original complaint."""
    return requests.exceptions.ConnectTimeout(MaxRetryError(
        None, "/api2/json/cluster/resources",
        ConnectTimeoutError(None, "Connection to 10.0.0.5 timed out. (connect timeout=15)")))


def _refused():
    return requests.exceptions.ConnectionError(MaxRetryError(
        None, "/api2/json/version",
        NewConnectionError(None, "Failed to establish a new connection: [Errno 111] Connection refused")))


@pytest.mark.parametrize("exc, says", [
    (_timeout(), "didn't answer in time"),
    (_refused(), "refused the connection"),
    (requests.exceptions.ConnectionError("Failed to resolve 'pve.lab' ([Errno -2] Name or service not known)"),
     "Couldn't find"),
    (requests.exceptions.SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"), "isn't trusted"),
    (proxmox.ProxmoxError('Proxmox cluster resources failed (401): {"data":null}'), "didn't accept the credentials"),
    (proxmox.ProxmoxError('Proxmox snapshot failed (403): {"data":null,"message":"Permission check failed"}'),
     "not allowed). Check the API token and its permissions"),
    (proxmox.ProxmoxError("Proxmox snapshot failed (500): internal"), "internal error (HTTP 500)"),
    (OSError("[Errno 113] No route to host"), "no network route"),
])
def test_failures_read_as_a_sentence_with_a_next_step(exc, says):
    text = describe(exc)
    assert says in text
    assert not any(m in text for m in RAW_MARKERS), text
    assert "10.0.0.5" not in text and "{" not in text


def test_our_own_messages_are_kept():
    msg = "Proxmox API token not configured — set it in Settings → Connections"
    assert describe(proxmox.ProxmoxError(msg)) == msg
    assert describe(proxmox.ProxmoxTaskFailed("Proxmox task failed: storage full")) == "Proxmox task failed: storage full"


def test_an_online_service_gets_internet_advice():
    text = describe(_timeout(), "NVD", reach_hint=friendly_errors.INTERNET)
    assert text == "NVD didn't answer in time. Check the controller can reach the internet (firewall, proxy)."


def test_anything_else_points_at_the_log():
    assert "log has the details" in describe(ValueError("<Response [200]> object at 0x7f00 not JSON"))


def test_the_detail_goes_to_the_log(caplog):
    with caplog.at_level("WARNING"):
        text = friendly_errors.report(_timeout(), context="proxmox inventory pve.lab")
    assert "didn't answer" in text
    assert "timed out" in caplog.text and "pve.lab" in caplog.text


def test_coverage_shows_the_sentence_not_the_exception(client, logged_in, db):
    """Settings → Connections / Coverage: an unreachable Proxmox."""
    from app.settings_store import set_secret, set_setting
    set_setting(db, "rollback_proxmox_host", "10.0.0.5")
    set_setting(db, "rollback_proxmox_node", "pve")
    set_setting(db, "rollback_proxmox_token_id", "kite@pve!t")
    set_secret(db, "rollback_proxmox_token_secret", "s")
    proxmox_inventory.clear_cache()
    try:
        logged_in("operator")
        with patch("app.proxmox.list_cluster_resources", side_effect=_timeout()):
            pm = client.get("/proxmox/coverage").json()["proxmox"]
        assert pm["error"].startswith("Proxmox didn't answer in time")
        assert not any(m in pm["error"] for m in RAW_MARKERS)
    finally:
        from app import models
        db.query(models.Setting).filter(models.Setting.key.in_((
            "rollback_proxmox_host", "rollback_proxmox_node", "rollback_proxmox_token_id",
            "rollback_proxmox_token_secret"))).delete(synchronize_session=False)
        db.commit()
        proxmox_inventory.clear_cache()
