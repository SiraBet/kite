"""
POST /settings/proxmox-test: try a Proxmox connection before saving it.
Proxmox itself is mocked at the two client calls; what's under test is
the fallback to saved values, the reporting, and the error wording.
"""
from unittest.mock import patch

import pytest
import requests

from app import crypto, models

from app.proxmox import ProxmoxConfig, ProxmoxError

_SAVED = ProxmoxConfig(host="saved.lab", node="", token_id="kite@pve!saved", token_secret="saved-secret")
_ROWS = [{"type": "node", "node": "pve1"}, {"type": "node", "node": "pve2"},
         {"type": "qemu", "vmid": 100}, {"type": "lxc", "vmid": 101}, {"type": "qemu", "vmid": 9000, "template": 1}]


def _post(client, **body):
    return client.post("/settings/proxmox-test", json=body)


@pytest.fixture
def saved(db):
    """A saved connection whose values blank form fields fall back to; its id."""
    row = models.ProxmoxConnection(name="saved", host=_SAVED.host, token_id=_SAVED.token_id,
                                   token_secret_enc=crypto.encrypt(_SAVED.token_secret))
    db.add(row)
    db.commit()
    return row.id


def test_admin_only(client, logged_in):
    logged_in("lead")
    assert _post(client).status_code == 403


def test_reports_nodes_guests_and_which_uses_are_covered(client, logged_in, saved):
    logged_in("admin")
    with patch("app.proxmox.list_cluster_resources", return_value=_ROWS), \
         patch("app.proxmox.token_privileges", return_value={"VM.Audit", "Sys.Audit"}):
        data = _post(client, connection_id=saved).json()
    assert data["ok"] is True
    assert data["nodes"] == 2 and data["guests"] == 2  # templates aren't guests
    granted = {u["privilege"]: u["granted"] for u in data["uses"]}
    assert granted == {"VM.Audit": True, "Sys.Audit": True, "SDN.Audit": False, "VM.Snapshot": False, "VM.PowerMgmt": False}


def test_form_values_override_saved_and_blanks_fall_back(client, logged_in, saved):
    logged_in("admin")
    seen = {}
    def fake(cfg):
        seen.update(host=cfg.host, token_id=cfg.token_id, token_secret=cfg.token_secret, verify=cfg.verify_ssl)
        return _ROWS
    with patch("app.proxmox.list_cluster_resources", side_effect=fake), \
         patch("app.proxmox.token_privileges", return_value=set()):
        _post(client, connection_id=saved, host="new.lab", token_id="", token_secret="", verify_ssl=True)
    assert seen == {"host": "new.lab", "token_id": "kite@pve!saved", "token_secret": "saved-secret", "verify": True}


def test_missing_values_are_named(client, logged_in):
    logged_in("admin")
    data = _post(client, host="pve.lab").json()   # a new connection: nothing saved to fall back to
    assert data == {"ok": False, "error": "Missing token ID, token secret"}


def test_proxmox_errors_are_reported_not_raised(client, logged_in, saved):
    logged_in("admin")
    with patch("app.proxmox.list_cluster_resources", side_effect=ProxmoxError("401 Unauthorized")):
        assert _post(client, connection_id=saved).json() == {"ok": False, "error": "401 Unauthorized"}


def test_untrusted_certificate_explains_the_checkbox(client, logged_in, saved):
    logged_in("admin")
    err = requests.exceptions.SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    with patch("app.proxmox.list_cluster_resources", side_effect=err):
        data = _post(client, connection_id=saved, verify_ssl=True).json()
    assert data["ok"] is False and "self-signed" in data["error"]


def test_unreadable_permissions_still_count_as_connected(client, logged_in, saved):
    logged_in("admin")
    with patch("app.proxmox.list_cluster_resources", return_value=_ROWS), \
         patch("app.proxmox.token_privileges", side_effect=ProxmoxError("403")):
        data = _post(client, connection_id=saved).json()
    assert data["ok"] is True and data["uses"] is None


def test_token_privileges_flattens_every_path():
    from unittest.mock import MagicMock
    from app import proxmox
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"data": {"/": {"Sys.Audit": 1}, "/vms/100": {"VM.Audit": 1, "VM.Snapshot": 0}}}
    with patch("app.proxmox.requests.get", return_value=resp):
        assert proxmox.token_privileges(_SAVED) == {"Sys.Audit", "VM.Audit"}


def test_a_connection_that_sees_another_connections_nodes_is_flagged(client, logged_in, saved):
    """A standalone host that later joined a cluster would show every VM twice."""
    logged_in("admin")
    with patch("app.proxmox.list_cluster_resources", return_value=_ROWS), \
         patch("app.proxmox.token_privileges", return_value=set()):
        data = _post(client, host="other.lab", token_id="a@pve!b", token_secret="x").json()
    assert data["overlaps"] == [{"connection": "saved", "nodes": ["pve1", "pve2"]}]
