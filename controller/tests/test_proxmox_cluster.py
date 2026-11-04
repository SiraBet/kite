"""
multi-Proxmox-node/cluster support. Covers app/proxmox.py's
new cluster-wide lookups (list_cluster_vms, resolve_vm_node, the
cluster-search path in find_vmid_by_smbios_uuid) and
app/rollback/__init__.py's use of them to resolve a VM's actual node
before snapshotting, instead of assuming the one globally configured
PROXMOX_NODE.
"""
from unittest.mock import patch, MagicMock

import pytest

from app import models, proxmox, rollback
from app.proxmox import ProxmoxConfig, ProxmoxError
from conftest import make_host

_CFG = ProxmoxConfig(host="10.0.0.5", node="pve1", token_id="t", token_secret="s", verify_ssl=False)


def _resp(status_code=200, data=None):
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = {"data": data or []}
    m.text = "error"
    return m


def test_list_cluster_vms_requires_host():
    with pytest.raises(ProxmoxError, match="host not configured"):
        proxmox.list_cluster_vms(ProxmoxConfig())


def test_list_cluster_vms_parses_node_per_vm():
    cluster_rows = [{"vmid": 101, "node": "pve1", "type": "qemu"}, {"vmid": 102, "node": "pve2", "type": "qemu"}]
    with patch("app.proxmox.requests.get", return_value=_resp(data=cluster_rows)) as mock_get:
        vms = proxmox.list_cluster_vms(_CFG)
    assert vms == [{"vmid": 101, "node": "pve1"}, {"vmid": 102, "node": "pve2"}]
    assert mock_get.call_args.kwargs["params"] == {"type": "vm"}


def test_list_cluster_vms_raises_on_error_status():
    with patch("app.proxmox.requests.get", return_value=_resp(status_code=500)):
        with pytest.raises(ProxmoxError, match="cluster resource list failed"):
            proxmox.list_cluster_vms(_CFG)


def test_resolve_vm_node_finds_match():
    with patch("app.proxmox.list_cluster_vms", return_value=[{"vmid": 101, "node": "pve1"}, {"vmid": 202, "node": "pve2"}]):
        assert proxmox.resolve_vm_node(_CFG, 202) == "pve2"


def test_resolve_vm_node_returns_none_when_not_found():
    with patch("app.proxmox.list_cluster_vms", return_value=[{"vmid": 101, "node": "pve1"}]):
        assert proxmox.resolve_vm_node(_CFG, 999) is None


def test_create_snapshot_uses_explicit_node_over_cfg_node():
    with patch("app.proxmox.requests.post", return_value=_resp(data={"upid": "x"})) as mock_post:
        proxmox.create_snapshot(_CFG, 202, "snap1", node="pve2")
    url = mock_post.call_args.args[0]
    assert "/nodes/pve2/qemu/202/snapshot" in url


def test_create_snapshot_falls_back_to_cfg_node_when_node_not_given():
    with patch("app.proxmox.requests.post", return_value=_resp(data={"upid": "x"})) as mock_post:
        proxmox.create_snapshot(_CFG, 101, "snap1")
    url = mock_post.call_args.args[0]
    assert "/nodes/pve1/qemu/101/snapshot" in url


def test_find_vmid_by_smbios_uuid_searches_cluster_wide():
    cluster = [{"vmid": 101, "node": "pve1"}, {"vmid": 202, "node": "pve2"}]
    uuids = {(101, "pve1"): "uuid-a", (202, "pve2"): "uuid-b"}
    with patch("app.proxmox.list_cluster_vms", return_value=cluster), \
         patch("app.proxmox.get_vm_smbios_uuid", side_effect=lambda cfg, vmid, node: uuids[(vmid, node)]):
        found = proxmox.find_vmid_by_smbios_uuid(_CFG, "uuid-b")
    assert found == 202


def test_find_vmid_by_smbios_uuid_falls_back_to_single_node_if_cluster_lookup_fails():
    with patch("app.proxmox.list_cluster_vms", side_effect=ProxmoxError("no cluster access")), \
         patch("app.proxmox.list_vmids", return_value=[101]), \
         patch("app.proxmox.get_vm_smbios_uuid", return_value="uuid-a"):
        found = proxmox.find_vmid_by_smbios_uuid(_CFG, "uuid-a")
    assert found == 101


# ---------- run_controller_snapshot: node resolution ----------

def test_run_controller_snapshot_resolves_node_via_cluster_when_unpinned(db, legacy_proxmox):
    host, _ = make_host(db)
    host.proxmox_vmid = 202
    db.commit()
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="proxmox")
    db.add(job)
    db.commit()
    db.refresh(job)

    with patch("app.proxmox.resolve_vm_node", return_value="pve2") as mock_resolve, \
         patch("app.proxmox.create_snapshot", return_value={"data": "UPID:fake"}) as mock_snap:
        output = rollback.run_controller_snapshot(db, job, "proxmox")

    assert mock_resolve.call_count == 1
    assert mock_snap.call_args.kwargs["node"] == "pve2"
    assert "on node pve2" in output


def test_run_controller_snapshot_uses_pinned_host_node_without_lookup(db, legacy_proxmox):
    host, _ = make_host(db)
    host.proxmox_vmid = 202
    host.proxmox_node = "pve-pinned"
    db.commit()
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="proxmox")
    db.add(job)
    db.commit()
    db.refresh(job)

    with patch("app.proxmox.resolve_vm_node") as mock_resolve, \
         patch("app.proxmox.create_snapshot", return_value={"data": "UPID:fake"}) as mock_snap:
        output = rollback.run_controller_snapshot(db, job, "proxmox")

    assert mock_resolve.call_count == 0  # pinned -- no lookup needed
    assert mock_snap.call_args.kwargs["node"] == "pve-pinned"
    assert "on node pve-pinned" in output


def test_run_controller_snapshot_falls_back_silently_when_node_lookup_fails(db, legacy_proxmox):
    host, _ = make_host(db)
    host.proxmox_vmid = 202
    db.commit()
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="proxmox")
    db.add(job)
    db.commit()
    db.refresh(job)

    with patch("app.proxmox.resolve_vm_node", side_effect=ProxmoxError("no access")), \
         patch("app.proxmox.create_snapshot", return_value={"data": "UPID:fake"}) as mock_snap:
        output = rollback.run_controller_snapshot(db, job, "proxmox")

    assert mock_snap.call_args.kwargs["node"] is None
    assert output.startswith("Taking snapshot 'kite-job") and "of VM 202" in output
    assert output.endswith("Proxmox task UPID:fake")


# ---------- host.proxmox_node via PATCH /hosts/{id} ----------

def test_patch_host_sets_and_clears_proxmox_node(client, logged_in, db):
    logged_in(role="admin", username="pn-admin-1")
    host, _ = make_host(db)

    resp = client.patch(f"/hosts/{host.id}", json={"proxmox_node": "pve-2"})
    assert resp.status_code == 200
    assert resp.json()["proxmox_node"] == "pve-2"

    resp = client.patch(f"/hosts/{host.id}", json={"proxmox_node": ""})
    assert resp.status_code == 200
    assert resp.json()["proxmox_node"] in ("", None)
