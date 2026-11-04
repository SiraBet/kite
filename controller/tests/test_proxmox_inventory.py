"""
Proxmox coverage and topology (app/proxmox_inventory.py,
app/routers/infrastructure.py). Proxmox itself is mocked at
proxmox.list_cluster_resources; everything downstream of it -- matching
guests to hosts, classification, blast radius, degradation when Proxmox
is down -- runs for real.

The test database is shared across the session, so guests here use
vmids no other test touches and assertions pick out their own rows
rather than counting the whole fleet.
"""
import uuid
from unittest.mock import patch

import pytest

from app import models, proxmox_inventory
from app.proxmox import ProxmoxConfig, ProxmoxError
from conftest import make_host

_CFG = ProxmoxConfig(host="10.0.0.5", node="pve1", token_id="t", token_secret="s")


@pytest.fixture(autouse=True)
def _fresh_cache():
    proxmox_inventory.clear_cache()
    yield
    proxmox_inventory.clear_cache()


@pytest.fixture
def cluster():
    """Patch in a configured Proxmox serving `rows`; returns the list to fill."""
    rows = []
    with patch("app.rollback.resolve_proxmox_config", return_value=_CFG), \
         patch("app.proxmox.list_cluster_resources", side_effect=lambda cfg: list(rows)) as mock:
        mock.rows = rows
        yield mock


def _vmid():
    return 70000 + uuid.uuid4().int % 20000


def _guest(vmid, name, node="pve1", type_="qemu", status="running", template=0):
    return {"type": type_, "vmid": vmid, "name": name, "node": node, "status": status, "template": template}


def _by_vmid(data, vmid):
    return next(g for g in data["guests"] if g["vmid"] == vmid)


def test_unconfigured_proxmox_answers_with_reason(client, logged_in):
    logged_in("operator")
    with patch("app.rollback.resolve_proxmox_config", return_value=ProxmoxConfig()):
        data = client.get("/proxmox/coverage").json()
    assert data["proxmox"]["configured"] is False
    assert "Settings → Connections" in data["proxmox"]["error"]
    assert data["guests"] == [] and data["stale_links"] == []


def test_coverage_classifies_guests(client, logged_in, db, cluster):
    logged_in("operator")
    managed_id, match_id, lost_id, tmpl_id, lxc_id = (_vmid() for _ in range(5))
    linked, _ = make_host(db)
    linked.proxmox_vmid = managed_id
    named, _ = make_host(db, hostname=f"named-{uuid.uuid4().hex[:6]}.lab.example")
    db.commit()
    cluster.rows += [
        _guest(managed_id, "whatever-name"),
        _guest(match_id, named.hostname.split(".")[0].upper()),  # short, case-insensitive
        _guest(lost_id, f"nobody-{uuid.uuid4().hex[:6]}", status="stopped"),
        _guest(tmpl_id, "rocky9-template", template=1),
        _guest(lxc_id, f"ct-{uuid.uuid4().hex[:6]}", type_="lxc"),
        {"type": "node", "node": "pve1", "status": "online"},
    ]
    data = client.get("/proxmox/coverage").json()
    assert data["proxmox"]["configured"] and not data["proxmox"]["error"]
    assert _by_vmid(data, managed_id)["coverage"] == "managed"
    assert _by_vmid(data, managed_id)["host"] == {"id": linked.id, "hostname": linked.hostname}
    assert _by_vmid(data, match_id)["coverage"] == "name_match"
    assert _by_vmid(data, match_id)["host"]["id"] == named.id
    assert _by_vmid(data, lost_id)["coverage"] == "unmanaged"
    assert _by_vmid(data, tmpl_id)["coverage"] == "template"
    assert _by_vmid(data, lxc_id)["coverage"] == "unmanaged"
    assert data["summary"]["unmanaged"] == 2 and data["summary"]["unmanaged_running"] == 1
    # Unmanaged and running sorts first: it's the one to act on.
    assert data["guests"][0]["vmid"] == lxc_id


def test_stale_link_reported_only_when_proxmox_answered(client, logged_in, db, cluster):
    logged_in("operator")
    host, _ = make_host(db)
    host.proxmox_vmid = _vmid()
    db.commit()
    cluster.rows.append({"type": "node", "node": "pve1", "status": "online"})
    data = client.get("/proxmox/coverage").json()
    assert host.id in [s["host_id"] for s in data["stale_links"]]

    proxmox_inventory.clear_cache()
    cluster.side_effect = ProxmoxError("connection refused")
    data = client.get("/proxmox/coverage").json()
    assert data["proxmox"]["error"] == "connection refused"
    assert data["stale_links"] == []


def test_ignore_list_round_trip_and_role_gate(client, logged_in, cluster):
    vmid = _vmid()
    cluster.rows.append(_guest(vmid, f"pfsense-{uuid.uuid4().hex[:6]}"))
    logged_in("operator")
    assert client.post("/proxmox/ignored", json={"vmid": vmid, "reason": "firewall"}).status_code == 403
    logged_in("lead")
    assert client.post("/proxmox/ignored", json={"vmid": vmid, "reason": "firewall appliance"}).status_code == 200
    assert client.post("/proxmox/ignored", json={"vmid": vmid, "reason": "again"}).status_code == 409
    g = _by_vmid(client.get("/proxmox/coverage?refresh=true").json(), vmid)
    assert g["coverage"] == "ignored" and g["ignore_reason"] == "firewall appliance"
    assert g["ignored_by"]
    assert client.delete(f"/proxmox/ignored/{vmid}").status_code == 200
    assert client.delete(f"/proxmox/ignored/{vmid}").status_code == 404
    assert _by_vmid(client.get("/proxmox/coverage?refresh=true").json(), vmid)["coverage"] == "unmanaged"


def test_ignore_beats_name_match(client, logged_in, db, cluster):
    host, _ = make_host(db)
    vmid = _vmid()
    cluster.rows.append(_guest(vmid, host.hostname))
    logged_in("lead")
    client.post("/proxmox/ignored", json={"vmid": vmid, "reason": "Lab box, rebuilt weekly"})
    assert _by_vmid(client.get("/proxmox/coverage").json(), vmid)["coverage"] == "ignored"
    client.delete(f"/proxmox/ignored/{vmid}")


def test_cluster_is_cached_until_refresh(client, logged_in, cluster):
    logged_in("operator")
    client.get("/proxmox/coverage")
    client.get("/topology")
    assert cluster.call_count == 1
    assert client.get("/proxmox/coverage").json()["proxmox"]["cached"] is True
    client.get("/proxmox/coverage?refresh=true")
    assert cluster.call_count == 2


def test_topology_places_hosts_and_computes_blast_radius(client, logged_in, db, cluster):
    logged_in("operator")
    node = f"pve-{uuid.uuid4().hex[:6]}"
    snap_id, lxc_id, free_id = _vmid(), _vmid(), _vmid()
    snap, _ = make_host(db)
    snap.proxmox_vmid, snap.rollback_backend = snap_id, "proxmox"
    ct, _ = make_host(db)
    ct.proxmox_vmid, ct.rollback_backend = lxc_id, "proxmox"  # LXC: proxmox backend can't snapshot it
    db.add(models.PendingUpdate(host_id=ct.id, package="openssl", severity="critical"))
    db.add(models.Container(host_id=snap.id, name="web", image="nginx:1", state="running",
                            managed_by="compose", compose_working_dir="/srv", compose_service="web",
                            update_available=True))
    db.commit()
    cluster.rows += [
        {"type": "node", "node": node, "status": "online", "maxcpu": 8},
        _guest(snap_id, "a", node=node), _guest(lxc_id, "b", node=node, type_="lxc"),
        _guest(free_id, f"stray-{uuid.uuid4().hex[:6]}", node=node, status="stopped"),
        _guest(_vmid(), "tmpl", node=node, template=1),
    ]
    data = client.get("/topology").json()
    n = next(x for x in data["nodes"] if x["name"] == node)
    assert n["status"] == "online" and n["templates"] == 1
    hosts = {g["vmid"]: g["host"] for g in n["guests"]}
    assert hosts[snap_id]["safety_net"] == "snapshot"
    assert hosts[snap_id]["containers"] == {"total": 1, "running": 1, "updatable": 1, "update_available": 1}
    assert hosts[snap_id]["container_runtime"] == ""
    assert hosts[lxc_id]["safety_net"] == "none"
    assert hosts[lxc_id]["max_severity"] == "critical"
    assert hosts[free_id] is None
    assert n["blast_radius"] == {"guests": 3, "running": 2, "managed": 2, "unmanaged": 1,
                                 "active_runs": 0, "no_snapshot": 1, "critical_pending": 1}
    unplaced = {h["id"] for h in data["unplaced"]}
    assert snap.id not in unplaced and ct.id not in unplaced


def test_topology_degrades_to_pinned_nodes_when_proxmox_is_down(client, logged_in, db, cluster):
    logged_in("operator")
    node = f"pve-{uuid.uuid4().hex[:6]}"
    pinned, _ = make_host(db)
    pinned.proxmox_vmid, pinned.proxmox_node = _vmid(), node
    loose, _ = make_host(db)
    db.commit()
    cluster.side_effect = ProxmoxError("timeout")
    data = client.get("/topology").json()
    assert data["proxmox"]["error"] == "timeout"
    n = next(x for x in data["nodes"] if x["name"] == node)
    assert n["status"] == "unknown"
    assert n["guests"][0]["host"]["id"] == pinned.id
    assert n["guests"][0]["host"]["placement"] == "pinned"
    assert loose.id in {h["id"] for h in data["unplaced"]}


def test_read_token_can_use_both_views(client, logged_in, cluster):
    from fastapi.testclient import TestClient
    from app.main import app
    logged_in("operator")
    token = client.post("/tokens", json={"name": "mcp"}).json()["token"]
    api = TestClient(app)
    api.headers["Authorization"] = f"Bearer {token}"
    assert api.get("/proxmox/coverage").status_code == 200
    assert api.get("/topology").status_code == 200
    assert api.post("/proxmox/ignored", json={"vmid": 1, "reason": "x"}).status_code == 403


def test_ignore_reason_is_required_prose_without_markup(client, logged_in, cluster):
    logged_in("lead")
    vmid = _vmid()
    assert client.post("/proxmox/ignored", json={"vmid": vmid}).status_code == 422
    assert client.post("/proxmox/ignored", json={"vmid": vmid, "reason": "   "}).status_code == 422
    assert client.post("/proxmox/ignored", json={"vmid": vmid, "reason": "<b>x</b>"}).status_code == 422
    assert client.post("/proxmox/ignored", json={"vmid": vmid, "reason": "x" * 201}).status_code == 422
    ok = client.post("/proxmox/ignored", json={"vmid": vmid, "reason": "Appliance, vendor-updated (pfSense)"})
    assert ok.status_code == 200
    client.delete(f"/proxmox/ignored/{vmid}")


def test_status_block_names_the_cluster(client, logged_in, cluster):
    logged_in("operator")
    cluster.rows += [{"type": "node", "node": "pve1", "status": "online"},
                     {"type": "node", "node": "pve2", "status": "online"}]
    status = client.get("/proxmox/coverage").json()["proxmox"]
    assert status["host"] == "10.0.0.5" and status["nodes"] == 2
    assert status["stale"] is False


def test_failed_refresh_serves_the_last_good_fetch_marked_stale(client, logged_in, db, cluster):
    logged_in("operator")
    host, _ = make_host(db)
    vmid = _vmid()
    host.proxmox_vmid = vmid
    db.commit()
    cluster.rows += [{"type": "node", "node": "pve1", "status": "online"}, _guest(vmid, "x")]
    good = client.get("/proxmox/coverage").json()
    cluster.side_effect = ProxmoxError("401 Unauthorized")
    data = client.get("/proxmox/coverage?refresh=true").json()
    assert data["proxmox"]["error"] == "401 Unauthorized"
    assert data["proxmox"]["stale"] is True
    assert data["proxmox"]["fetched_at"] == good["proxmox"]["fetched_at"]
    assert _by_vmid(data, vmid)["coverage"] == "managed"
    topo = client.get("/topology").json()
    assert topo["proxmox"]["stale"] is True
    assert host.id not in {h["id"] for h in topo["unplaced"]}


def test_topology_host_detail_and_unplaced_reasons(client, logged_in, db, cluster):
    logged_in("operator")
    placed, _ = make_host(db)
    placed.proxmox_vmid = _vmid()
    gone, _ = make_host(db)
    gone.proxmox_vmid = _vmid()
    loose, _ = make_host(db)
    db.add_all([models.PendingUpdate(host_id=placed.id, package="a", severity="critical"),
                models.PendingUpdate(host_id=placed.id, package="b", severity="moderate"),
                models.PendingUpdate(host_id=placed.id, package="c", severity="moderate")])
    db.commit()
    cluster.rows += [{"type": "node", "node": "pve1", "status": "online"}, _guest(placed.proxmox_vmid, "p")]
    data = client.get("/topology").json()
    h = next(g["host"] for n in data["nodes"] for g in n["guests"] if g["host"] and g["host"]["id"] == placed.id)
    assert h["pending_by_severity"] == {"critical": 1, "moderate": 2}
    assert "last_seen" in h
    reasons = {u["id"]: u["unplaced_reason"] for u in data["unplaced"]}
    assert reasons[gone.id] == "stale_link" and reasons[loose.id] == "not_linked"
