"""
Several Proxmox connections side by side (app/proxmox_connections.py and
everything that reads through it): adopting the old single connection,
managing the list, and keeping VM ids, nodes, snapshots and the ignore
list apart per connection. Proxmox itself is mocked per connection host.
"""
import uuid
from unittest.mock import patch

import pytest

from app import crypto, models, proxmox_connections, proxmox_inventory, rollback
from app.proxmox import ProxmoxConfig
from app.settings_store import set_setting, set_secret
from conftest import make_host


def _conn(db, name, host, secret="s"):
    row = models.ProxmoxConnection(name=name, host=host, token_id=f"kite@pve!{name}",
                                   token_secret_enc=crypto.encrypt(secret))
    db.add(row)
    db.commit()
    return row


def _vm(vmid, name, node="pve", status="running"):
    return {"type": "qemu", "vmid": vmid, "name": name, "node": node, "status": status, "template": 0}


@pytest.fixture
def two_clusters(db):
    """A cluster and a standalone host, both with a node called 'pve' and a VM 100."""
    proxmox_inventory.clear_cache()
    a, b = _conn(db, "cluster", "10.1.0.1"), _conn(db, "standalone", "10.2.0.1")
    data = {
        "10.1.0.1": [{"type": "node", "node": "pve", "status": "online"}, _vm(100, "alpha"), _vm(101, "beta")],
        "10.2.0.1": [{"type": "node", "node": "pve", "status": "online"}, _vm(100, "gamma")],
    }
    with patch("app.proxmox.list_cluster_resources", side_effect=lambda cfg: list(data[cfg.host])):
        yield {"a": a, "b": b, "data": data}
    proxmox_inventory.clear_cache()


# ---------- adopting the old single connection ----------

def test_legacy_settings_become_the_first_connection_once(db):
    set_setting(db, "rollback_proxmox_host", "legacy.lab")
    set_setting(db, "rollback_proxmox_token_id", "kite@pve!old")
    set_secret(db, "rollback_proxmox_token_secret", "old-secret")
    host, _ = make_host(db)
    host.proxmox_vmid = 4242
    db.add(models.ProxmoxIgnoredGuest(vmid=4243, reason="appliance"))
    db.commit()
    try:
        assert proxmox_connections.list_connections(db)[0].id is None      # legacy, before adoption
        row = proxmox_connections.adopt_legacy_connection(db)
        assert row.host == "legacy.lab" and row.token_id == "kite@pve!old"
        conns = proxmox_connections.list_connections(db)
        assert [c.id for c in conns] == [row.id] and conns[0].cfg.token_secret == "old-secret"
        db.refresh(host)
        assert host.proxmox_connection_id == row.id
        assert db.query(models.ProxmoxIgnoredGuest).filter_by(vmid=4243).one().connection_id == row.id
        assert proxmox_connections.adopt_legacy_connection(db) is None      # only once
    finally:
        # Delete rather than blank: other tests insert these keys fresh.
        db.query(models.Setting).filter(models.Setting.key.in_(
            ["rollback_proxmox_host", "rollback_proxmox_token_id", "rollback_proxmox_token_secret_enc"])).delete(
            synchronize_session=False)
        db.query(models.ProxmoxIgnoredGuest).filter_by(vmid=4243).delete()
        db.commit()


def test_an_env_configured_secret_stays_in_the_environment(db):
    with patch("app.rollback.resolve_proxmox_config",
               return_value=ProxmoxConfig(host="env.lab", token_id="a@pve!env", token_secret="from-env")), \
         patch("app.proxmox_connections.settings") as env:
        env.proxmox_token_secret = "from-env"
        row = proxmox_connections.adopt_legacy_connection(db)
        assert row.token_secret_enc == ""                                   # not copied into the DB
        assert proxmox_connections.list_connections(db)[0].cfg.token_secret == "from-env"


# ---------- managing the list ----------

def test_add_edit_remove_connections(client, logged_in, db):
    logged_in("admin")
    body = {"name": "standalone", "host": "10.3.0.1", "token_id": "kite@pve!x", "token_secret": "sekret"}
    assert client.post("/settings/proxmox-connections", json=dict(body, token_secret="")).status_code == 400
    created = client.post("/settings/proxmox-connections", json=body)
    assert created.status_code == 200, created.text
    c = created.json()
    assert c["secret_set"] is True and "sekret" not in created.text
    assert client.post("/settings/proxmox-connections", json=body).status_code == 409   # same name
    assert client.post("/settings/proxmox-connections",
                       json=dict(body, name="bad", host="https://x:8006/")).status_code == 422
    # blank secret on edit keeps the saved one
    edited = client.patch(f"/settings/proxmox-connections/{c['id']}", json={"name": "renamed", "token_secret": ""})
    assert edited.json()["name"] == "renamed"
    assert proxmox_connections.get_connection(db, c["id"]).cfg.token_secret == "sekret"
    # removing unlinks its machines and forgets what was learned through it
    host, _ = make_host(db)
    host.proxmox_vmid, host.proxmox_connection_id = 7, c["id"]
    db.add(models.ProxmoxGuestNic(connection_id=c["id"], vmid=7, mac="bc:24:11:00:00:07", bridge="vmbr0"))
    db.commit()
    listed = client.get("/settings/proxmox-connections").json()[0]
    assert listed["linked_hosts"] == 1 and listed["guests"] == 1
    gone = client.delete(f"/settings/proxmox-connections/{c['id']}").json()
    assert gone["unlinked_hosts"] == 1
    db.refresh(host)
    assert host.proxmox_vmid is None and host.proxmox_connection_id is None
    assert db.query(models.ProxmoxGuestNic).filter_by(connection_id=c["id"]).count() == 0


def test_connections_are_admin_only(client, logged_in):
    logged_in("lead")
    assert client.get("/settings/proxmox-connections").status_code == 403
    assert client.post("/settings/proxmox-connections", json={}).status_code == 403


# ---------- keeping connections apart ----------

def test_the_same_vmid_on_two_connections_is_two_vms(client, logged_in, db, two_clusters):
    host, _ = make_host(db)
    host.proxmox_vmid, host.proxmox_connection_id = 100, two_clusters["b"].id
    db.commit()
    logged_in("operator")
    guests = client.get("/proxmox/coverage").json()["guests"]
    by = {(g["connection"], g["vmid"]): g for g in guests}
    assert by[("standalone", 100)]["coverage"] == "managed"
    assert by[("cluster", 100)]["coverage"] == "unmanaged"


def test_nodes_with_the_same_name_stay_separate(client, logged_in, db, two_clusters):
    logged_in("operator")
    topo = client.get("/topology").json()
    pves = [n for n in topo["nodes"] if n["name"] == "pve"]
    assert len(pves) == 2 and len({n["key"] for n in pves}) == 2
    assert {n["connection"] for n in pves} == {"cluster", "standalone"}
    assert [c["name"] for c in topo["clusters"]] == ["cluster", "standalone"]


def test_one_connection_failing_leaves_the_others_on_screen(client, logged_in, db, two_clusters):
    from app.proxmox import ProxmoxError
    def flaky(cfg):
        if cfg.host == "10.2.0.1":
            raise ProxmoxError("401 Unauthorized")
        return list(two_clusters["data"][cfg.host])
    logged_in("operator")
    with patch("app.proxmox.list_cluster_resources", side_effect=flaky):
        data = client.get("/proxmox/coverage").json()
    assert data["proxmox"]["error"] == "standalone: 401 Unauthorized"
    assert data["proxmox"]["stale"] is True                         # data is still shown, with the error
    assert {g["name"] for g in data["guests"]} == {"alpha", "beta"}


def test_ignoring_is_per_connection(client, logged_in, db, two_clusters):
    logged_in("lead")
    assert client.post("/proxmox/ignored", json={"vmid": 100, "connection_id": two_clusters["a"].id,
                                                  "reason": "appliance"}).status_code == 200
    by = {(g["connection"], g["vmid"]): g for g in client.get("/proxmox/coverage?refresh=true").json()["guests"]}
    assert by[("cluster", 100)]["coverage"] == "ignored" and by[("standalone", 100)]["coverage"] == "unmanaged"
    assert client.delete(f"/proxmox/ignored/100?connection_id={two_clusters['b'].id}").status_code == 404
    assert client.delete(f"/proxmox/ignored/100?connection_id={two_clusters['a'].id}").status_code == 200


def test_snapshot_goes_to_the_hosts_own_connection(db, two_clusters):
    host, _ = make_host(db)
    host.proxmox_vmid, host.proxmox_connection_id = 100, two_clusters["b"].id
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="proxmox")
    db.add(job)
    db.commit()
    db.refresh(job)
    with patch("app.proxmox.resolve_vm_node", return_value="pve"), \
         patch("app.proxmox.create_snapshot", return_value={}) as snap:
        rollback.run_controller_snapshot(db, job, "proxmox")
    assert snap.call_args.args[0].host == "10.2.0.1"


def test_snapshot_refuses_to_guess_between_connections(db, two_clusters):
    host, _ = make_host(db)
    host.proxmox_vmid = 100            # no connection chosen, and there are two
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="proxmox")
    db.add(job)
    db.commit()
    db.refresh(job)
    with pytest.raises(RuntimeError, match="more than one"):
        rollback.run_controller_snapshot(db, job, "proxmox")


def test_vm_lookup_searches_every_connection(client, logged_in, db, two_clusters):
    host, _ = make_host(db)
    host.smbios_uuid = str(uuid.uuid4())
    db.commit()
    def find(cfg, uuid_):
        return 100 if cfg.host == "10.2.0.1" else None
    logged_in("admin")
    with patch("app.proxmox.find_vmid_by_smbios_uuid", side_effect=find):
        out = client.post(f"/hosts/{host.id}/resolve-vmid").json()
    assert out["proxmox_vmid"] == 100 and out["proxmox_connection_id"] == two_clusters["b"].id


def test_linking_a_host_names_its_connection(client, logged_in, db, two_clusters):
    host, _ = make_host(db)
    logged_in("admin")
    assert client.patch(f"/hosts/{host.id}", json={"proxmox_vmid": 100, "proxmox_connection_id": 99999}).status_code == 400
    ok = client.patch(f"/hosts/{host.id}", json={"proxmox_vmid": 100, "proxmox_connection_id": two_clusters["a"].id})
    assert ok.json()["proxmox_connection_id"] == two_clusters["a"].id
