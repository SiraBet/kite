"""
Network discovery (app/network_inventory.py, the network half of the
agent inventory in routers/agent.py, and the /network endpoints).

Proxmox is mocked at its client calls; the parsing, the MAC join, the
VLAN derivation, the baseline/announce logic and the role gate all run
for real. The test DB is shared across the session, so vmids, MACs and
subnets here are unique to this file and assertions pick out their own
rows.
"""
import uuid
from unittest.mock import patch

import pytest

from app import models, network_inventory, proxmox_inventory
from app.proxmox import ProxmoxConfig, ProxmoxError
from conftest import make_host

_CFG = ProxmoxConfig(host="10.0.0.5", node="pve1", token_id="t", token_secret="s")


# ---------- parsing ----------

def test_parse_qemu_and_lxc_net_lines():
    q = network_inventory.parse_net_line("virtio=BC:24:11:AA:BB:CC,bridge=vmbr20,firewall=1")
    assert q == {"mac": "bc:24:11:aa:bb:cc", "bridge": "vmbr20", "vlan_tag": None, "firewall": True, "ip": ""}
    c = network_inventory.parse_net_line("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=10.9.0.5/24,tag=30,type=veth")
    assert c == {"mac": "bc:24:11:00:00:01", "bridge": "vmbr0", "vlan_tag": 30, "firewall": False, "ip": "10.9.0.5/24"}
    assert network_inventory.parse_net_line("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,ip=dhcp")["ip"] == ""


def test_parse_bridges_derives_vlans_on_a_non_vlan_aware_setup():
    rows = [
        {"iface": "eno1", "type": "eth"},
        {"iface": "eno1.20", "type": "vlan", "vlan-id": "20", "vlan-raw-device": "eno1"},
        {"iface": "vmbr0", "type": "bridge", "bridge_ports": "eno1", "cidr": "10.0.0.2/24"},
        {"iface": "vmbr20", "type": "bridge", "bridge_ports": "eno1.20", "comments": "servers\n"},
        {"iface": "vmbr30", "type": "bridge", "bridge_ports": "bond0.30", "address": "10.0.30.2", "netmask": "255.255.255.0"},
        {"iface": "vmbr40", "type": "bridge", "bridge_ports": "vlan40"},
        {"iface": "vmbr9", "type": "bridge", "bridge_ports": "eno2", "bridge_vlan_aware": 1},
        {"iface": "vmbr99", "type": "bridge", "bridge_ports": ""},
    ]
    b = {x["name"]: x for x in network_inventory.parse_bridges(rows)}
    assert b["vmbr0"]["vlan_id"] is None and b["vmbr0"]["cidr"] == "10.0.0.2/24"
    assert b["vmbr20"]["vlan_id"] == 20 and b["vmbr20"]["comments"] == "servers"
    assert b["vmbr30"]["vlan_id"] == 30 and b["vmbr30"]["cidr"] == "10.0.30.2/24"
    assert b["vmbr40"]["vlan_id"] == 40
    assert b["vmbr9"]["vlan_aware"] is True and b["vmbr9"]["vlan_id"] is None
    assert b["vmbr99"]["vlan_id"] is None and b["vmbr99"]["ports"] == ""


# ---------- agent inventory ----------

def _mac():
    h = uuid.uuid4().hex
    return "bc:24:" + ":".join(h[i:i + 2] for i in range(0, 8, 2))


def _net(ifaces=None, listening=None, ok=True, error="", gw="10.0.20.1"):
    return {"ok": ok, "error": error, "default_gateway": gw,
            "interfaces": ifaces or [], "listening": listening or []}


def _sock(port, proto="tcp", address="0.0.0.0", process="sshd", loopback=False):
    return {"proto": proto, "address": address, "port": port, "process": process, "loopback": loopback}


def _report(client, host, secret, network, **extra):
    body = dict({"runtime": "", "containers": [], "updates": [], "updates_ok": True, "network": network}, **extra)
    resp = client.post(f"/agent/{host.id}/inventory", json=body, headers={"Authorization": f"Bearer {secret}"})
    assert resp.status_code == 200, resp.text
    return resp


def _opened(db, host):
    return [a.detail for a in db.query(models.AuditLog).filter(models.AuditLog.action == "port_opened",
                                                                 models.AuditLog.detail.contains(host.hostname)).all()]


def test_first_report_is_a_baseline_and_later_new_ports_are_announced(client, db):
    host, secret = make_host(db)
    _report(client, host, secret, _net(listening=[_sock(22)]))
    assert _opened(db, host) == []
    _report(client, host, secret, _net(listening=[
        _sock(22), _sock(3306, process="mysqld"), _sock(5432, address="127.0.0.1", loopback=True),
        _sock(45000, process="node")]))
    detail = _opened(db, host)
    assert len(detail) == 1 and "tcp/3306 (mysqld)" in detail[0]
    assert "5432" not in detail[0] and "45000" not in detail[0]  # loopback and ephemeral stay quiet
    first = db.query(models.HostListeningPort).filter_by(host_id=host.id, port=22).one().first_seen
    _report(client, host, secret, _net(listening=[_sock(22)]))
    db.expire_all()
    remaining = {p.port for p in db.query(models.HostListeningPort).filter_by(host_id=host.id)}
    assert remaining == {22}  # closed ports are dropped
    assert db.query(models.HostListeningPort).filter_by(host_id=host.id, port=22).one().first_seen == first


def test_could_not_tell_keeps_the_last_good_picture(client, db):
    host, secret = make_host(db)
    _report(client, host, secret, _net(ifaces=[{"name": "eth0", "mac": _mac(), "addresses": ["10.0.20.7/24"]}],
                                       listening=[_sock(22)]))
    _report(client, host, secret, _net(ok=False, error="ss failed: not found"))
    db.expire_all()
    h = db.get(models.Host, host.id)
    assert h.network_ok is False and "ss failed" in h.network_error
    assert db.query(models.HostListeningPort).filter_by(host_id=host.id).count() == 1
    assert db.query(models.HostInterface).filter_by(host_id=host.id).count() == 1


def test_older_agent_without_network_leaves_it_alone(client, db):
    host, secret = make_host(db)
    _report(client, host, secret, _net(listening=[_sock(22)]))
    client.post(f"/agent/{host.id}/inventory", json={"runtime": "", "containers": [], "updates": []},
                headers={"Authorization": f"Bearer {secret}"})
    db.expire_all()
    assert db.query(models.HostListeningPort).filter_by(host_id=host.id).count() == 1


def test_malformed_entries_are_dropped_not_the_report(client, db):
    host, secret = make_host(db)
    _report(client, host, secret, _net(
        ifaces=[{"name": "eth0", "mac": "NOT-A-MAC", "addresses": ["10.0.20.8/24", "garbage", "10.0.20.9"]},
                {"name": "<script>", "mac": _mac()}],
        listening=[_sock(22), _sock(99999), {"proto": "sctp", "address": "0.0.0.0", "port": 1},
                   _sock(80, address="not-an-ip"), _sock(443, process="<img src=x>")]),
        updates=[{"package": "openssl", "new_version": "3", "severity": "critical"}])
    iface = db.query(models.HostInterface).filter_by(host_id=host.id).one()
    assert iface.name == "eth0" and iface.mac == "" and iface.address_list == ["10.0.20.8/24"]
    socks = {p.port: p for p in db.query(models.HostListeningPort).filter_by(host_id=host.id)}
    assert set(socks) == {22, 443} and socks[443].process == ""
    assert db.query(models.PendingUpdate).filter_by(host_id=host.id, package="openssl").count() == 1


def test_deleting_a_host_removes_its_network_rows(client, logged_in, db):
    host, secret = make_host(db)
    _report(client, host, secret, _net(ifaces=[{"name": "eth0", "mac": _mac(), "addresses": ["10.0.20.10/24"]}],
                                       listening=[_sock(22)]))
    host.last_seen = None  # offline, so deletable
    db.commit()
    logged_in("admin")
    assert client.delete(f"/hosts/{host.id}").status_code == 200
    assert db.query(models.HostInterface).filter_by(host_id=host.id).count() == 0
    assert db.query(models.HostListeningPort).filter_by(host_id=host.id).count() == 0


# ---------- Proxmox refresh + the view ----------

@pytest.fixture
def lab(db):
    """
    A two-node cluster with VLAN bridges: vmbr20 over eno1.20 on both
    nodes, untagged vmbr0, and one VLAN-aware bridge. Returns a dict of
    the moving parts so tests can adjust them.
    """
    proxmox_inventory.clear_cache()
    base = 60000 + uuid.uuid4().int % 30000
    vm_web, vm_dual, vm_stray, vm_ct = base, base + 1, base + 2, base + 3
    macs = {k: _mac() for k in ("web", "dual_a", "dual_b", "stray", "ct")}
    resources = [
        {"type": "node", "node": "pve1", "status": "online"},
        {"type": "node", "node": "pve2", "status": "online"},
        {"type": "qemu", "vmid": vm_web, "name": "web", "node": "pve1", "status": "running"},
        {"type": "qemu", "vmid": vm_dual, "name": "gateway", "node": "pve2", "status": "running"},
        {"type": "qemu", "vmid": vm_stray, "name": "stray", "node": "pve1", "status": "running"},
        {"type": "lxc", "vmid": vm_ct, "name": "ct", "node": "pve2", "status": "running"},
    ]
    node_net = [
        {"iface": "eno1.20", "type": "vlan", "vlan-id": "20"},
        {"iface": "vmbr0", "type": "bridge", "bridge_ports": "eno1", "cidr": "10.70.0.2/24"},
        {"iface": "vmbr20", "type": "bridge", "bridge_ports": "eno1.20"},
        {"iface": "vmbr9", "type": "bridge", "bridge_ports": "eno2", "bridge_vlan_aware": 1},
    ]
    configs = {
        vm_web: {"net0": f"virtio={macs['web'].upper()},bridge=vmbr20"},
        vm_dual: {"net0": f"virtio={macs['dual_a']},bridge=vmbr20", "net1": f"virtio={macs['dual_b']},bridge=vmbr0"},
        vm_stray: {"net0": f"virtio={macs['stray']},bridge=vmbr9,tag=30"},
        vm_ct: {"net0": f"name=eth0,bridge=vmbr0,hwaddr={macs['ct']},ip=10.70.0.40/24"},
    }
    state = {"resources": resources, "configs": configs, "fail_vmids": set()}

    def guest_config(cfg, node, vmid, guest_type):
        if vmid in state["fail_vmids"]:
            raise ProxmoxError("500")
        return state["configs"].get(vmid, {})

    with patch("app.rollback.resolve_proxmox_config", return_value=_CFG), \
         patch("app.proxmox.list_cluster_resources", side_effect=lambda cfg: list(state["resources"])), \
         patch("app.proxmox.list_node_network", side_effect=lambda cfg, node: node_net), \
         patch("app.proxmox.get_guest_config", side_effect=guest_config):
        yield dict(state, vm_web=vm_web, vm_dual=vm_dual, vm_stray=vm_stray, vm_ct=vm_ct, macs=macs)
    proxmox_inventory.clear_cache()


def _bridge(view, node, key):
    n = next(n for n in view["nodes"] if n["name"] == node)
    return next(b for b in n["networks"] if b["key"] == f"{n['key']}/{key}")


def _member(bridge, key):
    return next(m for m in bridge["members"] if (f"host:{m['host']['id']}" if m.get("host") else f"vm:{m['vmid']}") == key)


def test_topology_puts_guests_under_their_bridges_with_agent_ips(client, logged_in, db, lab):
    web, web_secret = make_host(db)
    web.proxmox_vmid = lab["vm_web"]
    dual, dual_secret = make_host(db)
    dual.proxmox_vmid = lab["vm_dual"]
    db.commit()
    _report(client, web, web_secret, _net(
        ifaces=[{"name": "eth0", "mac": lab["macs"]["web"], "addresses": ["10.70.20.5/24"]},
                {"name": "docker0", "mac": _mac(), "kind": "bridge", "addresses": ["172.17.0.1/16"]}],
        listening=[_sock(22), _sock(443, address="10.70.20.5", process="nginx"),
                   _sock(5432, address="127.0.0.1", loopback=True)]))
    _report(client, dual, dual_secret, _net(
        ifaces=[{"name": "eth0", "mac": lab["macs"]["dual_a"], "addresses": ["10.70.20.1/24"]},
                {"name": "eth1", "mac": lab["macs"]["dual_b"], "addresses": ["10.70.0.1/24"]}],
        listening=[_sock(53, proto="udp", address="10.70.20.1", process="dnsmasq")]))
    network_inventory.refresh(db)

    logged_in("operator")
    view = client.get("/topology").json()
    vlan20 = _bridge(view, "pve1", "vmbr20")
    assert vlan20["label"] == "VLAN 20 · vmbr20" and vlan20["vlan_id"] == 20 and "10.70.20.0/24" in vlan20["subnets"]
    m = _member(vlan20, f"host:{web.id}")
    assert m["ips"] == ["10.70.20.5/24"] and m["ip_source"] == "agent"
    assert [p["port"] for p in m["ports"]] == [22, 443]          # loopback 5432 excluded
    assert m["host"]["network_ok"] is True and m["multi_homed"] is False

    # a NIC per bridge: the dual-homed VM sits under both, each with its own IP and ports
    on20, on0 = _member(_bridge(view, "pve2", "vmbr20"), f"host:{dual.id}"), _member(_bridge(view, "pve2", "vmbr0"), f"host:{dual.id}")
    assert on20["multi_homed"] and on0["multi_homed"]
    assert on20["ips"] == ["10.70.20.1/24"] and on0["ips"] == ["10.70.0.1/24"]
    assert [p["port"] for p in on20["ports"]] == [53] and on0["ports"] == []  # bound to the VLAN 20 address only

    untagged = _bridge(view, "pve2", "vmbr0")
    assert untagged["label"] == "vmbr0" and untagged["note"] == "on eno1" and untagged["kind"] == "bridge"
    ct = _member(untagged, f"vm:{lab['vm_ct']}")
    assert ct["ips"] == ["10.70.0.40/24"] and ct["ip_source"] == "proxmox" and ct["multi_homed"] is False

    # the VLAN-aware bridge splits by the NIC's tag; an unmanaged VM still shows where it is
    stray = _member(_bridge(view, "pve1", "vmbr9.30"), f"vm:{lab['vm_stray']}")
    assert stray["coverage"] == "unmanaged" and stray["ips"] == []
    assert _bridge(view, "pve1", "vmbr9.30")["label"] == "VLAN 30 · vmbr9"
    assert vlan20["summary"]["listening"] == 2


def test_a_guest_without_nics_read_goes_under_not_read_yet(client, logged_in, db, lab):
    lab["configs"].pop(lab["vm_stray"])
    lab["fail_vmids"].add(lab["vm_stray"])
    db.query(models.ProxmoxGuestNic).filter_by(vmid=lab["vm_stray"]).delete()
    db.commit()
    network_inventory.refresh(db)
    logged_in("operator")
    unknown = _bridge(client.get("/topology").json(), "pve1", "?")
    assert unknown["kind"] == "unknown" and unknown["label"] == "Network not read yet"
    assert _member(unknown, f"vm:{lab['vm_stray']}")["nic"] is None


def test_refresh_keeps_unreadable_guests_and_drops_deleted_ones(db, lab):
    network_inventory.refresh(db)
    assert db.query(models.ProxmoxGuestNic).filter_by(vmid=lab["vm_dual"]).count() == 2
    lab["fail_vmids"].add(lab["vm_dual"])
    lab["resources"][:] = [r for r in lab["resources"] if r.get("vmid") != lab["vm_stray"]]
    status = network_inventory.refresh(db)
    assert "500" in status["error"]
    assert db.query(models.ProxmoxGuestNic).filter_by(vmid=lab["vm_dual"]).count() == 2  # kept
    assert db.query(models.ProxmoxGuestNic).filter_by(vmid=lab["vm_stray"]).count() == 0  # gone from cluster


def test_network_endpoints_role_gate(client, logged_in, db, lab):
    host, _ = make_host(db)
    logged_in("viewer")
    assert client.post("/network/refresh").status_code == 403
    assert client.get(f"/hosts/{host.id}/network").status_code == 403
    logged_in("operator")
    status = client.post("/network/refresh").json()
    assert status["refreshed_at"] and status["error"] == ""
    assert client.get("/network").status_code in (404, 405)   # the old separate view is gone


def test_host_network_detail(client, logged_in, db, lab):
    host, secret = make_host(db)
    host.proxmox_vmid = lab["vm_web"]
    db.commit()
    network_inventory.refresh(db)
    _report(client, host, secret, _net(
        ifaces=[{"name": "eth0", "mac": lab["macs"]["web"], "addresses": ["10.70.20.5/24"]},
                {"name": "docker0", "mac": _mac(), "kind": "bridge", "addresses": ["172.17.0.1/16"]}],
        listening=[_sock(22), _sock(5432, address="127.0.0.1", loopback=True)]))
    logged_in("operator")
    data = client.get(f"/hosts/{host.id}/network").json()
    assert data["ok"] is True and data["default_gateway"] == "10.0.20.1"
    eth0 = next(i for i in data["interfaces"] if i["name"] == "eth0")
    assert eth0["proxmox"] == {"bridge": "vmbr20", "vlan_id": 20, "proxmox_iface": "net0", "firewall": False}
    assert next(i for i in data["interfaces"] if i["name"] == "docker0")["container"] is True
    assert {(p["port"], p["loopback"]) for p in data["listening"]} == {(22, False), (5432, True)}
    assert client.get("/hosts/999999/network").status_code == 404


def test_unreadable_bridge_config_says_vlan_unknown_not_untagged(client, logged_in, db, lab):
    with patch("app.proxmox.list_node_network", side_effect=ProxmoxError("403 Permission check failed")):
        status = network_inventory.refresh(db)
    assert "403" in status["error"]
    db.query(models.ProxmoxBridge).delete()
    db.commit()
    logged_in("operator")
    bridge = _bridge(client.get("/topology").json(), "pve1", "vmbr20")
    assert bridge["label"] == "vmbr20 · VLAN unknown" and "SDN.Audit" in bridge["note"]


def test_bridges_hidden_by_missing_sdn_audit_are_named(db, lab):
    """Proxmox 8+ answers a token without SDN.Audit with physical NICs only."""
    nics_only = [{"iface": "nic0", "type": "eth"}, {"iface": "nic1", "type": "eth"}]
    with patch("app.proxmox.list_node_network", side_effect=lambda cfg, node: nics_only):
        status = network_inventory.refresh(db)
    assert "SDN.Audit" in status["error"] and "vmbr20" in status["error"]


def test_bridge_names_lead_with_the_proxmox_comment():
    meta = network_inventory._bridge_meta
    internal = meta(models.ProxmoxBridge(name="vmbr1", ports="", comments="Servers"))
    assert internal == {"label": "Servers · vmbr1", "kind": "internal", "note": "internal — no physical port"}
    lan = meta(models.ProxmoxBridge(name="vmbr0", ports="nic0", comments=""))
    assert lan == {"label": "vmbr0", "kind": "bridge", "note": "on nic0"}
    aware = meta(models.ProxmoxBridge(name="vmbr9", ports="eno2", vlan_aware=True, comments="Trunk"))
    assert aware["label"] == "Trunk · vmbr9" and "VLAN-aware" in aware["note"]




def test_an_unenrolled_vm_on_several_bridges_is_marked(client, logged_in, db, lab):
    lab["configs"][lab["vm_stray"]] = {"net0": "virtio=BC:24:11:77:77:01,bridge=vmbr20",
                                       "net1": "virtio=BC:24:11:77:77:02,bridge=vmbr0"}
    network_inventory.refresh(db)
    logged_in("operator")
    view = client.get("/topology").json()
    for key in ("vmbr20", "vmbr0"):
        assert _member(_bridge(view, "pve1", key), f"vm:{lab['vm_stray']}")["multi_homed"] is True
