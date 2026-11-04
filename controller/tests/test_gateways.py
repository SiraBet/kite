"""
Gateways in Topology (proxmox_inventory._promote_gateways and the
/proxmox/gateway endpoints): a router/firewall VM with a NIC on every
zone is drawn once, above the bridges it routes, instead of as a tile
under each. Tagged in Proxmox, or promoted by a person; otherwise only
suggested.

One node: an uplink bridge with a physical port and two internal
bridges, a firewall VM on all three, and a server on each internal one.
Proxmox is mocked at its client calls; vmids are unique to this file.
"""
import uuid
from unittest.mock import patch

import pytest

from app import models, network_inventory, proxmox_inventory
from app.proxmox import ProxmoxConfig

_CFG = ProxmoxConfig(host="10.0.0.5", node="gwnode", token_id="t", token_secret="s")


def _mac():
    h = uuid.uuid4().hex
    return "bc:24:" + ":".join(h[i:i + 2] for i in range(0, 8, 2))


@pytest.fixture
def zones(db):
    proxmox_inventory.clear_cache()
    base = 40000 + uuid.uuid4().int % 15000
    fw, app_vm, db_vm, inner = base, base + 1, base + 2, base + 3
    resources = [
        {"type": "node", "node": "gwnode", "status": "online"},
        {"type": "qemu", "vmid": fw, "name": "edge-fw", "node": "gwnode", "status": "running"},
        {"type": "qemu", "vmid": app_vm, "name": "app", "node": "gwnode", "status": "running"},
        {"type": "qemu", "vmid": db_vm, "name": "store", "node": "gwnode", "status": "running"},
    ]
    node_net = [
        {"iface": "vmbr0", "type": "bridge", "bridge_ports": "eno1"},
        {"iface": "vmbr1", "type": "bridge", "bridge_ports": ""},
        {"iface": "vmbr2", "type": "bridge", "bridge_ports": ""},
    ]
    configs = {
        fw: {"net0": f"virtio={_mac()},bridge=vmbr0", "net1": f"virtio={_mac()},bridge=vmbr1",
             "net2": f"virtio={_mac()},bridge=vmbr2"},
        app_vm: {"net0": f"virtio={_mac()},bridge=vmbr1"},
        db_vm: {"net0": f"virtio={_mac()},bridge=vmbr2"},
    }
    state = {"resources": resources, "configs": configs}
    with patch("app.rollback.resolve_proxmox_config", return_value=_CFG), \
         patch("app.proxmox.list_cluster_resources", side_effect=lambda cfg: list(state["resources"])), \
         patch("app.proxmox.list_node_network", side_effect=lambda cfg, node: node_net), \
         patch("app.proxmox.get_guest_config", side_effect=lambda cfg, node, vmid, t: state["configs"].get(vmid, {})):
        network_inventory.refresh(db)
        yield dict(state, fw=fw, app=app_vm, db=db_vm, inner=inner)
    db.query(models.ProxmoxGuestFlag).filter(models.ProxmoxGuestFlag.vmid.in_([fw, inner])).delete(
        synchronize_session=False)
    db.commit()
    proxmox_inventory.clear_cache()


def _tag(zones, vmid, tags="kite-gateway"):
    next(r for r in zones["resources"] if r.get("vmid") == vmid)["tags"] = tags


def _node(client):
    return next(n for n in client.get("/topology?refresh=true").json()["nodes"] if n["name"] == "gwnode")


def _net(node, bridge):
    return next(n for n in node["networks"] if n["key"] == f"{node['key']}/{bridge}")


def _vmids(net):
    return [m["vmid"] for m in net["members"]]


def test_untagged_firewall_stays_under_each_bridge_with_a_suggestion(client, logged_in, zones):
    logged_in("operator")
    node = _node(client)
    assert node["gateways"] == []
    for br in ("vmbr0", "vmbr1", "vmbr2"):
        fw = next(m for m in _net(node, br)["members"] if m["vmid"] == zones["fw"])
        assert "uplink bridge" in fw["gateway_suggestion"]
    assert all(n["depth"] == 0 for n in node["networks"])


def test_a_tagged_gateway_is_drawn_once_above_the_zones_it_routes(client, logged_in, zones):
    _tag(zones, zones["fw"], "prod;Kite-Gateway")
    logged_in("operator")
    node = _node(client)
    [gw] = node["gateways"]
    assert gw["vmid"] == zones["fw"] and gw["source"] == "tag" and gw["coverage"] == "gateway"
    assert gw["parent"] == f"{node['key']}/vmbr0"
    assert sorted(gw["routed"]) == [f"{node['key']}/vmbr1", f"{node['key']}/vmbr2"]
    assert {i["bridge"]: i["role"] for i in gw["interfaces"]} == {"vmbr0": "uplink", "vmbr1": "routes", "vmbr2": "routes"}
    # not a tile anywhere any more
    assert all(zones["fw"] not in _vmids(n) for n in node["networks"])
    assert _vmids(_net(node, "vmbr1")) == [zones["app"]] and _vmids(_net(node, "vmbr2")) == [zones["db"]]
    # the tree: uplink at the top, the routed zones one level down, right after it
    assert [n["key"].split("/")[-1] for n in node["networks"]][0] == "vmbr0"
    assert _net(node, "vmbr0")["depth"] == 0 and _net(node, "vmbr1")["depth"] == 1
    assert _net(node, "vmbr1")["parent_gateway"] == gw["key"]
    # a gateway with no agent isn't a coverage gap
    assert node["blast_radius"]["unmanaged"] == 2
    cov = client.get("/proxmox/coverage?refresh=true").json()
    assert next(g for g in cov["guests"] if g["vmid"] == zones["fw"])["coverage"] == "gateway"
    assert cov["summary"]["gateways"] >= 1


def test_promote_dismiss_and_back_to_automatic(client, logged_in, zones):
    logged_in("operator")
    assert client.post("/proxmox/gateway", json={"vmid": zones["fw"], "gateway": True}).status_code == 403
    logged_in("lead")
    assert client.post("/proxmox/gateway", json={"vmid": zones["fw"], "gateway": True}).status_code == 200
    [gw] = _node(client)["gateways"]
    assert gw["source"] == "marked"

    assert client.post("/proxmox/gateway", json={"vmid": zones["fw"], "gateway": False}).status_code == 200
    node = _node(client)
    assert node["gateways"] == []
    fw = next(m for m in _net(node, "vmbr1")["members"] if m["vmid"] == zones["fw"])
    assert "gateway_suggestion" not in fw and fw["gateway_dismissed"]

    assert client.delete(f"/proxmox/gateway/{zones['fw']}").status_code == 200
    assert client.delete(f"/proxmox/gateway/{zones['fw']}").status_code == 404
    fw = next(m for m in _net(_node(client), "vmbr1")["members"] if m["vmid"] == zones["fw"])
    assert fw["gateway_suggestion"]


def test_the_tag_wins_over_a_dismissal(client, logged_in, zones):
    logged_in("lead")
    client.post("/proxmox/gateway", json={"vmid": zones["fw"], "gateway": False})
    _tag(zones, zones["fw"])
    assert [g["source"] for g in _node(client)["gateways"]] == ["tag"]


def test_a_router_behind_a_router_hangs_under_the_zone_it_sits_in(client, logged_in, zones, db):
    # the edge firewall routes vmbr1; an inner router on vmbr1 and vmbr2 routes vmbr2
    zones["resources"].append({"type": "qemu", "vmid": zones["inner"], "name": "lab-router", "node": "gwnode",
                               "status": "running", "tags": "kite-gateway"})
    zones["configs"][zones["fw"]] = {"net0": f"virtio={_mac()},bridge=vmbr0", "net1": f"virtio={_mac()},bridge=vmbr1"}
    zones["configs"][zones["inner"]] = {"net0": f"virtio={_mac()},bridge=vmbr1", "net1": f"virtio={_mac()},bridge=vmbr2"}
    _tag(zones, zones["fw"])
    network_inventory.refresh(db)
    logged_in("operator")
    node = _node(client)
    gws = {g["vmid"]: g for g in node["gateways"]}
    assert gws[zones["inner"]]["parent"] == f"{node['key']}/vmbr1"
    assert gws[zones["inner"]]["routed"] == [f"{node['key']}/vmbr2"]
    assert _net(node, "vmbr2")["depth"] == 2 and gws[zones["inner"]]["depth"] == 1


def test_a_gateway_with_no_uplink_hangs_off_the_node(client, logged_in, zones, db):
    zones["configs"][zones["fw"]] = {"net0": f"virtio={_mac()},bridge=vmbr1", "net1": f"virtio={_mac()},bridge=vmbr2"}
    _tag(zones, zones["fw"])
    network_inventory.refresh(db)
    logged_in("operator")
    node = _node(client)
    [gw] = node["gateways"]
    assert gw["parent"] is None and gw["depth"] == 0
    assert _net(node, "vmbr1")["depth"] == 1


def test_a_router_like_name_is_only_a_suggestion(client, logged_in, zones, db):
    # two internal bridges, no uplink: the bridge rule doesn't fire, the name does
    zones["configs"][zones["fw"]] = {"net0": f"virtio={_mac()},bridge=vmbr1", "net1": f"virtio={_mac()},bridge=vmbr2"}
    network_inventory.refresh(db)
    logged_in("operator")
    node = _node(client)
    assert node["gateways"] == []
    fw = next(m for m in _net(node, "vmbr1")["members"] if m["vmid"] == zones["fw"])
    assert "name looks like a router" in fw["gateway_suggestion"]
    assert proxmox_inventory._ROUTER_NAME_RE.search("pfsense-01")
    assert proxmox_inventory._ROUTER_NAME_RE.search("opnsense")
    assert not proxmox_inventory._ROUTER_NAME_RE.search("webfwd")     # "fw" only as a word
