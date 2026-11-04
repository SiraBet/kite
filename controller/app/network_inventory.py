"""
Network discovery: which network every machine sits on, its addresses,
and what it listens on -- kept current without anyone maintaining it.

Two sources, joined by MAC address:

  - Proxmox, polled by network_loop(): each node's bridges (and, on a
    non-VLAN-aware setup, the `ethX.N` port that makes a bridge VLAN N),
    and each guest's NICs (netN: MAC, bridge, VLAN tag). Known for every
    guest, enrolled or not.
  - The agent (0.1.8+), with each inventory report: the host's own
    interfaces and addresses, and its listening sockets -- see
    routers/agent.py's _store_network.

A guest NIC's MAC matches one of its host's interfaces, which puts that
interface's addresses on that NIC's network. Hosts Proxmox doesn't know
(bare metal, unlinked) are placed by subnet instead.

Read-only throughout, like the rest of the Proxmox integration: the
token needs Sys.Audit (node network config) and VM.Audit (guest config),
both already part of the documented role.
"""
import asyncio
import ipaddress
import re
import threading
from datetime import datetime

from sqlalchemy.orm import Session

from . import friendly_errors, models, proxmox
from .proxmox_connections import effective_connection_id, list_connections
from .logging_config import logger

# How often the Proxmox side is re-read. One call per node plus one per
# guest, so this is kept well away from the 60s cache the coverage and
# topology views use; agent-reported facts refresh on every poll anyway.
REFRESH_SECONDS = 600
STARTUP_DELAY_SECONDS = 20

_status = {"refreshed_at": None, "error": "", "running": False}
_refresh_lock = threading.Lock()

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_NET_KEY_RE = re.compile(r"^net\d+$")
# Interfaces that belong to container runtimes and overlays rather than
# to the network the machine is plugged into. Their subnets (172.17/16 on
# every Docker host) would otherwise show up as networks of their own.
_CONTAINER_IFACE_PREFIXES = ("docker", "br-", "cni", "flannel", "cali", "virbr", "podman",
                             "lxcbr", "kube", "veth", "weave", "cilium", "vxlan")
_WILDCARD = {"0.0.0.0", "::"}


def refresh_status() -> dict:
    return dict(_status)


# ---------- parsing Proxmox config ----------

def parse_net_line(value: str) -> dict:
    """
    One netN value from a guest config into {mac, bridge, vlan_tag,
    firewall, ip}. QEMU writes 'virtio=BC:24:11:..,bridge=vmbr20,tag=20';
    LXC writes 'name=eth0,bridge=vmbr0,hwaddr=BC:..,ip=10.0.0.5/24'.
    """
    out = {"mac": "", "bridge": "", "vlan_tag": None, "firewall": False, "ip": ""}
    for part in (value or "").split(","):
        key, _, val = part.partition("=")
        key, val = key.strip(), val.strip()
        if _MAC_RE.match(val.lower()) and not out["mac"]:
            out["mac"] = val.lower()  # QEMU's model=MAC, or LXC's hwaddr=MAC
        elif key == "bridge":
            out["bridge"] = val
        elif key == "tag" and val.isdigit():
            out["vlan_tag"] = int(val)
        elif key == "firewall":
            out["firewall"] = val == "1"
        elif key == "ip" and val not in ("dhcp", "manual", "auto"):
            out["ip"] = val
    return out


def _vlan_of_port(port: str, vlan_ifaces: dict):
    """The VLAN id a bridge port carries: an `eno1.20` / `vlan20` interface."""
    if port in vlan_ifaces:
        vid = vlan_ifaces[port].get("vlan-id")
        if str(vid).isdigit():
            return int(vid)
    m = re.match(r"^.+\.(\d+)$", port) or re.match(r"^vlan(\d+)$", port)
    return int(m.group(1)) if m else None


def parse_bridges(rows: list) -> list:
    """
    A node's bridges from its network config, each with the VLAN it
    carries. On a non-VLAN-aware bridge over `eno1.20`, that's 20; over a
    plain NIC or bond, it's untagged (None). A VLAN-aware bridge carries
    many, so its guests' own tag= decides instead.
    """
    vlan_ifaces = {r.get("iface"): r for r in rows if r.get("type") == "vlan"}
    out = []
    for r in rows:
        if r.get("type") != "bridge":
            continue
        ports = (r.get("bridge_ports") or "").split()
        vids = {v for v in (_vlan_of_port(p, vlan_ifaces) for p in ports) if v is not None}
        cidr = r.get("cidr") or ""
        if not cidr and r.get("address") and r.get("netmask"):
            try:
                cidr = str(ipaddress.ip_interface(f"{r['address']}/{r['netmask']}"))
            except ValueError:
                cidr = ""
        out.append({
            "name": r.get("iface", ""),
            "vlan_id": vids.pop() if len(vids) == 1 else None,
            "vlan_aware": bool(r.get("bridge_vlan_aware")),
            "ports": " ".join(ports),
            "cidr": cidr,
            "comments": (r.get("comments") or "").strip()[:200],
        })
    return out


# ---------- the refresh pass ----------

def refresh(db: Session) -> dict:
    """
    Re-read bridges and guest NICs from every Proxmox connection and store
    them, each row tagged with its connection. A connection, node or guest
    that can't be read keeps its previous rows rather than losing them --
    the same "could not tell is not nothing" rule as everywhere.
    """
    conns = list_connections(db)
    if not conns:
        _status.update(refreshed_at=datetime.utcnow(), error="Proxmox is not configured")
        return refresh_status()
    errors = []
    several = len(conns) > 1
    for conn in conns:
        label = f"{conn.name}: " if several else ""
        if not conn.configured:
            errors.append(f"{label}connection is incomplete")
            continue
        try:
            errors += [label + e for e in _refresh_connection(db, conn, only=not several)]
        except (proxmox.ProxmoxError, OSError) as e:
            errors.append(label + friendly_errors.report(e, context=f"network refresh {conn.name}"))
    _status.update(refreshed_at=datetime.utcnow(),
                   error="; ".join(errors[:3]) + (f" (+{len(errors) - 3} more)" if len(errors) > 3 else ""))
    if errors:
        logger.warning("network_refresh_incomplete error=%s", _status["error"])
    return refresh_status()


def _refresh_connection(db: Session, conn, only: bool = True) -> list:
    """One connection's pass. Returns its non-fatal errors."""
    cfg, cid = conn.cfg, conn.id
    rows = proxmox.list_cluster_resources(cfg)
    now = datetime.utcnow()
    errors = []
    all_nodes = {r["node"] for r in rows if r.get("type") == "node"}
    online = {r["node"] for r in rows if r.get("type") == "node" and r.get("status") == "online"}

    bridges_by_node = {}
    for node in sorted(online):
        try:
            bridges_by_node[node] = parse_bridges(proxmox.list_node_network(cfg, node))
        except (proxmox.ProxmoxError, OSError) as e:
            errors.append(f"node {node}: " + friendly_errors.report(e, context=f"network of node {node}"))

    nics, read_ok = [], set()
    for g in rows:
        if g.get("type") not in ("qemu", "lxc") or g.get("template") or g.get("node") not in online:
            continue
        try:
            conf = proxmox.get_guest_config(cfg, g["node"], g["vmid"], g["type"])
        except (proxmox.ProxmoxError, OSError) as e:
            errors.append(f"VM {g['vmid']}: " + friendly_errors.report(e, context=f"config of VM {g['vmid']}"))
            continue
        read_ok.add(g["vmid"])
        for key, value in conf.items():
            if _NET_KEY_RE.match(key):
                nic = parse_net_line(value)
                nics.append(models.ProxmoxGuestNic(
                    connection_id=cid, vmid=g["vmid"], node=g["node"], guest_type=g["type"], iface=key,
                    mac=nic["mac"], bridge=nic["bridge"], vlan_tag=nic["vlan_tag"], firewall=nic["firewall"],
                    config_ip=nic["ip"], refreshed_at=now))

    # Replace what was read; drop what no longer exists; keep the rest --
    # all within this connection. Rows from before connections existed
    # (connection_id None) belong to the only connection there was.
    existing_vmids = {g.get("vmid") for g in rows if g.get("type") in ("qemu", "lxc")}
    mine = lambda row: row.connection_id == cid or (row.connection_id is None and only)  # noqa: E731
    for row in db.query(models.ProxmoxGuestNic).all():
        if mine(row) and (row.vmid in read_ok or row.vmid not in existing_vmids):
            db.delete(row)
    db.add_all(nics)
    for row in db.query(models.ProxmoxBridge).all():
        if mine(row) and (row.node in bridges_by_node or row.node not in all_nodes):
            db.delete(row)
    for node, bridges in bridges_by_node.items():
        db.add_all(models.ProxmoxBridge(connection_id=cid, node=node, refreshed_at=now, **b) for b in bridges)
    db.commit()

    # Nodes answered, guests sit on bridges, but no bridge came back: that's
    # Proxmox 8+ filtering bridges (SDN resources) out of the listing for a
    # token without SDN.Audit -- an empty answer, not an error, so say so.
    used = {n.bridge for n in nics if n.bridge}
    if bridges_by_node and used and not any(bridges_by_node.values()):
        errors.insert(0, "Proxmox listed no bridges, though guests use " + ", ".join(sorted(used)[:5])
                      + " — the API token needs SDN.Audit to see them "
                      + "(pveum role modify <role> --privs SDN.Audit --append 1)")
    return errors


def refresh_now() -> dict:
    """One refresh pass with its own session; skipped if one is running."""
    from .db import SessionLocal
    if not _refresh_lock.acquire(blocking=False):
        return dict(refresh_status(), running=True)
    _status["running"] = True
    try:
        db = SessionLocal()
        try:
            return refresh(db)
        except (proxmox.ProxmoxError, OSError) as e:
            _status.update(refreshed_at=datetime.utcnow(), error=friendly_errors.report(e, context="network refresh"))
            return refresh_status()
        finally:
            db.close()
    finally:
        _status["running"] = False
        _refresh_lock.release()


async def network_loop():
    """Background refresh. HTTP-bound, so it runs off the event loop."""
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            await asyncio.to_thread(refresh_now)
        except Exception:  # noqa: BLE001 — one bad pass must never kill the loop
            logger.exception("network refresh failed")
        await asyncio.sleep(REFRESH_SECONDS)


# ---------- helpers shared with the Topology tree (proxmox_inventory) ----------

def _bridge_meta(br: models.ProxmoxBridge) -> dict:
    """
    How to name a bridge that carries no VLAN. Its Proxmox comment is the
    name people actually use ("Servers", "DMZ"), so that leads. A bridge
    with no physical port is an internal network that exists only inside
    the host -- isolation by design, not "untagged" traffic.
    """
    name = br.name or "?"
    label = f"{br.comments} · {name}" if br.comments else name
    if not br.ports:
        return {"label": label, "kind": "internal", "note": "internal — no physical port"}
    if br.vlan_aware:
        return {"label": label, "kind": "bridge", "note": f"VLAN-aware on {br.ports}, untagged traffic"}
    return {"label": label, "kind": "bridge", "note": f"on {br.ports}"}


def _ip(cidr: str) -> str:
    return cidr.split("/", 1)[0]


def _subnet(cidr: str):
    try:
        return ipaddress.ip_interface(cidr).network
    except ValueError:
        return None


def _usable_interface(iface: models.HostInterface) -> bool:
    return bool(iface.address_list) and not iface.name.startswith(_CONTAINER_IFACE_PREFIXES)


def _ports_on(ports: list, ips: list) -> list:
    """Non-loopback listeners reachable on these addresses: bound to one of them, or to every interface."""
    bare = {_ip(a) for a in ips}
    return [{"proto": p.proto, "port": p.port, "address": p.address, "process": p.process,
             "first_seen": p.first_seen}
            for p in sorted(ports, key=lambda p: (p.port, p.proto))
            if not p.loopback and (p.address in _WILDCARD or p.address in bare)]


def host_network(db: Session, host: models.Host) -> dict:
    """One host's interfaces (each with the network it's on, when known) and listening sockets."""
    conns = list_connections(db)
    eff = lambda cid: effective_connection_id(cid, conns)  # noqa: E731
    host_conn = eff(host.proxmox_connection_id)
    nic_by_mac = {}
    if host.proxmox_vmid:
        for n in db.query(models.ProxmoxGuestNic).filter(models.ProxmoxGuestNic.vmid == host.proxmox_vmid).all():
            if eff(n.connection_id) == host_conn:
                nic_by_mac[n.mac] = n
    bridges = {(b.node, b.name): b for b in db.query(models.ProxmoxBridge).all() if eff(b.connection_id) == host_conn}

    def where(iface):
        nic = nic_by_mac.get(iface.mac)
        if not nic:
            return None
        br = bridges.get((nic.node, nic.bridge))
        vid = nic.vlan_tag if nic.vlan_tag is not None else (br.vlan_id if br else None)
        return {"bridge": nic.bridge, "vlan_id": vid, "proxmox_iface": nic.iface, "firewall": nic.firewall}

    ifaces = db.query(models.HostInterface).filter(models.HostInterface.host_id == host.id).order_by(models.HostInterface.name).all()
    socks = (db.query(models.HostListeningPort).filter(models.HostListeningPort.host_id == host.id)
             .order_by(models.HostListeningPort.port, models.HostListeningPort.proto).all())
    return {
        "ok": host.network_ok, "error": host.network_error or "", "reported_at": host.network_reported_at,
        "default_gateway": host.default_gateway or "",
        "interfaces": [{"name": i.name, "mac": i.mac, "kind": i.kind, "up": i.is_up, "addresses": i.address_list,
                        "container": i.name.startswith(_CONTAINER_IFACE_PREFIXES), "proxmox": where(i)}
                       for i in ifaces],
        "listening": [{"proto": p.proto, "address": p.address, "port": p.port, "process": p.process,
                       "loopback": p.loopback, "first_seen": p.first_seen, "last_seen": p.last_seen} for p in socks],
    }
