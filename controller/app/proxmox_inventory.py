"""
Read-only views over the Proxmox cluster, joined against enrolled hosts:

  - coverage(): every guest Proxmox knows about, and whether kite
    manages it. The question this answers is "what in my cluster is
    going unpatched because nobody enrolled it?" -- the gap a patching
    tool cannot see from its own host list, by definition.
  - topology(): node -> guests -> enrolled host, with per-node blast
    radius, for the topology map. Rebooting a node takes every guest on
    it down at once, which is what you want to see before patching one.

Neither changes anything in Proxmox, and both work from the token the
snapshot backend already holds; they need only audit rights.

A page never waits on Proxmox. Each connection's /cluster/resources is
kept, and a request answers from it straight away; once it's older than
KITE_PROXMOX_CACHE_SECONDS (5 minutes), the request starts a fresh
fetch in the background and says so (`refreshing`), and the page asks
again shortly. Only the very first fetch, and an explicit Refresh, wait.
Each connection has its own lock, so a Proxmox that doesn't answer (up
to its 15 s timeout) holds up nobody else; and one that keeps failing is
retried after 1, 2, then every 5 minutes, not on every page view.

When Proxmox isn't configured or can't be reached, both still answer,
with that reason under `proxmox`. Topology falls back to each host's
pinned proxmox_node and otherwise lists the host as unplaced, so the
map degrades to what kite knows rather than to an error page.
"""
import os
import re
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from . import friendly_errors, models, monitoring, proxmox
from .proxmox_connections import effective_connection_id, list_connections
from .settings_store import get_setting

# How old a connection's guest list may get before a page view starts a
# fresh fetch (in the background). Guests come and go on a scale of
# minutes, and Refresh is always there for "now".
CACHE_SECONDS = int(os.environ.get("KITE_PROXMOX_CACHE_SECONDS", "300"))
# After 1, 2, 3+ failed fetches in a row: how long until the next try.
RETRY_SECONDS = (60, 120, 300)


class _Entry:
    """One connection's guest list, and how fetching it last went."""

    def __init__(self):
        self.lock = threading.Lock()      # held while fetching, so one connection is fetched once at a time
        self.attempted = False
        self.at = 0.0                     # monotonic time of the last attempt
        self.fetched_at = None            # wall time of the last good fetch
        self.rows = []
        self.error = ""
        self.fails = 0                    # failed attempts in a row
        self.refreshing = False           # a background fetch is running


_entries = {}  # (host, token_id) -> _Entry
_entries_lock = threading.Lock()          # only for the dict and the refreshing flag: never held over a fetch


def clear_cache():
    with _entries_lock:
        _entries.clear()


def _wait_seconds(e: _Entry) -> float:
    """How long after the last attempt the next one is due."""
    return RETRY_SECONDS[min(e.fails, len(RETRY_SECONDS)) - 1] if e.fails else CACHE_SECONDS


def _load(cfg, e: _Entry):
    """Fetch now. Called with e.lock held."""
    try:
        e.rows, e.fetched_at, e.error, e.fails = proxmox.list_cluster_resources(cfg), datetime.utcnow(), "", 0
    except (proxmox.ProxmoxError, OSError) as exc:
        # OSError covers requests' connection errors, which subclass it. The
        # last good rows stay, with the error to say they're old.
        e.error = friendly_errors.report(exc, context=f"proxmox inventory {cfg.host}")
        e.fails += 1
    e.at, e.attempted = time.monotonic(), True


def _load_in_background(cfg, e: _Entry):
    try:
        with e.lock:
            _load(cfg, e)
    finally:
        with _entries_lock:
            e.refreshing = False


def _connection_rows(conn, refresh: bool = False):
    """
    One connection's (status, rows): rows is its /cluster/resources list.

    A failed fetch still returns the last good rows when there are any,
    with `error` set and `stale` true: a cluster that was readable nine
    minutes ago is a better picture than an empty page, as long as the
    page says how old it is (fetched_at stays the time of that last good
    fetch). rows is [] only when there has never been a good fetch.
    """
    status = {"connection_id": conn.id, "name": conn.name, "configured": conn.configured,
              "host": conn.cfg.host or "", "nodes": 0, "error": "", "stale": False, "fetched_at": None,
              "cached": False, "refreshing": False, "retry_in": None}
    if not conn.configured:
        status["error"] = "connection is incomplete — finish it in Settings → Connections"
        return status, []
    rows = _fetch(conn.cfg, refresh, status)
    status["nodes"] = sum(1 for r in rows if r.get("type") == "node")
    return status, rows


def _all_cluster_rows(db: Session, refresh: bool = False):
    """
    Every connection's rows, plus the combined `proxmox` status block the
    pages show. One connection failing doesn't blank the others: their
    data is still there, so the combined status reads as stale (data,
    with an error to explain), not as nothing at all.
    """
    conns = list_connections(db)
    per = [(c, *_connection_rows(c, refresh)) for c in conns]
    statuses = [s for _, s, _ in per]
    if not statuses:
        status = {"configured": False, "host": "", "nodes": 0, "error":
                  "Proxmox is not configured — add a connection in Settings → Connections",
                  "stale": False, "fetched_at": None, "cached": False, "refreshing": False, "retry_in": None}
    else:
        several = len(statuses) > 1
        errors = [f"{s['name']}: {s['error']}" if several else s["error"] for s in statuses if s["error"]]
        fetched = [s["fetched_at"] for s in statuses if s["fetched_at"]]
        status = {
            "configured": any(s["configured"] for s in statuses),
            "host": ", ".join(s["host"] for s in statuses if s["host"]),
            "nodes": sum(s["nodes"] for s in statuses),
            "error": "; ".join(errors),
            "stale": bool(errors) and any(rows for _, _, rows in per),
            "fetched_at": min(fetched) if fetched else None,
            "cached": all(s["cached"] for s in statuses),
            # a fresher list is on its way: the page asks again shortly
            "refreshing": any(s["refreshing"] for s in statuses),
            "retry_in": min((s["retry_in"] for s in statuses if s["retry_in"] is not None), default=None),
        }
    status["connections"] = statuses
    return conns, per, status


def _fetch(cfg, refresh: bool, status: dict) -> list:
    """
    The connection's guest list as last fetched, starting a background
    fetch when it's due. Waits only for an explicit refresh, and for the
    first fetch of all (there's nothing to show before it).
    """
    key = (cfg.host, cfg.token_id)
    with _entries_lock:
        e = _entries.setdefault(key, _Entry())
    if refresh or not e.attempted:
        with e.lock:
            if refresh or not e.attempted:   # a fetch that finished while we waited counts as the first
                _load(cfg, e)
    else:
        status["cached"] = True
        with _entries_lock:
            start = not e.refreshing and time.monotonic() - e.at >= _wait_seconds(e)
            if start:
                e.refreshing = True
        if start:
            threading.Thread(target=_load_in_background, args=(cfg, e), daemon=True,
                             name=f"proxmox-inventory-{cfg.host}").start()
    retry_in = max(0, int(e.at + _wait_seconds(e) - time.monotonic())) if e.error else None
    status.update(fetched_at=e.fetched_at, error=e.error, stale=bool(e.error and e.rows),
                  refreshing=e.refreshing, retry_in=retry_in)
    return e.rows


def _short_name(name: str) -> str:
    return (name or "").split(".")[0].strip().lower()


def _guest(row: dict, conn=None) -> dict:
    return {
        "connection_id": conn.id if conn else None,
        "connection": conn.name if conn else "",
        "vmid": row.get("vmid"),
        "name": row.get("name") or "",
        "node": row.get("node") or "",
        "type": row.get("type"),  # 'qemu' | 'lxc'
        "status": row.get("status") or "unknown",
        "template": bool(row.get("template")),
        "tags": [t for t in (row.get("tags") or "").replace(",", ";").split(";") if t],
    }


def _match(guests: list, hosts: list, ignored: dict, conns: list = (), answered: set = None):
    """
    Pair each guest with a host, and classify it:

      managed     a host has this guest's vmid recorded -- the link the
                  snapshot backend uses, so this is the authoritative one
      name_match  no host has the vmid, but exactly one host's short name
                  equals the guest's -- almost certainly the same machine,
                  just never linked (fixable with resolve-vmid)
      ignored     deliberately left out (ProxmoxIgnoredGuest)
      template    a template, which never runs and so never needs patching
      unmanaged   none of the above: Proxmox runs it, kite doesn't know it

    Also returns the stale links: hosts whose recorded vmid Proxmox did
    not report. Their snapshots will fail.

    A vmid only identifies a VM within one connection, so matching is by
    (connection, vmid); `ignored` is keyed the same way. `answered` is
    the connections that returned data -- a host on a connection that
    didn't answer isn't called stale, there's nothing to compare with.
    """
    conns = list(conns)
    eff = lambda cid: effective_connection_id(cid, conns)  # noqa: E731
    by_vmid = {(eff(h.proxmox_connection_id), h.proxmox_vmid): h for h in hosts if h.proxmox_vmid}
    by_name = defaultdict(list)
    for h in hosts:
        by_name[_short_name(h.hostname)].append(h)
    linked = set()

    for g in guests:
        key = (g.get("connection_id"), g["vmid"])
        host = by_vmid.get(key)
        if host:
            g["coverage"], g["host"] = "managed", host
            linked.add(key)
        elif g["template"]:
            g["coverage"], g["host"] = "template", None
        elif key in ignored:
            # Ahead of name_match: ignoring is an explicit decision, a
            # name match is only a guess.
            g["coverage"], g["host"] = "ignored", None
        elif len(by_name.get(_short_name(g["name"]), [])) == 1 and not by_name[_short_name(g["name"])][0].proxmox_vmid:
            g["coverage"], g["host"] = "name_match", by_name[_short_name(g["name"])][0]
        else:
            g["coverage"], g["host"] = "unmanaged", None
        g["ignore_reason"] = ignored[key].reason if key in ignored else ""
        g["ignored_by"] = ignored[key].created_by if key in ignored else ""

    answered = {c.id for c in conns} if answered is None else answered
    stale = [h for h in hosts if h.proxmox_vmid and (eff(h.proxmox_connection_id), h.proxmox_vmid) not in linked
             and (eff(h.proxmox_connection_id) in answered or eff(h.proxmox_connection_id) is None and answered)]
    return stale


# A VM tagged with this in Proxmox is a gateway, whatever else is stored --
# the portable way to say "this routes my zones", for any router/firewall.
GATEWAY_TAG = "kite-gateway"
# Names that suggest a router or firewall appliance. A suggestion only:
# promotion is always a person's decision (or the tag).
_ROUTER_NAME_RE = re.compile(
    r"(^|[^a-z])(pfsense|opnsense|vyos|openwrt|routeros|mikrotik|ipfire|sophos|fortigate|fortinet|untangle|"
    r"clearos|smoothwall|endian|firewall|router|gateway|fw|gw)([^a-z]|$)")


def _flag_map(db: Session, conns: list) -> dict:
    """Gateway promote/dismiss decisions keyed by (connection, vmid)."""
    return {(effective_connection_id(r.connection_id, conns), r.vmid): r
            for r in db.query(models.ProxmoxGuestFlag).all()}


def _is_gateway(g: dict, flags: dict) -> bool:
    if GATEWAY_TAG in [t.lower() for t in g.get("tags") or []]:
        return True
    flag = flags.get((g.get("connection_id"), g.get("vmid")))
    return bool(flag and flag.gateway)


def _apply_gateway_coverage(guests: list, flags: dict):
    """
    A gateway with no kite agent isn't a coverage gap -- routers and
    firewalls are patched through their own UI, by design. It reads as
    "gateway", not "unmanaged".
    """
    for g in guests:
        if _is_gateway(g, flags):
            tagged = GATEWAY_TAG in [t.lower() for t in g.get("tags") or []]
            g["gateway_source"] = "tag" if tagged else "marked"
            if g["coverage"] == "unmanaged":
                g["coverage"] = "gateway"


def _ignored_map(db: Session, conns: list) -> dict:
    """Ignored guests keyed by (connection, vmid), legacy rows resolved to the only connection."""
    return {(effective_connection_id(r.connection_id, conns), r.vmid): r
            for r in db.query(models.ProxmoxIgnoredGuest).all()}


_COVERAGE_ORDER = {"unmanaged": 0, "name_match": 1, "managed": 2, "gateway": 3, "ignored": 4, "template": 5}


def coverage(db: Session, refresh: bool = False) -> dict:
    conns, per, status = _all_cluster_rows(db, refresh)
    hosts = db.query(models.Host).all()
    ignored = _ignored_map(db, conns)
    guests = [_guest(r, c) for c, _, rows in per for r in rows if r.get("type") in ("qemu", "lxc")]
    # Stale links are only meaningful against real cluster data (fresh, or
    # the last good fetch) -- with none, every linked host would look stale.
    answered = {c.id for c, _, rows in per if rows}
    stale = _match(guests, hosts, ignored, conns, answered) if answered else []
    _apply_gateway_coverage(guests, _flag_map(db, conns))

    counts = defaultdict(int)
    for g in guests:
        counts[g["coverage"]] += 1
    summary = {
        "guests": len(guests),
        "managed": counts["managed"],
        "name_match": counts["name_match"],
        "unmanaged": counts["unmanaged"],
        "unmanaged_running": sum(1 for g in guests if g["coverage"] == "unmanaged" and g["status"] == "running"),
        "ignored": counts["ignored"],
        "gateways": counts["gateway"],
        "templates": counts["template"],
        "stale_links": len(stale),
    }
    guests.sort(key=lambda g: (_COVERAGE_ORDER[g["coverage"]], g["status"] != "running", g["node"], g["vmid"] or 0))
    for g in guests:
        host = g.pop("host")
        g["host"] = {"id": host.id, "hostname": host.hostname} if host else None
    return {
        "proxmox": status,
        "summary": summary,
        "guests": guests,
        "stale_links": [{"host_id": h.id, "hostname": h.hostname, "proxmox_vmid": h.proxmox_vmid,
                         "connection_id": effective_connection_id(h.proxmox_connection_id, conns),
                         "proxmox_node": h.proxmox_node} for h in stale],
    }


def _safety_net(backend: str, host: models.Host, guest_type: Optional[str]) -> str:
    """
    What a run on this host could actually fall back to: 'snapshot' (a
    full VM snapshot), 'package_history' (dnf transaction undo), or
    'none'. The proxmox backend only snapshots QEMU VMs with a vmid, so
    an LXC guest or an unlinked host on that backend has no net at all
    -- the case the blast radius exists to surface.
    """
    if backend == "proxmox":
        return "snapshot" if host.proxmox_vmid and guest_type in ("qemu", None) else "none"
    if backend == "dnf_history":
        return "package_history"
    return "none"


def _severity_counts(db: Session) -> dict:
    """host_id -> {severity: count}, one grouped query for the fleet."""
    out = defaultdict(dict)
    rows = (db.query(models.PendingUpdate.host_id, models.PendingUpdate.severity, func.count())
            .group_by(models.PendingUpdate.host_id, models.PendingUpdate.severity).all())
    for host_id, severity, count in rows:
        out[host_id][severity] = count
    return out


def _container_counts(db: Session) -> dict:
    out = defaultdict(lambda: {"total": 0, "running": 0, "updatable": 0, "update_available": 0})
    for c in db.query(models.Container).all():
        row = out[c.host_id]
        row["total"] += 1
        row["running"] += c.state == "running"
        row["updatable"] += c.updatable
        row["update_available"] += bool(c.update_available)
    return out


def _host_summary(host, default_backend, containers, severities, guest_type, placement) -> dict:
    # Same resolution as rollback.resolve_backend_name, with the global
    # default read once per request instead of once per host.
    backend = host.rollback_backend or default_backend
    return {
        "id": host.id,
        "hostname": host.hostname,
        "team": host.team or "",
        "role": host.role or "",
        "os_family": host.os_family or "",
        "connectivity": monitoring.connectivity_tier(host),
        "status": host.status,
        "pending_updates": getattr(host, "pending_updates", 0),
        "pending_by_severity": severities.get(host.id, {}),
        "max_severity": getattr(host, "max_severity", "none"),
        "updates_assessed_ok": host.updates_assessed_ok,
        "active_job_id": getattr(host, "active_job_id", None),
        "last_seen": host.last_seen,
        "last_patched": host.last_patched,
        "rollback_backend": backend,
        "safety_net": _safety_net(backend, host, guest_type),
        "containers": containers.get(host.id, {"total": 0, "running": 0, "updatable": 0, "update_available": 0}),
        "container_runtime": host.container_runtime or "",
        # None = the agent doesn't report network facts (older, or Windows).
        "network_ok": host.network_ok,
        "default_gateway": host.default_gateway or "",
        "placement": placement,  # 'live' (from Proxmox) | 'pinned' (Host.proxmox_node, Proxmox unavailable)
    }


def topology(db: Session, refresh: bool = False) -> dict:
    # Local import: the hosts router owns the batched pending-update and
    # active-job lookups, and importing it at module level would tie this
    # module's import to the router package's.
    from .routers.hosts import _attach_active_jobs, _attach_update_counts

    conns, per, status = _all_cluster_rows(db, refresh)
    hosts = _attach_update_counts(db, _attach_active_jobs(db, db.query(models.Host).all()))
    ignored = _ignored_map(db, conns)
    containers = _container_counts(db)
    severities = _severity_counts(db)
    default_backend = get_setting(db, "rollback_default_backend")

    guests = [_guest(r, c) for c, _, rows in per for r in rows if r.get("type") in ("qemu", "lxc")]
    answered = {c.id for c, _, rows in per if rows}
    _match(guests, hosts, ignored, conns, answered)
    flags = _flag_map(db, conns)
    _apply_gateway_coverage(guests, flags)
    conn_names = {c.id: c.name for c in conns}
    order = {c.id: i for i, c in enumerate(conns)}

    # Nodes are per connection: a standalone host and a cluster member can
    # both be called "pve".
    nodes = {}

    def node_for(conn_id, name):
        key = (conn_id, name)
        if key not in nodes:
            nodes[key] = {"key": f"{conn_id if conn_id is not None else 0}:{name}", "name": name,
                          "connection_id": conn_id, "connection": conn_names.get(conn_id, ""),
                          "status": "unknown", "maxcpu": None, "maxmem": None, "uptime": None,
                          "templates": 0, "template_list": [], "guests": []}
        return nodes[key]

    for c, _, rows in per:
        for r in rows:
            if r.get("type") == "node":
                node_for(c.id, r["node"]).update(status=r.get("status") or "unknown", maxcpu=r.get("maxcpu"),
                                                 maxmem=r.get("maxmem"), uptime=r.get("uptime"))

    placed = set()
    for g in guests:
        node = node_for(g["connection_id"], g["node"])
        if g["template"]:
            node["templates"] += 1
            node["template_list"].append({"vmid": g["vmid"], "name": g["name"], "type": g["type"]})
            continue
        host = g.pop("host")
        # Only a vmid link places a host on the map. A name match is shown
        # as a suggestion on the guest, not asserted as fact.
        g["host"] = _host_summary(host, default_backend, containers, severities, g["type"], "live") if g["coverage"] == "managed" else None
        g["suggested_host"] = {"id": host.id, "hostname": host.hostname} if g["coverage"] == "name_match" else None
        if g["coverage"] == "managed":
            placed.add(host.id)
        node["guests"].append(g)

    # No cluster data at all: place what we can from each host's pinned
    # node, so the map still shows the shape of the cluster.
    unplaced = []
    for h in hosts:
        if h.id in placed:
            continue
        conn_id = effective_connection_id(h.proxmox_connection_id, conns)
        if conn_id not in answered and h.proxmox_node:
            node_for(conn_id, h.proxmox_node)["guests"].append({
                "connection_id": conn_id, "connection": conn_names.get(conn_id, ""),
                "vmid": h.proxmox_vmid, "name": h.hostname, "node": h.proxmox_node, "type": None,
                "status": "unknown", "template": False, "tags": [], "coverage": "managed",
                "ignore_reason": "", "ignored_by": "", "suggested_host": None,
                "host": _host_summary(h, default_backend, containers, severities, None, "pinned"),
            })
        else:
            summary = _host_summary(h, default_backend, containers, severities, None, "none")
            # Why it isn't on the map, which decides what fixing it means.
            summary["unplaced_reason"] = (
                "proxmox_unavailable" if h.proxmox_vmid and conn_id is not None and conn_id not in answered
                else "proxmox_unavailable" if not answered
                else "stale_link" if h.proxmox_vmid
                else "not_linked")
            summary["proxmox_vmid"] = h.proxmox_vmid
            unplaced.append(summary)

    for node in nodes.values():
        managed = [g["host"] for g in node["guests"] if g["host"]]
        node["guests"].sort(key=lambda g: (g["host"] is None, g["vmid"] or 0))
        node["blast_radius"] = {
            "guests": len(node["guests"]),
            "running": sum(1 for g in node["guests"] if g["status"] == "running"),
            "managed": len(managed),
            "unmanaged": sum(1 for g in node["guests"] if g["coverage"] in ("unmanaged", "name_match")),
            "active_runs": sum(1 for h in managed if h["active_job_id"]),
            "no_snapshot": sum(1 for h in managed if h["safety_net"] != "snapshot"),
            "critical_pending": sum(1 for h in managed if h["max_severity"] == "critical"),
        }

    _attach_bridges(db, nodes, conns, flags)
    unplaced.sort(key=lambda h: h["hostname"])
    return {
        "proxmox": status,
        # One box per connection in the tree; nodes point back via connection_id.
        "clusters": [{"connection_id": s["connection_id"], "name": s["name"], "host": s["host"],
                      "error": s["error"], "stale": s["stale"], "nodes": s["nodes"]}
                     for s in status["connections"]],
        "nodes": sorted(nodes.values(), key=lambda n: (order.get(n["connection_id"], 99), n["name"])),
        "unplaced": unplaced,
    }


def _attach_bridges(db: Session, nodes: dict, conns: list = (), flags: dict = None):
    """
    The network level of the tree: node -> bridge -> guest. Each node gets
    `networks`, one per bridge its guests are plugged into (a VLAN-aware
    bridge splits by tag), from the NICs network_inventory reads out of
    Proxmox. A guest with NICs on several bridges -- a firewall with one
    per zone -- appears under each, marked multi_homed. A guest whose NICs
    haven't been read yet goes under "Network not read yet" rather than
    being dropped.

    Each appearance carries that NIC's addresses (the agent's interface
    with the same MAC, or an LXC's static ip=) and the ports listening on
    them, so one tile per network says what is reachable *there*.
    """
    from .network_inventory import _bridge_meta, _ports_on, _subnet

    conns = list(conns)
    eff = lambda cid: effective_connection_id(cid, conns)  # noqa: E731
    bridges = {(eff(b.connection_id), b.node, b.name): b for b in db.query(models.ProxmoxBridge).all()}
    nics = defaultdict(list)
    for n in db.query(models.ProxmoxGuestNic).order_by(models.ProxmoxGuestNic.iface).all():
        nics[(eff(n.connection_id), n.vmid)].append(n)
    ifaces = defaultdict(list)
    for i in db.query(models.HostInterface).all():
        ifaces[i.host_id].append(i)
    ports = defaultdict(list)
    for p in db.query(models.HostListeningPort).all():
        ports[p.host_id].append(p)

    flags = flags or {}
    for node in nodes.values():
        nets = {}
        placements = defaultdict(list)   # vmid -> [(local net key, bridge row or None, nic)]

        def net(key, _nets=nets, _node=node["key"], **meta):
            if key not in _nets:
                _nets[key] = dict({"key": f"{_node}/{key}", "kind": "bridge", "vlan_id": None, "note": "",
                                   "bridges": [], "subnets": set(), "members": []}, **meta)
            return _nets[key]

        for g in node["guests"]:
            host = g.get("host")
            guest_nics = nics.get((g.get("connection_id"), g["vmid"])) if g.get("vmid") is not None else None
            if not guest_nics:
                target = [(net("?", label="Network not read yet", kind="unknown",
                               note="this VM's NICs haven't been read from Proxmox"), None)]
            else:
                target = []
                for nic in guest_nics:
                    br = bridges.get((node["connection_id"], nic.node, nic.bridge))
                    vid = nic.vlan_tag if nic.vlan_tag is not None else (br.vlan_id if br else None)
                    if vid is not None:
                        meta = {"label": f"VLAN {vid} · {nic.bridge}", "kind": "vlan", "vlan_id": vid,
                                "note": br.comments if br and br.comments else ""}
                    elif br:
                        meta = _bridge_meta(br)
                    else:
                        meta = {"label": f"{nic.bridge or '?'} · VLAN unknown", "kind": "bridge",
                                "note": "bridge config not readable — the token needs Sys.Audit and SDN.Audit"}
                    key = f"{nic.bridge}.{nic.vlan_tag}" if nic.vlan_tag is not None else nic.bridge
                    n = net(key, **meta)
                    placements[g["vmid"]].append((key, br, nic))
                    if f"{node['name']}/{nic.bridge}" not in n["bridges"]:
                        n["bridges"].append(f"{node['name']}/{nic.bridge}")
                    if br and br.cidr and _subnet(br.cidr):
                        n["subnets"].add(_subnet(br.cidr))
                    target.append((n, nic))
            for n, nic in target:
                ips, ip_source = [], "none"
                if nic and host:
                    match = [i for i in ifaces.get(host["id"], []) if nic.mac and i.mac == nic.mac]
                    if match:
                        ips, ip_source = match[0].address_list, "agent"
                elif nic and nic.config_ip:
                    ips, ip_source = [nic.config_ip], "proxmox"
                for cidr in ips:
                    sn = _subnet(cidr)
                    if sn and not sn.is_link_local:
                        n["subnets"].add(sn)
                n["members"].append(dict(
                    g, nic={"iface": nic.iface, "mac": nic.mac, "bridge": nic.bridge, "firewall": nic.firewall} if nic else None,
                    ips=ips, ip_source=ip_source,
                    ports=_ports_on(ports.get(host["id"], []), ips) if host and ips else [],
                ))

        node["gateways"] = _promote_gateways(node, nets, placements, flags)

        appearances = defaultdict(int)
        for n in nets.values():
            for m in n["members"]:
                appearances[m["host"]["id"] if m.get("host") else ("vm", m["vmid"])] += 1
        order = {"vlan": 0, "bridge": 1, "internal": 1, "unknown": 9}
        out = []
        for n in _tree_order(nets, node["gateways"], order):
            for m in n["members"]:
                m["multi_homed"] = appearances[m["host"]["id"] if m.get("host") else ("vm", m["vmid"])] > 1
            managed = [m for m in n["members"] if m.get("host")]
            n["subnets"] = sorted(str(s) for s in n["subnets"])
            n["summary"] = {
                "machines": len(n["members"]),
                "managed": len(managed),
                "unmanaged": sum(1 for m in n["members"] if m["coverage"] in ("unmanaged", "name_match")),
                "listening": sum(len(m["ports"]) for m in n["members"]),
                "critical": sum(1 for m in managed if m["host"]["max_severity"] == "critical"),
                "active_runs": sum(1 for m in managed if m["host"]["active_job_id"]),
            }
            out.append(n)
        node["networks"] = out


def _promote_gateways(node: dict, nets: dict, placements: dict, flags: dict) -> list:
    """
    Lift gateways -- routers/firewalls -- out of the zones they sit in and
    put them above the zones they route:

        node -> uplink bridge -> GATEWAY -> the bridges it routes -> their VMs

    A gateway is a VM tagged GATEWAY_TAG in Proxmox, or one a person
    promoted. Its uplink is its NIC on a bridge with a physical port; with
    none, a bridge another gateway routes (a router behind a router); with
    neither, it hangs off the node directly. Every other bridge it has a NIC
    on is a zone it routes -- unless another gateway already routes it (or
    routing it would make a loop), in which case it stays an ordinary tile
    there, marked secondary.

    Untagged VMs that look like gateways -- a NIC on an uplink and one on
    an internal bridge, or a router-like name -- get a suggestion on their
    tiles instead. Never promoted automatically: a dual-homed server
    matches the bridge rule too.
    """
    candidates, suggestions = [], {}
    for g in node["guests"]:
        if g.get("template") or g.get("vmid") is None or g["vmid"] not in placements:
            continue
        places = placements[g["vmid"]]
        keys = list(dict.fromkeys(k for k, _, _ in places))
        tagged = GATEWAY_TAG in [t.lower() for t in g.get("tags") or []]
        flag = flags.get((g.get("connection_id"), g["vmid"]))
        if tagged or (flag and flag.gateway):
            uplinks = [k for k, br, _ in places if br is not None and br.ports]
            candidates.append({"g": g, "places": places, "source": "tag" if tagged else "marked",
                               "parent": uplinks[0] if uplinks else None, "keys": keys})
        elif not (flag and flag.gateway is False) and len(keys) >= 2:
            uplink = [k for k, br, _ in places if br is not None and br.ports]
            internal = [k for k, br, _ in places if br is not None and not br.ports]
            named = _ROUTER_NAME_RE.search((g.get("name") or "").lower())
            if uplink and internal:
                suggestions[g["vmid"]] = (f"NICs on an uplink bridge ({nets[uplink[0]]['label']}) and on internal "
                                          f"bridges only it connects — the shape of a router")
            elif named:
                suggestions[g["vmid"]] = f"the name looks like a router or firewall ({named.group(2)})"

    # Gateways with a physical uplink claim first, then by vmid: the
    # outermost router is the one most likely to be the parent.
    candidates.sort(key=lambda c: (c["parent"] is None, c["g"]["vmid"]))
    claimed, gw_parent = {}, {}

    def ancestors(net_key):
        seen = set()
        while net_key and net_key not in seen:
            seen.add(net_key)
            owner = claimed.get(net_key)
            net_key = gw_parent.get(owner) if owner else None
        return seen

    gateways = []
    for c in candidates:
        vmid = c["g"]["vmid"]
        if c["parent"] is None:   # no physical uplink: behind another gateway, if one routes its bridge
            c["parent"] = next((k for k in c["keys"] if k in claimed), None)
        gw_parent[vmid] = c["parent"]
        above = ancestors(c["parent"]) if c["parent"] else set()
        routed = []
        for k in c["keys"]:
            if k == c["parent"] or k in claimed or k in above:
                continue
            claimed[k] = vmid
            routed.append(k)
        if not routed:
            gw_parent.pop(vmid)
            continue   # routes nothing of its own: stays an ordinary tile
        c["routed"] = routed
        gateways.append(c)

    node_key = node["key"]
    promoted = {c["g"]["vmid"]: c for c in gateways}
    gw_ips = defaultdict(list)   # (vmid, net key) -> addresses its tile there had
    for k, n in nets.items():
        if k in claimed:
            n["parent_gateway"] = f"{node_key}/gw:{claimed[k]}"
        kept = []
        for m in n["members"]:
            vmid = m.get("vmid")
            gw = promoted.get(vmid)
            if gw and (k == gw["parent"] or k in gw["routed"]):
                gw_ips[(vmid, k)] += m.get("ips") or []
                continue                       # drawn once, as the gateway card
            if gw:
                m["gateway_secondary"] = True  # a zone another gateway routes
            if vmid in suggestions:
                m["gateway_suggestion"] = suggestions[vmid]
            flag = flags.get((m.get("connection_id"), vmid))
            if flag and flag.gateway is False:
                m["gateway_dismissed"] = flag.set_by or True
            kept.append(m)
        n["members"] = kept

    out = []
    for c in gateways:
        g, vmid = c["g"], c["g"]["vmid"]
        interfaces = []
        for k, _br, nic in c["places"]:
            interfaces.append({"iface": nic.iface, "bridge": nic.bridge, "network": f"{node_key}/{k}",
                               "label": nets[k]["label"], "ips": gw_ips.get((vmid, k), []), "role": "uplink" if k == c["parent"]
                               else "routes" if k in c["routed"] else "also on"})
        out.append(dict(g, key=f"{node_key}/gw:{vmid}", source=c["source"],
                        parent=f"{node_key}/{c['parent']}" if c["parent"] else None,
                        routed=[f"{node_key}/{k}" for k in c["routed"]], interfaces=interfaces))
    return out


def _tree_order(nets: dict, gateways: list, order: dict) -> list:
    """
    Networks in the order the tree draws them, each with its depth: a
    top-level bridge, then (recursively) the gateways hanging under it and
    the bridges they route; gateways hanging off the node itself last. A
    gateway shares its parent bridge's depth and sits just below it; the
    bridges it routes are one deeper.
    """
    by_parent = defaultdict(list)
    for gw in gateways:
        by_parent[gw["parent"]].append(gw)
    full = {n["key"]: n for n in nets.values()}
    sort_key = lambda n: (order.get(n["kind"], 5), n["vlan_id"] or 0, n["label"])  # noqa: E731
    out, placed = [], set()

    def emit(n, depth):
        if n["key"] in placed:
            return
        placed.add(n["key"])
        n["depth"] = depth
        out.append(n)
        for gw in by_parent.get(n["key"], []):
            gw["depth"] = depth
            for rk in gw["routed"]:
                emit(full[rk], depth + 1)

    for n in sorted((n for n in nets.values() if not n.get("parent_gateway")), key=sort_key):
        emit(n, 0)
    for gw in by_parent.get(None, []):    # no uplink bridge: hangs off the node
        gw["depth"] = 0
        for rk in gw["routed"]:
            emit(full[rk], 1)
    for n in sorted(nets.values(), key=sort_key):   # anything left (shouldn't happen)
        emit(n, 0)
    return out
