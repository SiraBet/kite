"""
Minimal Proxmox VE API client — what snapshots, restoring them, and inventory need.

Proxmox authenticates API tokens via a header, not OAuth/basic auth:
  Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>

Docs: https://pve.proxmox.com/pve-docs/api-viewer/

Every function here takes an explicit ProxmoxConfig rather than reading
a module-level settings object — config can now come from the DB
(Settings -> Connections, see app/rollback/config.py) as well as .env, and
can change without a restart, so there's no single "the" config to read
implicitly anymore.
"""
import requests
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote


class ProxmoxError(Exception):
    pass


class ProxmoxTaskFailed(ProxmoxError):
    """Proxmox ran the task and it ended in an error (not: Proxmox couldn't be asked)."""


@dataclass
class ProxmoxConfig:
    host: str = ""
    node: str = ""
    token_id: str = ""
    token_secret: str = ""
    verify_ssl: bool = False


def _headers(cfg: ProxmoxConfig):
    if not (cfg.token_id and cfg.token_secret):
        raise ProxmoxError(
            "Proxmox API token not configured — set it in Settings → Connections, "
            "or PROXMOX_TOKEN_ID / PROXMOX_TOKEN_SECRET in .env"
        )
    return {"Authorization": f"PVEAPIToken={cfg.token_id}={cfg.token_secret}"}


def _base_url(cfg: ProxmoxConfig, vmid: int, node: str = None) -> str:
    node = node or cfg.node
    if not cfg.host or not node:
        raise ProxmoxError("Proxmox host/node not configured — set it in Settings → Connections, or PROXMOX_HOST / PROXMOX_NODE in .env")
    return f"https://{cfg.host}:8006/api2/json/nodes/{quote(node, safe='')}/qemu/{vmid}"


def list_cluster_vms(cfg: ProxmoxConfig) -> list:
    """
    Every QEMU VM in the cluster, each tagged with the node it's actually
    running on right now -- via /cluster/resources, which Proxmox exposes
    even on a single, non-clustered node (it just reports that one node's
    VMs). This is what removes the old single-PROXMOX_NODE assumption
   : callers no longer need to already know which node a VM
    lives on before they can look anything up about it.
    """
    if not cfg.host:
        raise ProxmoxError("Proxmox host not configured — set it in Settings → Connections, or PROXMOX_HOST in .env")
    url = f"https://{cfg.host}:8006/api2/json/cluster/resources"
    resp = requests.get(url, headers=_headers(cfg), params={"type": "vm"}, verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox cluster resource list failed ({resp.status_code}): {resp.text}")
    return [{"vmid": row["vmid"], "node": row["node"]} for row in resp.json().get("data", []) if "vmid" in row]


def list_cluster_resources(cfg: ProxmoxConfig) -> list:
    """
    The raw /cluster/resources rows for nodes and guests (QEMU and LXC) --
    the whole cluster's inventory in one read-only call, for the coverage
    and topology views (app/proxmox_inventory.py). Unlike list_cluster_vms
    this keeps every field Proxmox returns (name, status, template, tags,
    ...) and includes the node rows themselves.

    Only needs audit rights (VM.Audit / Sys.Audit). Proxmox silently
    omits what the token cannot see, so a missing guest here can mean
    "not visible to this token" as well as "doesn't exist".
    """
    if not cfg.host:
        raise ProxmoxError("Proxmox host not configured — set it in Settings → Connections, or PROXMOX_HOST in .env")
    url = f"https://{cfg.host}:8006/api2/json/cluster/resources"
    resp = requests.get(url, headers=_headers(cfg), verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox cluster resource list failed ({resp.status_code}): {resp.text}")
    return [row for row in resp.json().get("data", []) if row.get("type") in ("node", "qemu", "lxc")]


def list_node_network(cfg: ProxmoxConfig, node: str) -> list:
    """
    A node's network config: bridges, VLAN interfaces (`eno1.20`),
    bonds, NICs -- what /etc/network/interfaces says, as Proxmox parses
    it. Needs Sys.Audit on the node.
    """
    url = f"https://{cfg.host}:8006/api2/json/nodes/{quote(node, safe='')}/network"
    resp = requests.get(url, headers=_headers(cfg), verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox network config for {node} failed ({resp.status_code}): {resp.text}")
    return resp.json().get("data") or []


def get_guest_config(cfg: ProxmoxConfig, node: str, vmid: int, guest_type: str = "qemu") -> dict:
    """A VM's or container's config (netN lines and the rest). Needs VM.Audit."""
    kind = "lxc" if guest_type == "lxc" else "qemu"
    url = f"https://{cfg.host}:8006/api2/json/nodes/{quote(node, safe='')}/{kind}/{int(vmid)}/config"
    resp = requests.get(url, headers=_headers(cfg), verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox config for {kind} {vmid} failed ({resp.status_code}): {resp.text}")
    return resp.json().get("data") or {}


def token_privileges(cfg: ProxmoxConfig) -> set:
    """
    Every privilege the token holds on any path, from Proxmox's own
    /access/permissions -- what the connection test reports, so "the
    token works" and "the token can snapshot" are told apart before a
    patch run finds out the hard way.
    """
    if not cfg.host:
        raise ProxmoxError("Proxmox host not configured")
    url = f"https://{cfg.host}:8006/api2/json/access/permissions"
    resp = requests.get(url, headers=_headers(cfg), verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox permission lookup failed ({resp.status_code}): {resp.text}")
    privs = set()
    for path_privs in (resp.json().get("data") or {}).values():
        privs.update(p for p, granted in (path_privs or {}).items() if granted)
    return privs


def resolve_vm_node(cfg: ProxmoxConfig, vmid: int) -> Optional[str]:
    """
    Which node a given VMID is actually running on right now, per the
    cluster's own view -- not assumed from a single configured node.
    Returns None if not found (wrong vmid, or the API token lacks
    cluster-wide read access) -- callers fall back to cfg.node in that
    case, same single-node behavior as before this existed.
    """
    for vm in list_cluster_vms(cfg):
        if vm["vmid"] == vmid:
            return vm["node"]
    return None


def create_snapshot(cfg: ProxmoxConfig, vmid: int, snapname: str, description: str = "", node: str = None) -> dict:
    """
    Create a snapshot of the given VM. `node` should be the VM's actual
    current node (see resolve_vm_node) in a multi-node deployment; falls
    back to cfg.node when not given, unchanged single-node behavior.
    Raises ProxmoxError on failure.
    """
    url = f"{_base_url(cfg, vmid, node)}/snapshot"
    resp = requests.post(
        url,
        headers=_headers(cfg),
        data={"snapname": snapname, "description": description},
        verify=cfg.verify_ssl,
        timeout=30,
    )
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox snapshot failed ({resp.status_code}): {resp.text}")
    return resp.json()


def list_snapshots(cfg: ProxmoxConfig, vmid: int, node: str = None) -> list:
    """The VM's snapshots: [{name, snaptime, description, ...}], without Proxmox's 'current' pseudo-entry."""
    resp = requests.get(f"{_base_url(cfg, vmid, node)}/snapshot", headers=_headers(cfg),
                        verify=cfg.verify_ssl, timeout=30)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox snapshot list failed ({resp.status_code}): {resp.text}")
    return [s for s in (resp.json().get("data") or []) if s.get("name") != "current"]


def delete_snapshot(cfg: ProxmoxConfig, vmid: int, snapname: str, node: str = None) -> str:
    """Start deleting one snapshot. Returns the Proxmox task id; the delete itself runs async there."""
    resp = requests.delete(f"{_base_url(cfg, vmid, node)}/snapshot/{quote(snapname, safe='')}",
                           headers=_headers(cfg), verify=cfg.verify_ssl, timeout=30)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox snapshot delete failed ({resp.status_code}): {resp.text}")
    return resp.json().get("data") or ""


def _task_status(cfg: ProxmoxConfig, node: str, upid: str) -> dict:
    url = f"https://{cfg.host}:8006/api2/json/nodes/{quote(node, safe='')}/tasks/{quote(upid, safe='')}/status"
    resp = requests.get(url, headers=_headers(cfg), verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox task status failed ({resp.status_code}): {resp.text}")
    return resp.json().get("data") or {}


def task_finished(cfg: ProxmoxConfig, node: str, upid: str) -> bool:
    """
    One look at a Proxmox task: True when it ended OK, False while it's
    still running; raises ProxmoxError when it failed.
    """
    st = _task_status(cfg, node, upid)
    if st.get("status") != "stopped":
        return False
    if st.get("exitstatus") != "OK":
        raise ProxmoxTaskFailed(f"Proxmox task failed: {st.get('exitstatus') or 'unknown error'}")
    return True


def task_node(upid: str) -> str:
    """The node a task runs on, which Proxmox writes into its id: UPID:<node>:..."""
    parts = (upid or "").split(":")
    return parts[1] if len(parts) > 2 and parts[0] == "UPID" else ""


def wait_for_task(cfg: ProxmoxConfig, node: str, upid: str, timeout: float = 300, interval: float = 2) -> bool:
    """
    Wait for a Proxmox task to end. True when it ended OK, False when it
    was still running at `timeout`; raises ProxmoxError when it failed.
    """
    import time
    deadline = time.monotonic() + timeout
    while True:
        if task_finished(cfg, node, upid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def vm_status(cfg: ProxmoxConfig, vmid: int, node: str = None) -> str:
    """'running', 'stopped', ... Needs VM.Audit."""
    resp = requests.get(f"{_base_url(cfg, vmid, node)}/status/current", headers=_headers(cfg),
                        verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox VM status failed ({resp.status_code}): {resp.text}")
    return (resp.json().get("data") or {}).get("status") or ""


def rollback_snapshot(cfg: ProxmoxConfig, vmid: int, snapname: str, node: str = None) -> str:
    """
    Start rolling the VM back to a snapshot: its disks return to that
    moment and everything written since is lost. A snapshot without RAM
    (kite's) leaves the VM stopped. Needs VM.Snapshot (or
    VM.Snapshot.Rollback). Returns the task id.
    """
    resp = requests.post(f"{_base_url(cfg, vmid, node)}/snapshot/{quote(snapname, safe='')}/rollback",
                         headers=_headers(cfg), verify=cfg.verify_ssl, timeout=30)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox rollback failed ({resp.status_code}): {resp.text}")
    return resp.json().get("data") or ""


def start_vm(cfg: ProxmoxConfig, vmid: int, node: str = None) -> str:
    """Start the VM. Needs VM.PowerMgmt. Returns the task id."""
    resp = requests.post(f"{_base_url(cfg, vmid, node)}/status/start", headers=_headers(cfg),
                         verify=cfg.verify_ssl, timeout=30)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox start failed ({resp.status_code}): {resp.text}")
    return resp.json().get("data") or ""


def list_vmids(cfg: ProxmoxConfig, node: str = None) -> list:
    """List all QEMU VM IDs on the configured node."""
    node = node or cfg.node
    if not cfg.host or not node:
        raise ProxmoxError("Proxmox host/node not configured — set it in Settings → Connections, or PROXMOX_HOST / PROXMOX_NODE in .env")
    url = f"https://{cfg.host}:8006/api2/json/nodes/{quote(node, safe='')}/qemu"
    resp = requests.get(url, headers=_headers(cfg), verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox VM list failed ({resp.status_code}): {resp.text}")
    return [row["vmid"] for row in resp.json().get("data", [])]


def get_vm_smbios_uuid(cfg: ProxmoxConfig, vmid: int, node: str = None) -> str:
    """
    Read a VM's config and pull the SMBIOS UUID Proxmox stamped it with —
    the same value that shows up inside the guest at
    /sys/class/dmi/id/product_uuid. Returns '' if the VM has no smbios1
    line (older VMs, or ones created without one).
    """
    node = node or cfg.node
    url = f"https://{cfg.host}:8006/api2/json/nodes/{quote(node, safe='')}/qemu/{vmid}/config"
    resp = requests.get(url, headers=_headers(cfg), verify=cfg.verify_ssl, timeout=15)
    if resp.status_code >= 300:
        raise ProxmoxError(f"Proxmox VM config failed ({resp.status_code}): {resp.text}")
    smbios1 = resp.json().get("data", {}).get("smbios1", "")
    # smbios1 looks like "uuid=8f3c1a2e-....,base64=1" — pull just the uuid value
    for part in smbios1.split(","):
        if part.startswith("uuid="):
            return part[len("uuid="):].strip().lower()
    return ""


def find_vmid_by_smbios_uuid(cfg: ProxmoxConfig, target_uuid: str, node: str = None) -> Optional[int]:
    """
    Cross-reference a guest-reported SMBIOS UUID against VMs to find which
    numeric VM ID it belongs to. This is what makes automatic proxmox_vmid
    resolution possible — the agent can't know its own VM ID directly, but
    it CAN read its own SMBIOS UUID, and the controller already has the
    Proxmox API access needed to look it up. Returns None if no match (not
    an error — just means no automatic match was found, caller decides
    what to do about it).

    Searches the whole cluster via list_cluster_vms by default
    — a fleet spanning multiple Proxmox nodes now resolves correctly
    instead of only ever finding a match on whichever single node happened
    to be configured. Pass `node` to restrict the search to one node
    instead (also the fallback if /cluster/resources itself isn't
    reachable — an older Proxmox, or a token without cluster-wide read
    access).
    """
    target_uuid = (target_uuid or "").strip().lower()
    if not target_uuid:
        return None
    if node:
        candidates = [{"vmid": v, "node": node} for v in list_vmids(cfg, node)]
    else:
        try:
            candidates = list_cluster_vms(cfg)
        except ProxmoxError:
            candidates = [{"vmid": v, "node": cfg.node} for v in list_vmids(cfg)]
    for vm in candidates:
        try:
            if get_vm_smbios_uuid(cfg, vm["vmid"], vm["node"]) == target_uuid:
                return vm["vmid"]
        except ProxmoxError:
            continue  # one VM's config failing to fetch shouldn't abort the whole search
    return None


