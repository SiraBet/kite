"""
Pluggable rollback/snapshot backends. The 'snapshot' stage used
to mean one hardcoded thing -- a Proxmox VM snapshot -- which left
bare-metal, cloud, and plain KVM/libvirt hosts with no safety net at all.
This module resolves, per host, which backend actually applies, and
dispatches to it.

Two backends ship today:
  - 'proxmox'    (controller-side): unchanged behavior, now driven by
                  config that can live in the DB (Settings -> Connections,
                  set via the UI) instead of only .env.
  - 'dnf_history' (agent-side): no hypervisor needed -- captures the
                  current dnf transaction id as a rollback reference
                  point (RHEL-family only; see agent-linux/agent.py's
                  stage_snapshot). Genuinely lighter-weight than a full
                  snapshot, at the cost of being an undo-last-transaction
                  safety net rather than a full point-in-time restore.
  - 'none'        (controller-side): an explicit, visible opt-out --
                  skips the stage with a clear "no safety net" message
                  instead of failing the job.
LVM/Btrfs/ZFS local snapshots and cloud provider snapshot APIs are the
next real backends to add here -- this module
is exactly the seam that makes adding one just a new file, not a rewrite.
"""
import re
import time

from .. import audit, friendly_errors
from ..settings_store import get_setting
from .config import resolve_proxmox_config  # noqa: F401 -- re-exported for callers

BACKEND_CHOICES = ["proxmox", "dnf_history", "none"]

# Which side of the poll/execute/report split each backend runs on --
# this is what lets one job's 'snapshot' JobStage be a controller stage
# for one host and an agent stage for another (see routers/runs.py
# create_run, which bakes this into the stage row at job creation).
_BACKEND_EXECUTOR = {
    "proxmox": "controller",
    "none": "controller",
    "dnf_history": "agent",
}


def resolve_backend_name(db, host) -> str:
    """Per-host override, else the global default (Settings -> Connections)."""
    if host.rollback_backend:
        return host.rollback_backend
    return get_setting(db, "rollback_default_backend")


def safety_net(host, backend_name: str) -> str:
    """
    What a run on this host can fall back to: 'snapshot' (a full VM
    snapshot), 'package_history' (dnf transaction undo) or 'none'. Without
    Proxmox's view of the guest, a linked VM id counts as a snapshot; the
    Topology view (app/proxmox_inventory.py) also rules out LXC guests.
    """
    if backend_name == "proxmox":
        return "snapshot" if host.proxmox_vmid else "none"
    if backend_name == "dnf_history":
        return "package_history"
    return "none"


# How long a Proxmox snapshot may take before the run gives up on it.
# A disk-only snapshot is usually seconds; slow storage can take minutes.
SNAPSHOT_TIMEOUT_SECONDS = 15 * 60
_STARTED = re.compile(r"^Taking snapshot '([^']+)' of VM (\d+)(.*?); Proxmox task (UPID:\S+)$")


def stage_executor_for(backend_name: str) -> str:
    return _BACKEND_EXECUTOR.get(backend_name, "controller")


def run_controller_snapshot(db, job, backend_name: str) -> str:
    """
    Called from jobs_engine.py for a controller-executed 'snapshot' stage.
    Returns the stage output on success; raises (caught by the caller,
    same as any other controller-stage failure) on failure. Never called
    for 'dnf_history' -- that's an agent-side stage, dispatched through
    the normal agent poll/report path instead, not through here.
    """
    from .. import proxmox  # local import: keeps proxmox.py's requests dependency out of modules that never touch Proxmox

    host = job.host

    if backend_name == "proxmox":
        if not host.proxmox_vmid:
            raise RuntimeError(
                f"Host {host.hostname} has no proxmox_vmid set — cannot snapshot. Set it via PATCH /hosts/{{id}}."
            )
        # The connection this host's VM id belongs to (the same vmid can
        # exist on several clusters), and its node: a pinned per-host node,
        # else resolved live, else the connection's configured one.
        from ..snapshot_retention import host_vm
        cfg, node = host_vm(db, host)
        snapname = f"kite-job{job.id}-{int(time.time())}"
        try:
            resp = proxmox.create_snapshot(cfg, host.proxmox_vmid, snapname,
                                            description=f"kite job {job.id}, ticket {job.ticket_id}", node=node)
        except (proxmox.ProxmoxError, OSError) as e:
            raise RuntimeError("Couldn't take the snapshot: "
                               + friendly_errors.report(e, context=f"snapshot of {host.hostname}")) from None
        node_note = f" on node {node}" if node else ""
        upid = (resp or {}).get("data") if isinstance(resp, dict) else ""
        if isinstance(upid, str) and upid.startswith("UPID:"):
            # Proxmox only accepted the request; the snapshot is taken by
            # this task. The stage waits for it (snapshot_progress).
            return f"Taking snapshot '{snapname}' of VM {host.proxmox_vmid}{node_note}; Proxmox task {upid}"
        return f"Snapshot '{snapname}' created for VM {host.proxmox_vmid}{node_note} (backend: proxmox)"

    if backend_name == "none":
        audit.log(db, actor="system", role="controller", action="snapshot_skipped",
                  detail=f"{host.hostname} — job {job.id}, rollback backend is 'none'", tone="warning")
        return "Rollback backend is 'none' for this host — snapshot stage skipped intentionally. Patching without a safety net."

    raise RuntimeError(f"'{backend_name}' is not a controller-side rollback backend")


def snapshot_pending(output: str) -> bool:
    """Whether a snapshot stage's output says it's still waiting on its Proxmox task."""
    return bool(_STARTED.match(output or ""))


def snapshot_progress(db, job, output: str, waited_seconds: float):
    """
    One look at the Proxmox task a snapshot stage started. Returns the
    stage's final output once the snapshot exists, None while Proxmox is
    still taking it; raises when it failed or took too long, so the run
    stops before patching anything without its safety net.
    """
    from .. import proxmox
    from ..snapshot_retention import host_vm

    m = _STARTED.match(output or "")
    if not m:
        raise RuntimeError("snapshot stage has no Proxmox task to wait for")
    snapname, vmid, node_note, upid = m.groups()
    cfg, _ = host_vm(db, job.host)
    try:
        finished = proxmox.task_finished(cfg, proxmox.task_node(upid), upid)
    except proxmox.ProxmoxTaskFailed as e:
        raise RuntimeError(f"Proxmox couldn't take snapshot '{snapname}' of VM {vmid}: "
                           f"{str(e).split(': ', 1)[-1]}") from None
    except Exception:  # noqa: BLE001 -- can't reach Proxmox right now: look again next pass, until the timeout
        finished = False
    if finished:
        return f"Snapshot '{snapname}' created for VM {vmid}{node_note} (backend: proxmox)"
    if waited_seconds >= SNAPSHOT_TIMEOUT_SECONDS:
        raise RuntimeError(f"Snapshot '{snapname}' of VM {vmid} wasn't confirmed by Proxmox within "
                           f"{SNAPSHOT_TIMEOUT_SECONDS // 60} minutes; nothing was patched. "
                           f"Check the task in Proxmox ({upid}).")
    return None
