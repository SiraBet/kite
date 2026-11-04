"""
A machine's Proxmox snapshots taken by kite, and what cleanup will do
with each (app/snapshot_retention.py). Lead and above can keep or remove
one: both decide whether a way back from a patch still exists. Restoring
one -- putting the VM's disks back to that moment -- is admin-only and
must be confirmed with the machine's name: everything since is lost.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit, friendly_errors, models, proxmox, snapshot_retention
from ..auth import require_role
from ..db import get_db

router = APIRouter(prefix="/hosts/{host_id}/snapshots", tags=["snapshots"])


class KeepSet(BaseModel):
    keep: bool


class Restore(BaseModel):
    confirm: str        # the machine's name, typed: restoring loses everything since the snapshot
    start: bool = True  # start the VM again afterwards when it was running


RESTORE_WAIT_SECONDS = 300


def _host(db: Session, host_id: int) -> models.Host:
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    return host


def _ours(name: str) -> int:
    m = snapshot_retention.NAME.match(name)
    if not m:
        raise HTTPException(400, f"'{name}' wasn't taken by kite — manage it in Proxmox")
    return int(m.group(1))


@router.get("")
def list_snapshots(host_id: int, db: Session = Depends(get_db), user: models.User = Depends(require_role("operator"))):
    host = _host(db, host_id)
    out = {"policy": snapshot_retention.policy(db), "snapshots": [], "error": ""}
    if not host.proxmox_vmid:
        out["error"] = "not linked to a Proxmox VM"
        return out
    try:
        out["snapshots"] = snapshot_retention.snapshots_for(db, host)
    except (RuntimeError, proxmox.ProxmoxError, OSError) as e:
        out["error"] = friendly_errors.report(e, context=f"snapshots of {host.hostname}")
    return out


@router.post("/{name}/keep")
def keep_snapshot(host_id: int, name: str, payload: KeepSet, db: Session = Depends(get_db),
                  user: models.User = Depends(require_role("lead"))):
    host = _host(db, host_id)
    job = db.query(models.Job).filter(models.Job.id == _ours(name), models.Job.host_id == host.id).first()
    if not job:
        raise HTTPException(404, "No run of this machine took that snapshot")
    job.snapshot_keep = payload.keep
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="snapshot_kept" if payload.keep else "snapshot_unkept",
              detail=f"{host.hostname} — {name}")
    return {"ok": True}


@router.delete("/{name}")
def delete_snapshot(host_id: int, name: str, db: Session = Depends(get_db),
                    user: models.User = Depends(require_role("lead"))):
    host = _host(db, host_id)
    job = db.query(models.Job).filter(models.Job.id == _ours(name)).first()
    if job and job.status in ("queued", "running"):
        raise HTTPException(409, "Its run is still going — that snapshot is the way back")
    try:
        snapshot_retention.delete(db, host, name, actor=user.username, role=user.role, why="removed by hand")
    except (RuntimeError, proxmox.ProxmoxError, OSError) as e:
        raise HTTPException(502, friendly_errors.report(e, context=f"deleting {name}")) from e
    return {"ok": True}


@router.post("/{name}/restore")
def restore_snapshot(host_id: int, name: str, payload: Restore, db: Session = Depends(get_db),
                     user: models.User = Depends(require_role("admin"))):
    """
    Roll the machine's VM back to one of kite's snapshots, then start
    it again if it was running (kite's snapshots hold no RAM, so
    Proxmox leaves the VM off). Refused while a run is going on it.
    """
    host = _host(db, host_id)
    job_id = _ours(name)
    if not db.query(models.Job).filter(models.Job.id == job_id, models.Job.host_id == host.id).first():
        raise HTTPException(409, f"{name} isn't from a run recorded for {host.hostname}. If you're sure it's "
                                 "the right one, restore it in Proxmox.")
    if payload.confirm.strip() != host.hostname:
        raise HTTPException(400, f"Type the machine's name, {host.hostname}, to confirm")
    active = db.query(models.Job).filter(models.Job.host_id == host.id,
                                         models.Job.status.in_(("queued", "running"))).first()
    if active:
        raise HTTPException(409, f"Run {active.id} is going on {host.hostname} — let it finish or stop it first")
    try:
        cfg, node = snapshot_retention.host_vm(db, host)
        if name not in {s.get("name") for s in proxmox.list_snapshots(cfg, host.proxmox_vmid, node)}:
            raise HTTPException(404, f"{host.hostname}'s VM has no snapshot {name} any more")
        was = proxmox.vm_status(cfg, host.proxmox_vmid, node)
        task = proxmox.rollback_snapshot(cfg, host.proxmox_vmid, name, node)
        audit.log(db, actor=user.username, role=user.role, action="snapshot_restore_started",
                  detail=f"{host.hostname} — VM {host.proxmox_vmid} back to {name}", tone="danger")
        task_node = node or cfg.node
        finished = proxmox.wait_for_task(cfg, task_node, task, timeout=RESTORE_WAIT_SECONDS) if task_node and task else False
    except (RuntimeError, proxmox.ProxmoxError, OSError) as e:
        why = friendly_errors.report(e, context=f"restoring {name}")
        audit.log(db, actor=user.username, role=user.role, action="snapshot_restore_failed",
                  detail=f"{host.hostname} — {name}: {why}", tone="danger")
        raise HTTPException(502, f"Couldn't restore {name}: {why}") from e
    if not finished:
        return {"ok": True, "state": "restoring",
                "note": "Proxmox is still restoring. Check the VM in Proxmox; start it there when it's done."}
    started, note = False, ""
    if payload.start and was == "running":
        try:
            proxmox.wait_for_task(cfg, task_node, proxmox.start_vm(cfg, host.proxmox_vmid, node), timeout=120)
            started = True
        except (proxmox.ProxmoxError, OSError) as e:
            note = (f"Restored, but the VM couldn't be started: {friendly_errors.report(e, context='starting the VM')} "
                    "Start it in Proxmox "
                    "(or give the token VM.PowerMgmt so kite can).")
    elif was == "running":
        note = "Restored; the VM is off. Start it when you're ready."
    audit.log(db, actor=user.username, role=user.role, action="snapshot_restored",
              detail=f"{host.hostname} — VM {host.proxmox_vmid} restored to {name}"
                     f"{'; started again' if started else '; left off'}", tone="danger")
    return {"ok": True, "state": "restored", "started": started, "note": note}
