from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models, schemas, audit, proxmox_connections, rollback
from ..db import get_db
from ..auth import ROLE_RANK, get_current_user, require_role
from ..settings_store import get_setting

router = APIRouter(prefix="/hosts", tags=["hosts"])


def _attach_active_jobs(db: Session, hosts: list):
    """One query for all active jobs, mapped onto the host list — avoids N+1."""
    if not hosts:
        return hosts
    active = (
        db.query(models.Job)
        .filter(models.Job.host_id.in_([h.id for h in hosts]), models.Job.status.in_(["queued", "running"]))
        .all()
    )
    by_host = {j.host_id: j.id for j in active}  # last one wins if somehow >1 — shouldn't happen given the create_run guard
    for h in hosts:
        h.active_job_id = by_host.get(h.id)
    return hosts


def _attach_update_counts(db: Session, hosts: list):
    """
    Pending-update totals and worst severity per host, in one grouped
    query for the whole list rather than one per host.

    Worst severity rather than a count is what the fleet list needs: a
    host with one critical needs attention before a host with forty
    moderates, and a single number cannot say that.
    """
    if not hosts:
        return hosts
    rows = (
        db.query(models.PendingUpdate.host_id, models.PendingUpdate.severity, func.count())
        .filter(models.PendingUpdate.host_id.in_([h.id for h in hosts]))
        .group_by(models.PendingUpdate.host_id, models.PendingUpdate.severity)
        .all()
    )
    totals, worst = {}, {}
    rank = {name: i for i, name in enumerate(models.SEVERITY_RANK)}
    for host_id, severity, count in rows:
        totals[host_id] = totals.get(host_id, 0) + count
        if rank.get(severity, 99) < rank.get(worst.get(host_id, "none"), 99):
            worst[host_id] = severity
    for host in hosts:
        host.pending_updates = totals.get(host.id, 0)
        host.max_severity = worst.get(host.id, "none")
    return hosts


def _attach_safety_net(db: Session, hosts: list):
    """What each host's run falls back to, from its rollback backend (one settings read for the list)."""
    default = get_setting(db, "rollback_default_backend")
    for host in hosts:
        host.safety_net = rollback.safety_net(host, host.rollback_backend or default)
    return hosts


def _for(user: models.User, hosts: list) -> list:
    """
    The hosts as `user` may see them. A host's hardware id (SMBIOS UUID)
    is what proves a re-enrolling machine is the same one, so only admins
    -- who can re-enroll a host anyway -- see it.
    """
    out = [schemas.HostOut.model_validate(h) for h in hosts]
    if ROLE_RANK.get(user.role, -1) < ROLE_RANK["admin"]:
        for h in out:
            h.smbios_uuid = ""
    return out


@router.get("", response_model=List[schemas.HostOut])
def list_hosts(team: Optional[str] = None, db: Session = Depends(get_db),
               user: models.User = Depends(get_current_user)):
    q = db.query(models.Host)
    if team:
        q = q.filter(models.Host.team == team)
    return _for(user, _attach_safety_net(db, _attach_update_counts(db, _attach_active_jobs(db, q.all()))))


@router.get("/{host_id}", response_model=schemas.HostOut)
def get_host(host_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    return _for(user, _attach_safety_net(db, _attach_update_counts(db, _attach_active_jobs(db, [host]))))[0]


class HostPatch(BaseModel):
    proxmox_vmid: Optional[int] = None
    proxmox_connection_id: Optional[int] = None  # which connection the vmid is on; None = the only one
    proxmox_node: Optional[str] = None  # '' clears the pinned node, resolving it live via the cluster instead (see app/rollback/)
    role: Optional[schemas.Label] = None
    team: Optional[schemas.Label] = None
    os_family: Optional[schemas.Identifier] = None
    rollback_backend: Optional[str] = None  # 'proxmox' | 'dnf_history' | 'none' | '' (= clear override, use the global default)


@router.get("/{host_id}/containers", response_model=List[schemas.ContainerOut])
def list_host_containers(host_id: int, db: Session = Depends(get_db),
                          user: models.User = Depends(get_current_user)):
    """
    What this host's agent last reported running. Ordered so the things
    needing attention come first: outdated, then undetermined, then
    current, alphabetically within each group.
    """
    if not db.query(models.Host).filter(models.Host.id == host_id).first():
        raise HTTPException(404, "Host not found")
    rows = db.query(models.Container).filter(models.Container.host_id == host_id).all()
    rank = {True: 0, None: 1, False: 2}
    return sorted(rows, key=lambda c: (rank.get(c.update_available, 3), c.name.lower()))


@router.get("/{host_id}/updates", response_model=List[schemas.PendingUpdateOut])
def list_host_updates(host_id: int, db: Session = Depends(get_db),
                       user: models.User = Depends(get_current_user)):
    """
    Pending updates as this host's package manager last reported them,
    most severe first — the order they'd actually be worked in.
    """
    if not db.query(models.Host).filter(models.Host.id == host_id).first():
        raise HTTPException(404, "Host not found")
    rows = db.query(models.PendingUpdate).filter(models.PendingUpdate.host_id == host_id).all()
    rank = {name: i for i, name in enumerate(models.SEVERITY_RANK)}
    return sorted(rows, key=lambda u: (rank.get(u.severity, 99), u.package.lower()))


@router.get("/{host_id}/software")
def list_host_software(host_id: int, db: Session = Depends(get_db),
                       user: models.User = Depends(get_current_user)):
    """
    Everything installed, as the agent last reported it:
    OS packages, snap/flatpak apps, Windows programs and installed updates.
    `reported_at` None means this agent doesn't report software yet.
    """
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    rows = (db.query(models.HostSoftware).filter(models.HostSoftware.host_id == host_id)
            .order_by(models.HostSoftware.kind, models.HostSoftware.name).all())
    return {
        "reported_at": host.software_reported_at,
        "items": [{"kind": r.kind, "name": r.name, "version": r.version, "arch": r.arch,
                   "source_name": r.source_name, "source_version": r.source_version,
                   "publisher": r.publisher} for r in rows],
    }


@router.patch("/{host_id}", response_model=schemas.HostOut)
def patch_host(host_id: int, payload: HostPatch, db: Session = Depends(get_db),
                user: models.User = Depends(require_role("admin"))):
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    fields = payload.model_dump(exclude_unset=True)
    if fields.get("rollback_backend") and fields["rollback_backend"] not in rollback.BACKEND_CHOICES:
        raise HTTPException(400, f"rollback_backend must be one of {rollback.BACKEND_CHOICES}, or '' to clear the override")
    if fields.get("proxmox_connection_id") is not None and not db.query(models.ProxmoxConnection).filter(
            models.ProxmoxConnection.id == fields["proxmox_connection_id"]).first():
        raise HTTPException(400, "No such Proxmox connection")
    for field, value in fields.items():
        setattr(host, field, value)
    db.commit()
    db.refresh(host)
    return _attach_safety_net(db, [host])[0]


@router.post("/{host_id}/resolve-vmid", response_model=schemas.HostOut)
def resolve_vmid(host_id: int, db: Session = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    """
    Retry automatic VMID resolution — useful if Proxmox creds were added
    to .env after this host already enrolled, or the first attempt
    failed for some transient reason.
    """
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    if not host.smbios_uuid:
        raise HTTPException(400, "This host has no recorded SMBIOS UUID (enrolled with an older agent build?) — set proxmox_vmid manually instead")
    conn, vmid, errors = proxmox_connections.find_vm_by_smbios(db, host.smbios_uuid)
    if not vmid:
        if errors:
            raise HTTPException(502, "Proxmox lookup failed — " + "; ".join(errors))
        raise HTTPException(404, "No VM on any Proxmox connection matches this host's SMBIOS UUID")
    host.proxmox_vmid, host.proxmox_connection_id = vmid, conn.id
    db.commit()
    db.refresh(host)
    audit.log(db, actor=user.username, role=user.role, action="vmid_auto_resolved",
              detail=f"{host.hostname} -> VM {vmid} on {conn.name} (manual retry)", tone="success")
    return _attach_safety_net(db, [host])[0]


@router.delete("/{host_id}")
def delete_host(host_id: int, db: Session = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    """
    Admin-only, and refuses if the host has an active run — deleting out
    from under a live job would leave that job referencing a host that
    no longer exists. Intended for cleaning up disconnected/decommissioned
    hosts, not as a way to interrupt a run in progress.
    """
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    active = (
        db.query(models.Job)
        .filter(models.Job.host_id == host_id, models.Job.status.in_(["queued", "running"]))
        .first()
    )
    if active:
        raise HTTPException(409, f"{host.hostname} has an active run (job {active.id}) — can't delete until it finishes")
    hostname = host.hostname
    # Container rows reference this host but SQLite has foreign keys off
    # by default, so nothing cascades — clear them explicitly rather than
    # leaving inventory for a host that no longer exists. Jobs survive on
    # purpose (they carry a denormalized hostname, see models.Job).
    db.query(models.Container).filter(models.Container.host_id == host_id).delete()
    db.query(models.PendingUpdate).filter(models.PendingUpdate.host_id == host_id).delete()
    db.query(models.HostInterface).filter(models.HostInterface.host_id == host_id).delete()
    db.query(models.HostListeningPort).filter(models.HostListeningPort.host_id == host_id).delete()
    db.query(models.HostSoftware).filter(models.HostSoftware.host_id == host_id).delete()
    db.query(models.MachineGroupMember).filter(models.MachineGroupMember.host_id == host_id).delete()
    db.query(models.HostVuln).filter(models.HostVuln.host_id == host_id).delete()
    # Rules naming this machine keep naming it. A rule with no targets
    # applies to every machine, so dropping the target of a rule that
    # named only this one would turn it into a fleet-wide rule. The Rules
    # page shows such a target as a removed machine, and the id is never
    # given to another machine (see enroll._next_host_id).
    for t in db.query(models.PatchDefTarget).filter(models.PatchDefTarget.kind == "host",
                                                    models.PatchDefTarget.value == str(host_id)).all():
        rule = db.query(models.PatchDef).filter(models.PatchDef.id == t.def_id).first()
        db.add(models.DefHistory(def_id=t.def_id, pkg_pattern=rule.pkg_pattern if rule else "",
                                 change=f"{hostname} was removed from the fleet (still named in this rule, "
                                        f"as removed machine #{host_id})",
                                 by=user.username))
    db.delete(host)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="host_removed", detail=hostname, tone="danger")
    return {"ok": True}
