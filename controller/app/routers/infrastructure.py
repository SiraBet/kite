"""
Proxmox coverage and the fleet topology map -- read-only views of the
cluster, joined against enrolled hosts. The logic lives in
app/proxmox_inventory.py; this is the HTTP surface.

Visible to every authenticated user, and to read-only API tokens: none
of it is more sensitive than the host list itself. Changing the ignore
list is a lead decision, since it removes a guest from the "nobody is
patching this" list everyone else relies on.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, audit, network_inventory, proxmox_connections, proxmox_inventory
from ..auth import get_current_user, require_role
from ..db import get_db

router = APIRouter(tags=["infrastructure"])


@router.get("/proxmox/coverage")
def get_coverage(refresh: bool = False, db: Session = Depends(get_db),
                 user: models.User = Depends(get_current_user)):
    """Every Proxmox guest, and whether kite manages it. `refresh` skips the short cache."""
    return proxmox_inventory.coverage(db, refresh=refresh)


@router.post("/proxmox/ignored")
def ignore_guest(payload: schemas.IgnoreGuestCreate, db: Session = Depends(get_db),
                 user: models.User = Depends(require_role("lead"))):
    if _ignored_row(db, payload.connection_id, payload.vmid):
        raise HTTPException(409, f"VM {payload.vmid} is already ignored")
    db.add(models.ProxmoxIgnoredGuest(connection_id=payload.connection_id, vmid=payload.vmid,
                                      reason=payload.reason, created_by=user.username))
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="proxmox_guest_ignored",
              detail=f"VM {payload.vmid}" + (f": {payload.reason}" if payload.reason else ""), tone="warning")
    return {"ok": True}


def _ignored_row(db: Session, connection_id, vmid: int):
    """The ignore entry for this VM, with entries from before connections existed counted as the only one's."""
    conns = proxmox_connections.list_connections(db)
    want = proxmox_connections.effective_connection_id(connection_id, conns)
    return next((r for r in db.query(models.ProxmoxIgnoredGuest).filter(models.ProxmoxIgnoredGuest.vmid == vmid)
                 if proxmox_connections.effective_connection_id(r.connection_id, conns) == want), None)


@router.delete("/proxmox/ignored/{vmid}")
def unignore_guest(vmid: int, connection_id: int = None, db: Session = Depends(get_db),
                   user: models.User = Depends(require_role("lead"))):
    row = _ignored_row(db, connection_id, vmid)
    if not row:
        raise HTTPException(404, f"VM {vmid} is not ignored")
    db.delete(row)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="proxmox_guest_unignored", detail=f"VM {vmid}")
    return {"ok": True}


# Gateways: which VM routes which zones in Topology. A Proxmox tag
# (proxmox_inventory.GATEWAY_TAG) always wins; these are for people who
# would rather click than tag, and for "no, that one isn't a router".
@router.post("/proxmox/gateway")
def set_gateway(payload: schemas.GatewayFlagSet, db: Session = Depends(get_db),
                user: models.User = Depends(require_role("lead"))):
    row = _flag_row(db, payload.connection_id, payload.vmid)
    if not row:
        row = models.ProxmoxGuestFlag(connection_id=payload.connection_id, vmid=payload.vmid)
        db.add(row)
    row.gateway, row.set_by = payload.gateway, user.username
    row.set_at = datetime.utcnow()
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="proxmox_gateway_set",
              detail=f"VM {payload.vmid} " + ("marked as a gateway" if payload.gateway else "marked as not a gateway"))
    return {"ok": True}


@router.delete("/proxmox/gateway/{vmid}")
def clear_gateway(vmid: int, connection_id: int = None, db: Session = Depends(get_db),
                  user: models.User = Depends(require_role("lead"))):
    """Forget the decision: back to the tag and the automatic suggestion."""
    row = _flag_row(db, connection_id, vmid)
    if not row:
        raise HTTPException(404, f"VM {vmid} has no gateway decision")
    db.delete(row)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="proxmox_gateway_cleared", detail=f"VM {vmid}")
    return {"ok": True}


def _flag_row(db: Session, connection_id, vmid: int):
    conns = proxmox_connections.list_connections(db)
    want = proxmox_connections.effective_connection_id(connection_id, conns)
    return next((r for r in db.query(models.ProxmoxGuestFlag).filter(models.ProxmoxGuestFlag.vmid == vmid)
                 if proxmox_connections.effective_connection_id(r.connection_id, conns) == want), None)


# Network detail -- addresses and listening ports -- is a map of what to
# attack, so it stays off read-only accounts. Operators patch these
# machines; they see it. (Topology carries the same detail per bridge.)
@router.post("/network/refresh")
def refresh_network(user: models.User = Depends(require_role("operator"))):
    """Re-read bridges and guest NICs from Proxmox now instead of waiting for the next pass."""
    return network_inventory.refresh_now()


@router.get("/hosts/{host_id}/network")
def get_host_network(host_id: int, db: Session = Depends(get_db),
                     user: models.User = Depends(require_role("operator"))):
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    return network_inventory.host_network(db, host)


@router.get("/topology")
def get_topology(refresh: bool = False, db: Session = Depends(get_db),
                 user: models.User = Depends(get_current_user)):
    """Proxmox node -> guests -> enrolled host, with per-node blast radius."""
    return proxmox_inventory.topology(db, refresh=refresh)
