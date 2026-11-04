"""
Updating Linux agents from the console, the way a vendor console pushes
its agents rather than someone running dnf on every host. Sets a target;
each agent upgrades itself on its next idle poll (see app/agent_releases.py).
Viewing is open to every signed-in user; changing a target is admin-only,
since it installs software on hosts.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import agent_releases, audit, models
from ..auth import get_current_user, require_role
from ..db import get_db
from ..settings_store import set_setting

router = APIRouter(prefix="/agents/updates", tags=["agent-updates"])


class AgentUpdateSet(BaseModel):
    version: str                    # a published version, or "latest": each agent to the newest of its kind
    host_id: Optional[int] = None   # None = every agent that can update itself


@router.get("")
def agent_update_status(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return agent_releases.fleet_status(db)


@router.post("")
def set_agent_update(payload: AgentUpdateSet, db: Session = Depends(get_db),
                     user: models.User = Depends(require_role("admin"))):
    known = set(agent_releases.published()) | {agent_releases.bundle_info().get("version"),
                                              agent_releases.windows_info().get("version"), agent_releases.LATEST}
    if payload.version not in known - {None, ""}:
        raise HTTPException(400, f"Agent {payload.version} isn't published in this controller's repo")
    if payload.host_id is None:
        set_setting(db, "agent_target_version", payload.version)
        detail = f"every agent -> {payload.version}"
    else:
        host = db.query(models.Host).filter(models.Host.id == payload.host_id).first()
        if not host:
            raise HTTPException(404, "Host not found")
        if not agent_releases.can_self_update(host):
            raise HTTPException(400, f"{host.hostname}'s agent can't update itself from this controller")
        host.agent_update_to = payload.version
        db.commit()
        detail = f"{host.hostname} -> {payload.version}"
    audit.log(db, actor=user.username, role=user.role, action="agent_update_requested", detail=detail)
    return agent_releases.fleet_status(db)


@router.delete("")
def cancel_agent_update(host_id: Optional[int] = None, db: Session = Depends(get_db),
                        user: models.User = Depends(require_role("admin"))):
    """Stop: agents that haven't updated yet stay where they are."""
    if host_id is None:
        set_setting(db, "agent_target_version", "")
        detail = "every agent"
    else:
        host = db.query(models.Host).filter(models.Host.id == host_id).first()
        if not host:
            raise HTTPException(404, "Host not found")
        host.agent_update_to = None
        db.commit()
        detail = host.hostname
    audit.log(db, actor=user.username, role=user.role, action="agent_update_cancelled", detail=detail)
    return agent_releases.fleet_status(db)
