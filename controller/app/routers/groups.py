"""
Machine groups (app/groups.py): create, rename, delete, and put machines
in or take them out. Anyone signed in can see them; changing them is
admin-only, since a group's scripts run as root / SYSTEM on its machines
and update rules can apply to it.
"""
import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from .. import audit, groups, models
from ..auth import get_current_user, require_role
from ..db import get_db

router = APIRouter(prefix="/groups", tags=["groups"])
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")


class GroupOut(BaseModel):
    id: int
    name: str
    description: str = ""
    host_ids: List[int] = []
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class GroupCreate(BaseModel):
    name: str
    description: str = ""
    host_ids: List[int] = []


class GroupEdit(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class Members(BaseModel):
    host_ids: List[int]


def _out(g: models.MachineGroup) -> GroupOut:
    return GroupOut(id=g.id, name=g.name, description=g.description or "",
                    host_ids=[h.id for h in g.hosts], created_at=g.created_at)


def _group(db: Session, group_id: int) -> models.MachineGroup:
    g = db.query(models.MachineGroup).filter(models.MachineGroup.id == group_id).first()
    if not g:
        raise HTTPException(404, "Group not found")
    return g


def _check_name(db: Session, name: str, exclude_id: int = None) -> str:
    name = (name or "").strip()
    if not _NAME.match(name):
        raise HTTPException(400, "A group name is 1-64 letters, digits, spaces, dots, dashes or underscores, "
                                 "starting with a letter or digit")
    same = db.query(models.MachineGroup).filter(models.MachineGroup.name == name).first()
    if same and same.id != exclude_id:
        raise HTTPException(400, f"There's already a group called {name}")
    if db.query(models.Host).filter(models.Host.os_family == name).first() or \
            db.query(models.OsScript).filter(models.OsScript.os_family == name).first():
        raise HTTPException(400, f"{name} is an OS family's name — choose another for the group")
    return name


def _hosts(db: Session, ids: list) -> list:
    hosts = db.query(models.Host).filter(models.Host.id.in_(ids)).all() if ids else []
    if len(hosts) != len(set(ids)):
        raise HTTPException(404, "Some of these machines no longer exist")
    return hosts


@router.get("", response_model=List[GroupOut])
def list_groups(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return [_out(g) for g in db.query(models.MachineGroup).order_by(models.MachineGroup.name).all()]


@router.post("", response_model=GroupOut)
def create_group(payload: GroupCreate, db: Session = Depends(get_db),
                 user: models.User = Depends(require_role("admin"))):
    g = models.MachineGroup(name=_check_name(db, payload.name), description=payload.description.strip()[:500])
    g.hosts = _hosts(db, payload.host_ids)
    db.add(g)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="group_created",
              detail=f"{g.name}" + (f" — {audit.names(h.hostname for h in g.hosts)}" if g.hosts else ""))
    return _out(g)


@router.patch("/{group_id}", response_model=GroupOut)
def edit_group(group_id: int, payload: GroupEdit, db: Session = Depends(get_db),
               user: models.User = Depends(require_role("admin"))):
    g = _group(db, group_id)
    changes = []
    if payload.name is not None and payload.name.strip() != g.name:
        new = _check_name(db, payload.name, exclude_id=g.id)
        # its scripts are kept under its name
        for m in (models.OsScript, models.OsScriptHistory):
            db.query(m).filter(m.os_family == g.name).update({"os_family": new}, synchronize_session=False)
        changes.append(f"renamed {g.name} -> {new}")
        g.name = new
    if payload.description is not None:
        g.description = payload.description.strip()[:500]
        changes.append("description changed")
    db.commit()
    if changes:
        audit.log(db, actor=user.username, role=user.role, action="group_edited", detail=f"{g.name}: {'; '.join(changes)}")
    return _out(g)


@router.delete("/{group_id}")
def delete_group(group_id: int, db: Session = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    """Its machines stay as they are, minus the group; its scripts go to history."""
    g = _group(db, group_id)
    rules = (db.query(models.PatchDef).join(models.PatchDefTarget, models.PatchDefTarget.def_id == models.PatchDef.id)
             .filter(models.PatchDefTarget.kind == "group", models.PatchDefTarget.value == str(g.id)).all())
    if rules:
        names = ", ".join(sorted({r.pkg_pattern for r in rules}))
        raise HTTPException(400, f"Update rules apply to {g.name} ({names}). Change what they apply to first, "
                                 "so they don't end up applying somewhere you didn't mean.")
    for s in db.query(models.OsScript).filter(models.OsScript.os_family == g.name).all():
        db.add(models.OsScriptHistory(os_family=s.os_family, stage_name=s.stage_name, filename=s.filename,
                                      content=s.content, uploaded_by=s.uploaded_by, uploaded_at=s.uploaded_at,
                                      note="deleted with its group"))
        db.delete(s)
    name, n = g.name, len(g.hosts)
    g.hosts = []
    db.delete(g)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="group_deleted",
              detail=f"{name} ({n} machine{'' if n == 1 else 's'})", tone="warning")
    return {"ok": True}


@router.post("/{group_id}/members", response_model=GroupOut)
def add_members(group_id: int, payload: Members, db: Session = Depends(get_db),
                user: models.User = Depends(require_role("admin"))):
    g = _group(db, group_id)
    new = [h for h in _hosts(db, payload.host_ids) if h not in g.hosts]
    problems = groups.conflicts(db, new, g)
    if problems:
        raise HTTPException(400, " ".join(problems))
    g.hosts = list(g.hosts) + new
    db.commit()
    if new:
        audit.log(db, actor=user.username, role=user.role, action="group_members_added",
                  detail=f"{g.name} + {audit.names(sorted(h.hostname for h in new))}", tone="warning")
    return _out(g)


@router.post("/{group_id}/members/remove", response_model=GroupOut)
def remove_members(group_id: int, payload: Members, db: Session = Depends(get_db),
                   user: models.User = Depends(require_role("admin"))):
    g = _group(db, group_id)
    gone = [h for h in g.hosts if h.id in set(payload.host_ids)]
    g.hosts = [h for h in g.hosts if h not in gone]
    db.commit()
    if gone:
        audit.log(db, actor=user.username, role=user.role, action="group_members_removed",
                  detail=f"{g.name} − {audit.names(sorted(h.hostname for h in gone))}")
    return _out(g)
