from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..db import get_db
from ..auth import get_current_user, require_role

router = APIRouter(prefix="/defs", tags=["patch-definitions"])


@router.get("", response_model=List[schemas.DefOut])
def list_defs(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return db.query(models.PatchDef).all()


def _targets(db: Session, targets: list) -> list:
    """Checked, de-duplicated PatchDefTarget rows; 400 for a group or machine that doesn't exist."""
    out, seen = [], set()
    for t in targets:
        kind, value = t.kind, str(t.value).strip()
        if kind not in models.TARGET_KINDS or not value:
            raise HTTPException(400, f"A rule applies to OS families, groups or machines ({kind!r} isn't one)")
        if kind == "group" and not (value.isdigit() and db.get(models.MachineGroup, int(value))):
            raise HTTPException(400, f"No group {value}")
        if kind == "host" and not (value.isdigit() and db.get(models.Host, int(value))):
            raise HTTPException(400, f"No machine {value}")
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append(models.PatchDefTarget(kind=kind, value=value))
    return out


def describe_targets(db: Session, targets: list) -> str:
    """'every machine', or 'rocky9, group db-servers, machine web-01'."""
    if not targets:
        return "every machine"
    parts = []
    for t in targets:
        if t.kind == "os":
            parts.append(t.value)
        elif t.kind == "group":
            g = db.get(models.MachineGroup, int(t.value)) if t.value.isdigit() else None
            parts.append(f"group {g.name if g else t.value}")
        else:
            h = db.get(models.Host, int(t.value)) if t.value.isdigit() else None
            # a removed machine's target stays: dropping it could leave no targets, i.e. every machine
            parts.append(f"machine {h.hostname}" if h else f"removed machine #{t.value}")
    return ", ".join(parts)


@router.post("", response_model=schemas.DefOut)
def add_def(payload: schemas.DefCreate, db: Session = Depends(get_db),
            user: models.User = Depends(require_role("admin"))):
    if payload.mode not in ("skip", "pin"):
        raise HTTPException(400, "mode must be 'skip' or 'pin'")
    if payload.mode == "pin" and not payload.version:
        raise HTTPException(400, "version is required when mode is 'pin'")
    targets = list(payload.targets)
    if payload.os_family:
        targets.append(schemas.DefTarget(kind="os", value=payload.os_family))

    d = models.PatchDef(
        pkg_pattern=payload.pkg_pattern, mode=payload.mode,
        version=payload.version if payload.mode == "pin" else "",
        reason=payload.reason, reviewed="not yet reviewed", os_family="",
        targets=_targets(db, targets),
    )
    db.add(d)
    db.commit()
    db.refresh(d)

    change_desc = f"pin ≤ {payload.version}" if payload.mode == "pin" else "skip"
    scope_desc = f" [{describe_targets(db, d.targets)}]"
    db.add(models.DefHistory(def_id=d.id, pkg_pattern=d.pkg_pattern,
                              change=f"created — {change_desc}{scope_desc} — {payload.reason}", by=user.username))
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="def_added",
              detail=f"{d.pkg_pattern} — {change_desc}{scope_desc} — {payload.reason}")
    return d


@router.put("/{def_id}/targets", response_model=schemas.DefOut)
def set_targets(def_id: int, payload: schemas.DefTargetsSet, db: Session = Depends(get_db),
                user: models.User = Depends(require_role("admin"))):
    """Change what a rule applies to; none = every machine."""
    d = db.query(models.PatchDef).filter(models.PatchDef.id == def_id).first()
    if not d:
        raise HTTPException(404, "Definition not found")
    before = describe_targets(db, d.targets)
    d.targets = _targets(db, payload.targets)
    db.flush()
    after = describe_targets(db, d.targets)
    db.add(models.DefHistory(def_id=d.id, pkg_pattern=d.pkg_pattern, change=f"applies to {after} (was {before})",
                              by=user.username))
    db.commit()
    db.refresh(d)
    audit.log(db, actor=user.username, role=user.role, action="def_scope_changed",
              detail=f"{d.pkg_pattern} — applies to {after} (was {before})")
    return d


@router.delete("/{def_id}")
def delete_def(def_id: int, db: Session = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    d = db.query(models.PatchDef).filter(models.PatchDef.id == def_id).first()
    if not d:
        raise HTTPException(404, "Definition not found")
    desc = f"pin ≤ {d.version}" if d.mode == "pin" else "skip"
    db.add(models.DefHistory(def_id=None, pkg_pattern=d.pkg_pattern,
                              change=f"removed (was {desc})", by=user.username))
    audit.log(db, actor=user.username, role=user.role, action="def_removed", detail=f"{d.pkg_pattern} (was {desc})", tone="danger")
    db.delete(d)
    db.commit()
    return {"ok": True}


@router.get("/{def_id}/history")
def def_history(def_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rows = db.query(models.DefHistory).filter(models.DefHistory.def_id == def_id).order_by(models.DefHistory.at.desc()).all()
    return [{"at": r.at, "by": r.by, "change": r.change} for r in rows]
