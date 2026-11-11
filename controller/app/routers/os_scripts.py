import re
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .. import models, schemas, audit, groups
from ..db import get_db
from ..auth import get_current_user, require_role

router = APIRouter(prefix="/os-scripts", tags=["os-scripts"])

# A stage script is a page or two of shell or PowerShell. It is stored in
# the database, kept again in history on every replacement, and sent whole
# to every matching agent on every run.
MAX_SCRIPT_BYTES = 1024 * 1024


def _safe_filename(name: str) -> str:
    """
    The uploaded file's own name, reduced to something that is only ever
    a label: no directories, and no characters that mean anything inside
    the Content-Disposition header it is later sent back in (a quote ends
    the value, a line break ends the header).
    """
    base = re.split(r"[\\/]", name or "")[-1]
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")[:128]
    return cleaned or "script.sh"


@router.get("", response_model=List[schemas.OsScriptOut])
def list_scripts(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Flat list - the frontend groups these into per-OS 'folders' by os_family."""
    return db.query(models.OsScript).order_by(models.OsScript.os_family, models.OsScript.stage_name).all()


@router.get("/family/{os_family}", response_model=List[schemas.OsScriptOut])
def scripts_for_family(os_family: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return db.query(models.OsScript).filter(models.OsScript.os_family == os_family).all()


@router.get("/host/{host_id}", response_model=List[schemas.OsScriptOut])
def scripts_for_host(host_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """The custom scripts this machine runs, stage by stage: a group's, else its OS family's."""
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    rows = [groups.script_for(db, host, stage) for stage in models.SCRIPTABLE_STAGES]
    return [r for r in rows if r]


@router.get("/{os_family}/{stage_name}/download")
def download_script(os_family: str, stage_name: str, db: Session = Depends(get_db),
                     user: models.User = Depends(get_current_user)):
    s = (
        db.query(models.OsScript)
        .filter(models.OsScript.os_family == os_family, models.OsScript.stage_name == stage_name)
        .first()
    )
    if not s:
        raise HTTPException(404, f"No script for {os_family}/{stage_name}")
    return Response(
        content=s.content,
        media_type="text/x-sh",
        headers={"Content-Disposition": f'attachment; filename="{_safe_filename(s.filename)}"'},
    )


@router.post("/{os_family}/{stage_name}/upload", response_model=schemas.OsScriptOut)
async def upload_script(
    os_family: str, stage_name: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin")),
):
    # This is the sharpest edge in the whole system - a script uploaded here
    # runs as root on every host of this OS family on the next patch run.
    # admin-only, and identity comes from the authenticated session, never
    # a client-supplied field.
    if stage_name not in models.SCRIPTABLE_STAGES:
        raise HTTPException(400, f"'{stage_name}' isn't scriptable - allowed: {models.SCRIPTABLE_STAGES}")

    group = db.query(models.MachineGroup).filter(models.MachineGroup.name == os_family).first()
    if group:
        problems = groups.conflicts(db, list(group.hosts), group, stages=[stage_name])
        if problems:
            raise HTTPException(400, " ".join(problems))

    raw = await file.read(MAX_SCRIPT_BYTES + 1)
    if len(raw) > MAX_SCRIPT_BYTES:
        raise HTTPException(413, f"A stage script can be at most {MAX_SCRIPT_BYTES // 1024} KB")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise HTTPException(400, "Script must be a UTF-8 text file") from e

    existing = (
        db.query(models.OsScript)
        .filter(models.OsScript.os_family == os_family, models.OsScript.stage_name == stage_name)
        .first()
    )
    if existing:
        # Snapshot the outgoing version before it's overwritten - this is the
        # "one active script per OS+stage" rule: uploads REPLACE, never stack.
        db.add(models.OsScriptHistory(
            os_family=os_family, stage_name=stage_name, filename=existing.filename,
            content=existing.content, uploaded_by=existing.uploaded_by,
            uploaded_at=existing.uploaded_at, note="replaced",
        ))
        existing.filename = _safe_filename(file.filename)
        existing.content = content
        existing.tested = False  # new content - the tested flag doesn't carry over
        existing.uploaded_by = user.username
        existing.uploaded_at = datetime.utcnow()
        row = existing
    else:
        row = models.OsScript(
            os_family=os_family, stage_name=stage_name,
            filename=_safe_filename(file.filename), content=content, uploaded_by=user.username,
        )
        db.add(row)

    db.commit()
    db.refresh(row)
    audit.log(db, actor=user.username, role=user.role, action="os_script_uploaded",
              detail=f"{os_family}/{stage_name} - {row.filename}")
    return row


@router.delete("/{os_family}/{stage_name}")
def delete_script(os_family: str, stage_name: str, db: Session = Depends(get_db),
                   user: models.User = Depends(require_role("admin"))):
    s = (
        db.query(models.OsScript)
        .filter(models.OsScript.os_family == os_family, models.OsScript.stage_name == stage_name)
        .first()
    )
    if not s:
        raise HTTPException(404, f"No script for {os_family}/{stage_name}")
    db.add(models.OsScriptHistory(
        os_family=os_family, stage_name=stage_name, filename=s.filename,
        content=s.content, uploaded_by=s.uploaded_by, uploaded_at=s.uploaded_at, note="deleted",
    ))
    db.delete(s)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="os_script_removed",
              detail=f"{os_family}/{stage_name} - reverts to built-in agent default", tone="warning")
    return {"ok": True}


@router.get("/{os_family}/{stage_name}/history", response_model=List[schemas.OsScriptHistoryOut])
def script_history(os_family: str, stage_name: str, db: Session = Depends(get_db),
                    user: models.User = Depends(get_current_user)):
    return (
        db.query(models.OsScriptHistory)
        .filter(models.OsScriptHistory.os_family == os_family, models.OsScriptHistory.stage_name == stage_name)
        .order_by(models.OsScriptHistory.uploaded_at.desc())
        .all()
    )
