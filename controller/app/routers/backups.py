"""
The database backups (app/db_backups.py): list them, take one now,
download one. Admin only, from a console login -- never an API token,
read-only ones included: a backup is the whole database (password
hashes, the encrypted Proxmox token) -- and every download and
on-demand backup is in the Activity log.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .. import audit, db_backups, models
from ..auth import require_role, require_session_user
from ..db import get_db

router = APIRouter(prefix="/backups", tags=["backups"])


@router.get("")
def list_backups(db: Session = Depends(get_db), user: models.User = Depends(require_role("admin")), _console=Depends(require_session_user)):
    return {"keep": db_backups.keep_count(db), "backups": db_backups.list_backups()}


@router.post("")
def backup_now(db: Session = Depends(get_db), user: models.User = Depends(require_role("admin")), _console=Depends(require_session_user)):
    try:
        path = db_backups.take()
    except Exception as e:  # noqa: BLE001 -- sqlite3, gzip and disk errors alike: say what failed
        raise HTTPException(500, f"Backup failed: {e}") from e
    keep = db_backups.keep_count(db)
    removed = db_backups.prune(keep) if keep > 0 else []
    audit.log(db, actor=user.username, role=user.role, action="db_backup_taken",
              detail=f"{path.name}" + (f"; removed {len(removed)} older" if removed else ""))
    return {"ok": True, "name": path.name, "removed": removed}


@router.get("/{name}")
def download_backup(name: str, db: Session = Depends(get_db), user: models.User = Depends(require_role("admin")), _console=Depends(require_session_user)):
    if not db_backups.NAME.match(name) or not (db_backups.BACKUP_DIR / name).is_file():
        raise HTTPException(404, "No such backup")
    audit.log(db, actor=user.username, role=user.role, action="db_backup_downloaded", detail=name, tone="warning")
    return FileResponse(db_backups.BACKUP_DIR / name, media_type="application/gzip", filename=name)
