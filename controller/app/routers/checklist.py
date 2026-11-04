from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..db import get_db
from ..auth import get_current_user, require_role

router = APIRouter(prefix="/checklist-items", tags=["checklist"])


@router.get("", response_model=List[schemas.ChecklistItemOut])
def list_checklist_items(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Every logged-in user needs this — it drives the checklist step of
    the run wizard, not just the admin-editing UI."""
    return db.query(models.ChecklistItem).order_by(models.ChecklistItem.id).all()


@router.post("", response_model=schemas.ChecklistItemOut)
def add_checklist_item(payload: schemas.ChecklistItemCreate, db: Session = Depends(get_db),
                        user: models.User = Depends(require_role("admin"))):
    text = payload.text.strip()
    if not text:
        raise HTTPException(400, "text is required")
    item = models.ChecklistItem(text=text, created_by=user.username)
    db.add(item)
    db.commit()
    db.refresh(item)
    audit.log(db, actor=user.username, role=user.role, action="checklist_item_added", detail=text)
    return item


@router.delete("/{item_id}")
def delete_checklist_item(item_id: int, db: Session = Depends(get_db),
                           user: models.User = Depends(require_role("admin"))):
    item = db.query(models.ChecklistItem).filter(models.ChecklistItem.id == item_id).first()
    if not item:
        raise HTTPException(404, "Checklist item not found")
    if db.query(models.ChecklistItem).count() <= 1:
        raise HTTPException(400, "Can't remove the last checklist item — a run needs at least one to confirm")
    db.delete(item)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="checklist_item_removed", detail=item.text, tone="danger")
    return {"ok": True}
