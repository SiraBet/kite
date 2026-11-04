from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..auth import get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=List[schemas.AuditOut])
def list_audit(limit: int = 200, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(limit).all()
