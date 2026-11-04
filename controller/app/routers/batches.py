"""
Patching several machines from one wizard (app/batches.py). Starting,
continuing and stopping need the same role as starting a single run.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import audit, batches, models, schemas
from ..auth import get_current_user, require_role
from ..db import get_db
from .runs import check_host_ready, check_run_request

router = APIRouter(prefix="/batches", tags=["batches"])
MAX_HOSTS = 200


class BatchCreate(BaseModel):
    host_ids: List[int]
    rollout: str                          # 'one_at_a_time' | 'parallel' -- chosen by the person, no default
    ticket_id: Optional[str] = None
    checklist: List[schemas.ChecklistItemIn]
    window_override_reason: Optional[str] = None
    scope: str = "os"
    severity_filter: Optional[str] = ""


def _batch(db: Session, batch_id: int) -> models.Batch:
    b = db.query(models.Batch).filter(models.Batch.id == batch_id).first()
    if not b:
        raise HTTPException(404, "Batch not found")
    return b


@router.post("")
def create_batch(payload: BatchCreate, db: Session = Depends(get_db),
                 user: models.User = Depends(require_role("operator"))):
    if payload.rollout not in models.BATCH_ROLLOUTS:
        raise HTTPException(400, f"rollout must be one of {models.BATCH_ROLLOUTS}")
    ids = list(dict.fromkeys(payload.host_ids))
    if len(ids) < 2:
        raise HTTPException(400, "A batch needs at least two machines; patch one from its own page")
    if len(ids) > MAX_HOSTS:
        raise HTTPException(400, f"At most {MAX_HOSTS} machines in one batch")
    settings = check_run_request(db, user, payload)
    hosts = {h.id: h for h in db.query(models.Host).filter(models.Host.id.in_(ids)).all()}
    missing = [str(i) for i in ids if i not in hosts]
    if missing:
        raise HTTPException(404, f"Not in the fleet: host {audit.names(missing)}")
    # Every machine checked before anything starts, so the person sees all
    # the problems at once rather than a batch that stops halfway.
    problems = []
    for i in ids:
        try:
            check_host_ready(db, hosts[i], settings)
        except HTTPException as e:
            problems.append(str(e.detail))
    if problems:
        raise HTTPException(409, "Can't start: " + " · ".join(problems))
    b = batches.start(db, user, ids, payload.rollout, settings)
    return batches.view(db, b)


@router.get("")
def list_batches(limit: int = 20, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rows = db.query(models.Batch).order_by(models.Batch.id.desc()).limit(max(1, min(limit, 100))).all()
    return [batches.view(db, b) for b in rows]


@router.get("/{batch_id}")
def get_batch(batch_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return batches.view(db, _batch(db, batch_id))


@router.post("/{batch_id}/continue")
def continue_batch(batch_id: int, db: Session = Depends(get_db),
                   user: models.User = Depends(require_role("operator"))):
    b = _batch(db, batch_id)
    if b.status != "paused":
        raise HTTPException(409, f"Batch {b.id} isn't paused (it's {b.status})")
    batches.resume(db, b, user)
    return batches.view(db, b)


@router.post("/{batch_id}/stop")
def stop_batch(batch_id: int, db: Session = Depends(get_db),
               user: models.User = Depends(require_role("operator"))):
    b = _batch(db, batch_id)
    if b.status not in ("running", "paused"):
        raise HTTPException(409, f"Batch {b.id} is already {b.status}")
    batches.stop(db, b, user)
    return batches.view(db, b)
