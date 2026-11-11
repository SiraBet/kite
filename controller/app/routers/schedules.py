from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..db import get_db
from ..auth import get_current_user, require_role
from .runs import normalise_severity_filter

router = APIRouter(prefix="/schedules", tags=["schedules"])


def _validate_time(day_of_week, hour):
    if day_of_week is not None and not (0 <= day_of_week <= 6):
        raise HTTPException(400, "day_of_week must be 0 (Monday) through 6 (Sunday)")
    if hour is not None and not (0 <= hour <= 23):
        raise HTTPException(400, "hour must be 0-23 (UTC)")


@router.get("", response_model=List[schemas.ScheduleOut])
def list_schedules(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return db.query(models.Schedule).order_by(models.Schedule.id).all()


@router.post("", response_model=schemas.ScheduleOut)
def create_schedule(payload: schemas.ScheduleCreate, db: Session = Depends(get_db),
                     user: models.User = Depends(require_role("admin"))):
    if not payload.name.strip():
        raise HTTPException(400, "name is required")
    _validate_time(payload.day_of_week, payload.hour)

    scope = payload.scope or models.SCOPE_OS
    if scope not in models.RUN_SCOPES:
        raise HTTPException(400, f"scope must be one of {models.RUN_SCOPES}")

    s = models.Schedule(
        name=payload.name.strip(), team=payload.team or "", day_of_week=payload.day_of_week,
        hour=payload.hour, ticket_id=payload.ticket_id or None, created_by=user.username,
        scope=scope,
        # Names rather than ids: a schedule fires against whatever hosts
        # are in scope that week, and a container id is per-host while a
        # compose service name is the thing they have in common.
        container_selection="\n".join(payload.containers or []),
        # Checked as a single run's is: a typo here would otherwise match
        # nothing, and the schedule would "succeed" every week having
        # installed no updates at all.
        severity_filter=normalise_severity_filter(payload.severity_filter),
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    audit.log(db, actor=user.username, role=user.role, action="schedule_created",
              detail=f"{s.name} — {models.DAY_NAMES[s.day_of_week]} {s.hour:02d}:00 UTC, team={s.team or 'all'}")
    return s


@router.patch("/{schedule_id}", response_model=schemas.ScheduleOut)
def update_schedule(schedule_id: int, payload: schemas.ScheduleUpdate, db: Session = Depends(get_db),
                     user: models.User = Depends(require_role("admin"))):
    s = db.query(models.Schedule).filter(models.Schedule.id == schedule_id).first()
    if not s:
        raise HTTPException(404, "Schedule not found")
    fields = payload.model_dump(exclude_unset=True)
    _validate_time(fields.get("day_of_week"), fields.get("hour"))
    if fields.get("scope") is not None and fields["scope"] not in models.RUN_SCOPES:
        raise HTTPException(400, f"scope must be one of {models.RUN_SCOPES}")
    if fields.get("severity_filter") is not None:
        fields["severity_filter"] = normalise_severity_filter(fields["severity_filter"])
    # `containers` is a list on the wire and a newline-separated column
    # in the table; without translating it here a plain setattr would
    # attach a stray attribute and silently drop the change.
    if "containers" in fields:
        s.container_selection = "\n".join(fields.pop("containers") or [])
    for field, value in fields.items():
        setattr(s, field, value)
    db.commit()
    db.refresh(s)
    audit.log(db, actor=user.username, role=user.role, action="schedule_updated", detail=s.name)
    return s


@router.delete("/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db),
                     user: models.User = Depends(require_role("admin"))):
    s = db.query(models.Schedule).filter(models.Schedule.id == schedule_id).first()
    if not s:
        raise HTTPException(404, "Schedule not found")
    audit.log(db, actor=user.username, role=user.role, action="schedule_removed", detail=s.name, tone="danger")
    db.delete(s)
    db.commit()
    return {"ok": True}
