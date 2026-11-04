from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import models


def names(items, limit: int = 10) -> str:
    """
    "a, b, c" -- or "a, b, c and 397 more": an audit line naming machines
    stays readable however many there are.
    """
    items = list(items)
    shown = ", ".join(items[:limit])
    return shown if len(items) <= limit else f"{shown} and {len(items) - limit} more"


def log(db: Session, actor: str, role: str, action: str, detail: str, tone: str = "neutral"):
    entry = models.AuditLog(actor=actor, role=role, action=action, detail=detail, tone=tone)
    db.add(entry)
    db.commit()
    # Local import: every notable system event flows through this one
    # function, so this is where outbound notifications hook
    # in rather than at each individual call site -- see
    # app/notifications.py for what actually gets sent and to where.
    # Local rather than top-level to keep this foundational, imported-
    # everywhere module's own import graph minimal.
    from . import notifications
    notifications.notify_if_relevant(db, action, detail, tone)
    return entry


def prune(db: Session, keep_days: int, batch: int = 5000) -> int:
    """
    Remove activity older than `keep_days` (0 keeps everything), in
    batches so the database isn't locked for long. Returns how many.
    """
    if keep_days <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(days=keep_days)
    removed = 0
    while True:
        ids = [i for (i,) in db.query(models.AuditLog.id).filter(models.AuditLog.ts < cutoff).limit(batch).all()]
        if not ids:
            return removed
        db.query(models.AuditLog).filter(models.AuditLog.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        removed += len(ids)
