import hmac
from typing import List

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..db import get_db
from ..auth import get_current_user, require_role
from ..settings_store import get_secret

router = APIRouter(prefix="/tickets", tags=["tickets"])


@router.get("", response_model=List[schemas.TicketOut])
def list_tickets(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return db.query(models.Ticket).all()


@router.post("/webhook", response_model=schemas.TicketOut)
def ticket_webhook(payload: schemas.TicketCreate, db: Session = Depends(get_db),
                    x_kite_webhook_secret: str = Header(default="")):
    """
    Inbound integration point for a real ITSM system — a
    ServiceNow Business Rule / Flow Designer outbound REST step, a Jira
    Automation webhook action, or any script, pushing a ticket's real
    approval state into kite instead of an admin creating/approving
    tickets by hand via POST /tickets. Same payload shape as
    TicketCreate — the stub was already shaped like a real ticket
    response before this, so this is wiring, not a redesign. Upserts by
    ticket_id (creates if new, updates status/window/etc if it already
    exists) since a real ticket's status changes over its lifecycle
    (Pending approval -> Approved, or withdrawn afterward), not just
    once at creation.

    Auth: a shared secret (Settings -> Notifications -> "Ticket webhook
    secret"), sent as X-Kite-Webhook-Secret. No secret configured
    means this endpoint refuses every request rather than silently
    accepting unauthenticated ticket writes — a change-control gate
    shouldn't have a default-open door.
    """
    configured_secret = get_secret(db, "ticket_webhook_secret")
    if not configured_secret:
        raise HTTPException(503, "Ticket webhook not configured — set a secret via Settings first")
    if not x_kite_webhook_secret or not hmac.compare_digest(x_kite_webhook_secret, configured_secret):
        raise HTTPException(401, "Invalid or missing X-Kite-Webhook-Secret header")

    existing = db.query(models.Ticket).filter(models.Ticket.ticket_id == payload.ticket_id).first()
    if existing:
        for field, value in payload.model_dump(exclude={"ticket_id"}).items():
            setattr(existing, field, value)
        db.commit()
        audit.log(db, actor="system", role="controller", action="ticket_synced",
                  detail=f"{payload.ticket_id} — {payload.status} (via webhook)")
        return existing

    t = models.Ticket(**payload.model_dump())
    db.add(t)
    db.commit()
    audit.log(db, actor="system", role="controller", action="ticket_synced",
              detail=f"{payload.ticket_id} — {payload.status} (via webhook, created)")
    return t


@router.get("/{ticket_id}", response_model=schemas.TicketOut)
def get_ticket(ticket_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    t = db.query(models.Ticket).filter(models.Ticket.ticket_id == ticket_id).first()
    if not t:
        raise HTTPException(404, f"Ticket {ticket_id} not found")
    return t


@router.post("", response_model=schemas.TicketOut)
def create_ticket(payload: schemas.TicketCreate, db: Session = Depends(get_db),
                   user: models.User = Depends(require_role("lead"))):
    """
    Stand-in for a real ServiceNow/Jira webhook or sync job (see
    POST /tickets/webhook above for that) — this
    manual path stays too, for a lab without ITSM behind it, or for
    creating a ticket by hand for a specific one-off change. Requires
    lead+ — creating an "Approved" ticket is what unlocks a run, so it
    shouldn't be an operator-level action.
    """
    existing = db.query(models.Ticket).filter(models.Ticket.ticket_id == payload.ticket_id).first()
    if existing:
        raise HTTPException(409, f"Ticket {payload.ticket_id} already exists")
    t = models.Ticket(**payload.model_dump())
    db.add(t)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="ticket_created",
              detail=f"{payload.ticket_id} — {payload.status}")
    return t
