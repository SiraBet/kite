"""
POST /tickets, GET /tickets, GET /tickets/{id} — the manual ticket path
(POST /tickets/webhook, the ITSM-integration path, is covered separately
in test_ticket_webhook.py). Per app/routers/tickets.py: manual creation
requires lead+ (an "Approved" ticket is what unlocks a run), the two
GETs only require being logged in.
"""
from app import models


def _payload(ticket_id="CHG-9001", **overrides):
    body = {"ticket_id": ticket_id, "status": "Approved", "description": "test change",
            "window_start": 0, "window_end": 23, "requester": "alice"}
    body.update(overrides)
    return body


# ---------- POST /tickets ----------

def test_create_ticket_requires_lead(client, logged_in):
    logged_in(role="operator", username="ticket-create-1")
    resp = client.post("/tickets", json=_payload())
    assert resp.status_code == 403
    assert "lead" in resp.text.lower()


def test_create_ticket_succeeds_for_lead(client, logged_in, db):
    logged_in(role="lead", username="ticket-create-2")
    resp = client.post("/tickets", json=_payload(ticket_id="CHG-9002"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ticket_id"] == "CHG-9002"
    assert body["status"] == "Approved"

    entry = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.action == "ticket_created")
        .order_by(models.AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert "CHG-9002" in entry.detail


def test_create_ticket_succeeds_for_admin(client, logged_in):
    logged_in(role="admin", username="ticket-create-3")
    resp = client.post("/tickets", json=_payload(ticket_id="CHG-9003"))
    assert resp.status_code == 200


def test_create_ticket_conflicts_on_duplicate_ticket_id(client, logged_in):
    logged_in(role="lead", username="ticket-create-4")
    first = client.post("/tickets", json=_payload(ticket_id="CHG-9004"))
    assert first.status_code == 200

    second = client.post("/tickets", json=_payload(ticket_id="CHG-9004"))
    assert second.status_code == 409
    assert "already exists" in second.text


def test_create_ticket_defaults_when_fields_omitted(client, logged_in):
    logged_in(role="lead", username="ticket-create-5")
    resp = client.post("/tickets", json={"ticket_id": "CHG-9005"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "Pending approval"
    assert body["window_start"] == 0
    assert body["window_end"] == 23


# ---------- GET /tickets, GET /tickets/{id} ----------

def test_list_tickets_no_role_restriction(client, logged_in):
    logged_in(role="lead", username="ticket-list-setup")
    client.post("/tickets", json=_payload(ticket_id="CHG-9006"))

    logged_in(role="operator", username="ticket-list-1")
    resp = client.get("/tickets")
    assert resp.status_code == 200
    ids = [t["ticket_id"] for t in resp.json()]
    assert "CHG-9006" in ids


def test_get_ticket_success(client, logged_in):
    logged_in(role="lead", username="ticket-get-setup")
    client.post("/tickets", json=_payload(ticket_id="CHG-9007"))

    logged_in(role="operator", username="ticket-get-1")
    resp = client.get("/tickets/CHG-9007")
    assert resp.status_code == 200
    assert resp.json()["ticket_id"] == "CHG-9007"


def test_get_ticket_404_for_nonexistent_id(client, logged_in):
    logged_in(role="operator", username="ticket-get-2")
    resp = client.get("/tickets/CHG-DOES-NOT-EXIST")
    assert resp.status_code == 404
