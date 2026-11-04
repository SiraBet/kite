from app import models, crypto
from app.settings_store import set_secret


def test_webhook_refuses_when_not_configured(client):
    resp = client.post("/tickets/webhook", json={"ticket_id": "CHG-1", "status": "Approved"})
    assert resp.status_code == 503


def test_webhook_rejects_missing_secret_header(db, client):
    set_secret(db, "ticket_webhook_secret", "shh")
    resp = client.post("/tickets/webhook", json={"ticket_id": "CHG-1", "status": "Approved"})
    assert resp.status_code == 401


def test_webhook_rejects_wrong_secret(db, client):
    set_secret(db, "ticket_webhook_secret", "shh")
    resp = client.post("/tickets/webhook", json={"ticket_id": "CHG-1", "status": "Approved"},
                        headers={"X-Kite-Webhook-Secret": "wrong"})
    assert resp.status_code == 401


def test_webhook_creates_new_ticket(db, client):
    set_secret(db, "ticket_webhook_secret", "shh")
    resp = client.post("/tickets/webhook",
                        json={"ticket_id": "CHG-100", "status": "Approved", "window_start": 1, "window_end": 5,
                              "description": "from ServiceNow", "requester": "jdoe"},
                        headers={"X-Kite-Webhook-Secret": "shh"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "Approved"
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_id == "CHG-100").first()
    assert ticket is not None
    assert ticket.window_start == 1


def test_webhook_updates_existing_ticket_status(db, client):
    set_secret(db, "ticket_webhook_secret", "shh")
    db.add(models.Ticket(ticket_id="CHG-200", status="Pending approval", window_start=0, window_end=23))
    db.commit()

    resp = client.post("/tickets/webhook", json={"ticket_id": "CHG-200", "status": "Approved"},
                        headers={"X-Kite-Webhook-Secret": "shh"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "Approved"
    assert db.query(models.Ticket).filter(models.Ticket.ticket_id == "CHG-200").count() == 1  # upsert, not a duplicate


def test_webhook_secret_never_returned_in_generic_settings_listing(db, client, logged_in):
    logged_in(role="admin", username="tw-admin-1")
    set_secret(db, "ticket_webhook_secret", "a-real-secret-value")
    listing = client.get("/settings").json()
    body = str(listing)
    assert "a-real-secret-value" not in body
    settings_dict = {s["key"]: s["value"] for s in listing}
    assert settings_dict["ticket_webhook_secret_set"] == "true"


def test_set_secret_endpoint_requires_admin(client, logged_in):
    logged_in(role="lead", username="tw-lead-1")
    resp = client.put("/settings/secret/ticket_webhook_secret", json={"value": "x"})
    assert resp.status_code == 403


def test_set_secret_endpoint_rejects_unknown_name(client, logged_in):
    logged_in(role="admin", username="tw-admin-2")
    resp = client.put("/settings/secret/not_a_real_secret", json={"value": "x"})
    assert resp.status_code == 404


def test_set_secret_endpoint_stores_encrypted(client, logged_in, db):
    logged_in(role="admin", username="tw-admin-3")
    resp = client.put("/settings/secret/notify_slack_webhook", json={"value": "https://hooks.slack.example/x"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "set": True}
    row = db.query(models.Setting).filter(models.Setting.key == "notify_slack_webhook_enc").first()
    assert row.value != "https://hooks.slack.example/x"
    assert crypto.decrypt(row.value) == "https://hooks.slack.example/x"
