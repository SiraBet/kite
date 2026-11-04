"""
POST /runs, GET /runs, GET /runs/{id}, POST /runs/{id}/cancel — the core
patch-execution flow. Covers real behavior read directly from
app/routers/runs.py: POST /runs and the two GETs have NO role
restriction beyond being logged in (only window_override_reason and
cancel require lead+), and neither GET has any ownership/team scoping —
any authenticated user can see any job. Tests below assert that actual
behavior rather than an assumed "should probably be scoped" one.
"""
from datetime import datetime

from conftest import make_host
from app import models
from app.settings_store import set_setting


def _checklist():
    return [{"item_index": 0, "item_text": "confirmed"}]


def _start_run(client, host_id, ticket_id=None, window_override_reason=None):
    body = {"host_id": host_id, "checklist": _checklist()}
    if ticket_id is not None:
        body["ticket_id"] = ticket_id
    if window_override_reason is not None:
        body["window_override_reason"] = window_override_reason
    return client.post("/runs", json=body)


def _safe_host(db, **kw):
    """A host whose snapshot stage won't try to reach real Proxmox —
    same 'none' backend pattern proven safe in test_rollback.py."""
    host, secret = make_host(db, **kw)
    host.rollback_backend = "none"
    db.commit()
    return host, secret


def _always_open_ticket(db, ticket_id="CHG-RUN-1", status="Approved"):
    t = models.Ticket(ticket_id=ticket_id, status=status, window_start=0, window_end=23)
    db.add(t)
    db.commit()
    return t


def _closed_window_ticket(db, ticket_id="CHG-RUN-CLOSED"):
    """A 1-hour window guaranteed to exclude the current UTC hour."""
    hour = (datetime.utcnow().hour + 12) % 24
    t = models.Ticket(ticket_id=ticket_id, status="Approved", window_start=hour, window_end=hour)
    db.add(t)
    db.commit()
    return t


# ---------- POST /runs ----------

def test_create_run_succeeds_with_no_ticket_when_not_required(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="operator", username="run-create-1")
    host, _ = _safe_host(db)

    resp = _start_run(client, host.id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ticket_id"] == ""
    assert body["status"] == "running"


def test_create_run_has_no_role_restriction(client, logged_in, db):
    """POST /runs only depends on get_current_user, not require_role —
    every tier can start a run, including plain operator."""
    set_setting(db, "require_ticket", "false")
    for role in ("operator", "lead", "admin"):
        logged_in(role=role, username=f"run-create-role-{role}")
        host, _ = _safe_host(db)
        resp = _start_run(client, host.id)
        assert resp.status_code == 200, f"{role}: {resp.text}"


def test_create_run_requires_ticket_when_setting_enabled(client, logged_in, db):
    set_setting(db, "require_ticket", "true")
    logged_in(role="operator", username="run-create-2")
    host, _ = _safe_host(db)

    resp = _start_run(client, host.id)
    assert resp.status_code == 400
    assert "ticket is required" in resp.text


def test_create_run_ticket_not_found(client, logged_in, db):
    set_setting(db, "require_ticket", "true")
    logged_in(role="operator", username="run-create-3")
    host, _ = _safe_host(db)

    resp = _start_run(client, host.id, ticket_id="CHG-DOES-NOT-EXIST")
    assert resp.status_code == 404


def test_create_run_ticket_not_approved(client, logged_in, db):
    set_setting(db, "require_ticket", "true")
    logged_in(role="operator", username="run-create-4")
    host, _ = _safe_host(db)
    _always_open_ticket(db, ticket_id="CHG-RUN-PENDING", status="Pending approval")

    resp = _start_run(client, host.id, ticket_id="CHG-RUN-PENDING")
    assert resp.status_code == 409
    assert "not Approved" in resp.text


def test_create_run_outside_window_without_override_is_blocked(client, logged_in, db):
    set_setting(db, "require_ticket", "true")
    logged_in(role="admin", username="run-create-5")
    host, _ = _safe_host(db)
    _closed_window_ticket(db, ticket_id="CHG-RUN-CLOSED-1")

    resp = _start_run(client, host.id, ticket_id="CHG-RUN-CLOSED-1")
    assert resp.status_code == 409
    assert "Outside approved window" in resp.text


def test_create_run_window_override_requires_lead(client, logged_in, db):
    set_setting(db, "require_ticket", "true")
    logged_in(role="operator", username="run-create-6")
    host, _ = _safe_host(db)
    _closed_window_ticket(db, ticket_id="CHG-RUN-CLOSED-2")

    resp = _start_run(client, host.id, ticket_id="CHG-RUN-CLOSED-2", window_override_reason="urgent CVE")
    assert resp.status_code == 403
    assert "lead role or higher" in resp.text


def test_create_run_window_override_succeeds_for_lead(client, logged_in, db):
    set_setting(db, "require_ticket", "true")
    logged_in(role="lead", username="run-create-7")
    host, _ = _safe_host(db)
    _closed_window_ticket(db, ticket_id="CHG-RUN-CLOSED-3")

    resp = _start_run(client, host.id, ticket_id="CHG-RUN-CLOSED-3", window_override_reason="urgent CVE")
    assert resp.status_code == 200, resp.text

    entry = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.action == "window_override")
        .order_by(models.AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert "urgent CVE" in entry.detail


def test_create_run_missing_host_404(client, logged_in):
    logged_in(role="operator", username="run-create-8")
    resp = _start_run(client, 999999)
    assert resp.status_code == 404


def test_create_run_requires_at_least_one_checklist_item(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="operator", username="run-create-9")
    host, _ = _safe_host(db)

    item = models.ChecklistItem(text="Backups verified", created_by="test")
    db.add(item)
    db.commit()
    try:
        resp = client.post("/runs", json={"host_id": host.id, "checklist": []})
        assert resp.status_code == 400
        assert "checklist" in resp.text
    finally:
        db.delete(item)
        db.commit()


def test_with_no_checklist_set_up_a_run_needs_none(client, logged_in, db):
    """With no items configured, every run was refused: there was nothing to confirm."""
    set_setting(db, "require_ticket", "false")
    saved = [(i.text, i.created_by) for i in db.query(models.ChecklistItem).order_by(models.ChecklistItem.id)]
    db.query(models.ChecklistItem).delete()
    db.commit()
    try:
        logged_in(role="operator", username="run-create-9b")
        host, _ = _safe_host(db)
        assert client.post("/runs", json={"host_id": host.id, "checklist": []}).status_code == 200
    finally:
        db.add_all([models.ChecklistItem(text=t, created_by=b) for t, b in saved])
        db.commit()


def test_create_run_conflicts_when_host_already_has_active_run(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="operator", username="run-create-10")
    host, _ = _safe_host(db)

    first = _start_run(client, host.id)
    assert first.status_code == 200

    second = _start_run(client, host.id)
    assert second.status_code == 409
    assert "already has an active run" in second.text


# ---------- GET /runs/{id}, GET /runs ----------

def test_get_run_success(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="operator", username="run-get-1")
    host, _ = _safe_host(db)
    job_id = _start_run(client, host.id).json()["id"]

    resp = client.get(f"/runs/{job_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == job_id


def test_get_run_404_for_nonexistent_id(client, logged_in):
    logged_in(role="operator", username="run-get-2")
    resp = client.get("/runs/999999")
    assert resp.status_code == 404


def test_get_run_has_no_ownership_scoping(client, logged_in, db):
    """Documents real (lack of) behavior: any authenticated role can GET
    a job it didn't create and isn't on the same team as — there's no
    scoping check in the route at all, only get_current_user."""
    set_setting(db, "require_ticket", "false")
    logged_in(role="admin", username="run-get-owner")
    host, _ = _safe_host(db)
    job_id = _start_run(client, host.id).json()["id"]

    logged_in(role="operator", username="run-get-other")
    resp = client.get(f"/runs/{job_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == job_id


def test_list_runs_no_role_restriction(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="operator", username="run-list-1")
    host, _ = _safe_host(db)
    _start_run(client, host.id)

    resp = client.get("/runs")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_list_runs_filters_by_host_id(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="admin", username="run-list-2")
    host_a, _ = _safe_host(db)
    host_b, _ = _safe_host(db)
    job_a = _start_run(client, host_a.id).json()["id"]
    job_b = _start_run(client, host_b.id).json()["id"]

    resp = client.get("/runs", params={"host_id": host_a.id})
    assert resp.status_code == 200
    ids = [j["id"] for j in resp.json()]
    assert job_a in ids
    assert job_b not in ids


# ---------- POST /runs/{id}/cancel ----------

def test_cancel_run_requires_lead(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="operator", username="run-cancel-1")
    host, _ = _safe_host(db)
    job_id = _start_run(client, host.id).json()["id"]

    resp = client.post(f"/runs/{job_id}/cancel")
    assert resp.status_code == 403
    assert "lead role or higher" in resp.text


def test_cancel_run_success_marks_cancelled_and_host_unknown(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="lead", username="run-cancel-2")
    host, _ = _safe_host(db)
    job_id = _start_run(client, host.id).json()["id"]

    resp = client.post(f"/runs/{job_id}/cancel")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "cancelled"

    db.refresh(host)
    assert host.status == "unknown"

    running_stage = next(s for s in body["stages"] if s["status"] not in ("pending", "done"))
    assert running_stage["status"] == "failed"
    assert "cancelled by run-cancel-2" in running_stage["output"]


def test_cancel_run_404_for_nonexistent_id(client, logged_in):
    logged_in(role="lead", username="run-cancel-3")
    resp = client.post("/runs/999999/cancel")
    assert resp.status_code == 404


def test_cancel_run_already_cancelled_is_rejected(client, logged_in, db):
    set_setting(db, "require_ticket", "false")
    logged_in(role="lead", username="run-cancel-4")
    host, _ = _safe_host(db)
    job_id = _start_run(client, host.id).json()["id"]

    first = client.post(f"/runs/{job_id}/cancel")
    assert first.status_code == 200

    second = client.post(f"/runs/{job_id}/cancel")
    assert second.status_code == 400
    assert "already cancelled" in second.text
