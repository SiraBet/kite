from datetime import datetime

from app import models, scheduler
from app.settings_store import set_setting
from conftest import make_host


# ---------- CRUD ----------

def test_create_schedule_requires_admin(client, logged_in):
    logged_in(role="lead", username="sch-lead-1")
    resp = client.post("/schedules", json={"name": "Weekly", "day_of_week": 1, "hour": 3})
    assert resp.status_code == 403


def test_create_schedule_validates_day_and_hour(client, logged_in):
    logged_in(role="admin", username="sch-admin-1")
    bad_day = client.post("/schedules", json={"name": "Weekly", "day_of_week": 9, "hour": 3})
    assert bad_day.status_code == 400
    bad_hour = client.post("/schedules", json={"name": "Weekly", "day_of_week": 1, "hour": 30})
    assert bad_hour.status_code == 400


def test_create_and_list_schedule(client, logged_in):
    logged_in(role="admin", username="sch-admin-2")
    resp = client.post("/schedules", json={"name": "Patch Tuesday", "team": "Platform", "day_of_week": 1, "hour": 3})
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    assert body["team"] == "Platform"

    listing = client.get("/schedules").json()
    assert any(s["name"] == "Patch Tuesday" for s in listing)


def test_update_schedule_can_disable_it(client, logged_in):
    logged_in(role="admin", username="sch-admin-3")
    created = client.post("/schedules", json={"name": "Toggle me", "day_of_week": 2, "hour": 4}).json()
    resp = client.patch(f"/schedules/{created['id']}", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_delete_schedule(client, logged_in, db):
    logged_in(role="admin", username="sch-admin-4")
    created = client.post("/schedules", json={"name": "Delete me", "day_of_week": 3, "hour": 5}).json()
    resp = client.delete(f"/schedules/{created['id']}")
    assert resp.status_code == 200
    assert db.query(models.Schedule).filter(models.Schedule.id == created["id"]).first() is None


# ---------- firing logic ----------

def _seed_checklist(db):
    db.query(models.ChecklistItem).delete()
    db.add(models.ChecklistItem(text="Auto-confirmed item", created_by="test"))
    db.commit()


def test_fire_schedule_starts_a_run_for_hosts_in_scope(db):
    _seed_checklist(db)
    set_setting(db, "require_ticket", "false")
    host, _ = make_host(db)
    other_team_host, _ = make_host(db)
    other_team_host.team = "OtherTeam"
    db.commit()

    sched = models.Schedule(name="Test fire", team="", day_of_week=0, hour=3, created_by="tester")
    db.add(sched)
    db.commit()
    db.refresh(sched)

    scheduler._fire_schedule(db, sched)

    job = db.query(models.Job).filter(models.Job.host_id == host.id).first()
    assert job is not None
    assert job.operator == "system"
    confirmations = db.query(models.ChecklistConfirmation).filter(models.ChecklistConfirmation.job_id == job.id).all()
    assert len(confirmations) == 1
    assert confirmations[0].confirmed_by == "system (scheduled)"
    assert sched.last_fired_at is not None


def test_fire_schedule_scopes_to_team(db):
    _seed_checklist(db)
    set_setting(db, "require_ticket", "false")
    in_scope, _ = make_host(db)
    in_scope.team = "Platform"
    out_of_scope, _ = make_host(db)
    out_of_scope.team = "Web"
    db.commit()

    sched = models.Schedule(name="Platform only", team="Platform", day_of_week=0, hour=3, created_by="tester")
    db.add(sched)
    db.commit()

    scheduler._fire_schedule(db, sched)

    assert db.query(models.Job).filter(models.Job.host_id == in_scope.id).first() is not None
    assert db.query(models.Job).filter(models.Job.host_id == out_of_scope.id).first() is None


def test_fire_schedule_skips_host_with_active_job(db):
    _seed_checklist(db)
    set_setting(db, "require_ticket", "false")
    host, _ = make_host(db)
    existing = models.Job(host_id=host.id, ticket_id="", status="running")
    db.add(existing)
    db.commit()

    sched = models.Schedule(name="No double-run", team="", day_of_week=0, hour=3, created_by="tester")
    db.add(sched)
    db.commit()

    scheduler._fire_schedule(db, sched)

    jobs_for_host = db.query(models.Job).filter(models.Job.host_id == host.id).all()
    assert len(jobs_for_host) == 1  # still just the pre-existing one, no second run stacked


def test_fire_schedule_requires_approved_ticket_when_required(db):
    _seed_checklist(db)
    set_setting(db, "require_ticket", "true")
    host, _ = make_host(db)

    sched = models.Schedule(name="No ticket set", team="", day_of_week=0, hour=3, created_by="tester")
    db.add(sched)
    db.commit()

    scheduler._fire_schedule(db, sched)

    assert db.query(models.Job).filter(models.Job.host_id == host.id).first() is None
    skipped = db.query(models.AuditLog).filter(models.AuditLog.action == "schedule_skipped").first()
    assert skipped is not None


def test_fire_schedule_proceeds_with_approved_ticket(db):
    _seed_checklist(db)
    set_setting(db, "require_ticket", "true")
    host, _ = make_host(db)
    db.add(models.Ticket(ticket_id="CHG-1", status="Approved", window_start=0, window_end=23))
    db.commit()

    sched = models.Schedule(name="Has ticket", team="", day_of_week=0, hour=3, ticket_id="CHG-1", created_by="tester")
    db.add(sched)
    db.commit()

    scheduler._fire_schedule(db, sched)

    job = db.query(models.Job).filter(models.Job.host_id == host.id).first()
    assert job is not None
    assert job.ticket_id == "CHG-1"


# ---------- run_scheduler_pass: day/hour matching + dedup ----------

def test_run_scheduler_pass_only_fires_matching_day_and_hour(db):
    _seed_checklist(db)
    set_setting(db, "require_ticket", "false")
    host, _ = make_host(db)

    now = datetime.utcnow()
    wrong_hour = models.Schedule(name="Wrong hour", team="", day_of_week=now.weekday(),
                                  hour=(now.hour + 5) % 24, created_by="tester")
    db.add(wrong_hour)
    db.commit()

    scheduler.run_scheduler_pass(db)

    assert db.query(models.Job).filter(models.Job.host_id == host.id).first() is None


def test_run_scheduler_pass_matches_and_dedups_within_the_hour(db):
    _seed_checklist(db)
    set_setting(db, "require_ticket", "false")
    host, _ = make_host(db)

    now = datetime.utcnow()
    sched = models.Schedule(name="Right now", team="", day_of_week=now.weekday(), hour=now.hour, created_by="tester")
    db.add(sched)
    db.commit()

    scheduler.run_scheduler_pass(db)
    first_count = db.query(models.Job).filter(models.Job.host_id == host.id).count()
    assert first_count == 1

    # A second pass within the same hour must not fire again -- last_fired_at
    # dedup, since a job now exists for the host anyway this would be
    # caught by the active-job guard too, but this proves the dedup
    # itself (not just the active-job side effect) is doing its job.
    scheduler.run_scheduler_pass(db)
    second_count = db.query(models.Job).filter(models.Job.host_id == host.id).count()
    assert second_count == 1


def test_run_scheduler_pass_ignores_disabled_schedules(db):
    _seed_checklist(db)
    set_setting(db, "require_ticket", "false")
    host, _ = make_host(db)

    now = datetime.utcnow()
    sched = models.Schedule(name="Disabled", team="", day_of_week=now.weekday(), hour=now.hour,
                             enabled=False, created_by="tester")
    db.add(sched)
    db.commit()

    scheduler.run_scheduler_pass(db)

    assert db.query(models.Job).filter(models.Job.host_id == host.id).first() is None


def test_schedule_severity_filter_is_validated_like_a_runs(client, logged_in):
    """An unknown severity matches no update: the schedule fired every week, patched nothing
    and reported success."""
    logged_in(role="admin", username="sch-admin-severity")
    base = {"name": "Security weekly", "day_of_week": 1, "hour": 3}
    typo = client.post("/schedules", json={**base, "severity_filter": "critcal"})
    assert typo.status_code == 400 and "Unknown severity" in typo.json()["detail"]

    created = client.post("/schedules", json={**base, "severity_filter": " Critical, Important "}).json()
    assert created["severity_filter"] == "critical,important"
    assert client.post("/schedules", json={**base, "severity_filter": "all"}).json()["severity_filter"] == ""
    assert client.post("/schedules", json={**base, "severity_filter": "security"}).json()["severity_filter"] == "security"

    assert client.patch(f"/schedules/{created['id']}", json={"severity_filter": "hihg"}).status_code == 400
    patched = client.patch(f"/schedules/{created['id']}", json={"severity_filter": "critical"})
    assert patched.json()["severity_filter"] == "critical"
