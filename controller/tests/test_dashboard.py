"""
Covers app/routers/dashboard.py — the aggregated payload behind the home
page every login lands on.

The numbers here are the whole point of the endpoint (see its module
docstring on why they're computed server-side), so these assert on the
arithmetic and the ordering rules, not just on a 200.
"""
from datetime import datetime, timedelta

from app import models
from app.routers import dashboard
from conftest import make_host


def _host(db, hostname, *, seen_minutes_ago=1, patched_days_ago=1, team="platform",
          os_family="rocky9", poll_interval=900):
    host, _ = make_host(db, hostname=hostname, os_family=os_family)
    now = datetime.utcnow()
    host.team = team
    host.poll_interval_seconds = poll_interval
    host.last_seen = now - timedelta(minutes=seen_minutes_ago)
    host.last_patched = None if patched_days_ago is None else now - timedelta(days=patched_days_ago)
    db.commit()
    return host


def _clear_fleet(db):
    """These tests assert on fleet-wide totals, so they need the shared
    session database's host/job/audit tables to themselves."""
    for model in (models.ChecklistConfirmation, models.JobStage, models.Job,
                  models.AuditLog, models.Schedule, models.Host):
        db.query(model).delete()
    db.commit()


def test_requires_authentication(client):
    assert client.get("/dashboard").status_code == 401


def test_empty_fleet_reports_full_compliance_not_zero(client, db, logged_in):
    """A fresh install has nothing wrong with it — a red 0% would be
    alarming and wrong. See FleetSummary.compliance_pct."""
    _clear_fleet(db)
    logged_in("operator")

    fleet = client.get("/dashboard").json()["fleet"]

    assert fleet["total"] == 0
    assert fleet["compliance_pct"] == 100
    assert fleet["avg_days_since_patched"] is None


def test_connectivity_tiers_and_compliance(client, db, logged_in):
    _clear_fleet(db)
    logged_in("operator")
    # poll_interval 900s: stale past 2x (30min), offline past 4x (60min).
    _host(db, "healthy-1", seen_minutes_ago=5)
    _host(db, "healthy-2", seen_minutes_ago=10)
    _host(db, "stale-1", seen_minutes_ago=40)
    _host(db, "offline-1", seen_minutes_ago=600)

    fleet = client.get("/dashboard").json()["fleet"]

    assert (fleet["healthy"], fleet["stale"], fleet["offline"]) == (2, 1, 1)
    assert fleet["compliance_pct"] == 50  # 2 of 4


def test_patch_age_math(client, db, logged_in):
    _clear_fleet(db)
    logged_in("operator")
    _host(db, "recent", patched_days_ago=2)
    _host(db, "old", patched_days_ago=40)      # past STALE_PATCH_DAYS
    _host(db, "never", patched_days_ago=None)  # excluded from the average

    fleet = client.get("/dashboard").json()["fleet"]

    assert fleet["never_patched"] == 1
    assert fleet["overdue"] == 1
    assert fleet["avg_days_since_patched"] == 21  # (2 + 40) / 2, 'never' not counted


def test_attention_orders_offline_before_stale_before_unpatched(client, db, logged_in):
    _clear_fleet(db)
    logged_in("operator")
    _host(db, "z-offline", seen_minutes_ago=600)
    _host(db, "a-stale", seen_minutes_ago=40)
    _host(db, "a-unpatched", patched_days_ago=None)
    _host(db, "a-overdue", patched_days_ago=99)
    _host(db, "fine", patched_days_ago=1)

    attention = client.get("/dashboard").json()["attention"]

    assert [a["hostname"] for a in attention] == ["z-offline", "a-stale", "a-unpatched", "a-overdue"]
    assert attention[0]["tone"] == "danger"
    assert attention[3]["reason"] == "99d since patched"
    assert "fine" not in [a["hostname"] for a in attention]


def test_active_run_reports_its_current_stage(client, db, logged_in):
    _clear_fleet(db)
    logged_in("operator")
    host = _host(db, "patching-now")
    job = models.Job(host_id=host.id, hostname=host.hostname, ticket_id="CHG-1",
                     status="running", current_stage_index=2)
    db.add(job)
    db.commit()
    db.refresh(job)
    for i, (name, executor) in enumerate(models.STAGE_SEQUENCE):
        db.add(models.JobStage(job_id=job.id, stage_index=i, name=name, executor=executor,
                                status="done" if i < 2 else "pending"))
    db.commit()

    body = client.get("/dashboard").json()

    assert body["runs"]["active"] == 1
    run = body["active_runs"][0]
    assert run["hostname"] == "patching-now"
    assert run["stage"] == models.STAGE_SEQUENCE[2][0]
    assert run["total_stages"] == len(models.STAGE_SEQUENCE)


def test_run_counters_only_count_the_last_24h(client, db, logged_in):
    _clear_fleet(db)
    logged_in("operator")
    host = _host(db, "counted")
    now = datetime.utcnow()
    for status, hours_ago in [("done", 1), ("done", 5), ("failed", 2), ("done", 48)]:
        db.add(models.Job(host_id=host.id, hostname=host.hostname, ticket_id="CHG-1",
                          status=status, updated_at=now - timedelta(hours=hours_ago)))
    db.commit()

    runs = client.get("/dashboard").json()["runs"]

    assert runs["completed_24h"] == 2  # the 48h-old one is outside the window
    assert runs["failed_24h"] == 1


def test_activity_is_newest_first_by_timestamp(client, db, logged_in):
    """
    Ordered by ts, not by row id — a row whose timestamp was set
    explicitly must still sort by when it happened.
    """
    _clear_fleet(db)
    logged_in("operator")
    now = datetime.utcnow()
    # Inserted oldest-last on purpose, so id order contradicts ts order.
    db.add(models.AuditLog(ts=now - timedelta(minutes=5), actor="a", action="newer", detail=""))
    db.add(models.AuditLog(ts=now - timedelta(minutes=90), actor="a", action="older", detail=""))
    db.commit()

    actions = [a["action"] for a in client.get("/dashboard").json()["activity"]]

    assert actions.index("newer") < actions.index("older")


def test_upcoming_schedule_next_fire_skips_an_already_fired_slot(client, db, logged_in):
    _clear_fleet(db)
    logged_in("operator")
    _host(db, "sched-host", team="platform")
    now = datetime.utcnow()
    db.add(models.Schedule(name="Weekly", team="platform", day_of_week=now.weekday(),
                            hour=now.hour, enabled=True,
                            last_fired_at=now.replace(minute=0, second=0, microsecond=0)))
    db.commit()

    upcoming = client.get("/dashboard").json()["upcoming"]

    assert len(upcoming) == 1
    assert upcoming[0]["host_count"] == 1
    # This hour's slot is already handled, so the next one is a week out.
    assert datetime.fromisoformat(upcoming[0]["next_fire"]) > now + timedelta(days=6)


def test_disabled_schedules_are_not_listed(client, db, logged_in):
    _clear_fleet(db)
    logged_in("operator")
    db.add(models.Schedule(name="Off", team="", day_of_week=0, hour=3, enabled=False))
    db.commit()

    assert client.get("/dashboard").json()["upcoming"] == []


def test_next_fire_is_in_the_future_for_every_weekday_and_hour(db):
    """
    _next_fire's modular arithmetic is the kind of thing that's correct
    for the day you wrote it and wrong on Sundays — check the whole grid
    rather than today's cell.
    """
    now = datetime(2026, 9, 5, 14, 30)  # a Saturday
    for day in range(7):
        for hour in (0, 3, 14, 23):
            schedule = models.Schedule(name="s", day_of_week=day, hour=hour, enabled=True)
            fire = dashboard._next_fire(schedule, now)
            assert fire > now, (day, hour, fire)
            assert fire.weekday() == day
            assert fire.hour == hour
            assert fire - now < timedelta(days=7, hours=1)


def _pending(db, host, severity, package="pkg"):
    db.add(models.PendingUpdate(
        host_id=host.id, package=f"{package}-{host.id}", new_version="1.0",
        advisory="ADV-1", severity=severity, is_security=severity != "none"))
    db.commit()


def test_unreachable_hosts_cannot_crowd_urgent_ones_off_the_worst_off_table(client, db, logged_in):
    """
    The table is headed "ranked by severity". Sorting unreachable-first and
    then truncating meant six silent hosts pushed every Critical host off the
    Overview's only risk table — the one place an operator looks to find them.
    """
    _clear_fleet(db)
    logged_in("operator")

    # Eight hosts that have gone quiet (poll 60s, last seen hours ago).
    for i in range(8):
        _host(db, f"silent-{i}", seen_minutes_ago=600, poll_interval=60)
    # One reachable host carrying a Critical advisory.
    loud = _host(db, "critical-host", seen_minutes_ago=1)
    _pending(db, loud, "critical")

    worst = client.get("/dashboard").json()["risk"]["worst_hosts"]

    names = [r["hostname"] for r in worst]
    assert "critical-host" in names, f"urgent host fell off the table: {names}"
    assert any(r["status"] == "no_answer" for r in worst), "unreachable hosts should still appear"


def test_verified_current_excludes_a_host_that_has_gone_silent(client, db, logged_in):
    """
    A clean assessment from a week ago is not evidence the host is current
    now. Counting it made the tile disagree with the table underneath it,
    which lists the same host as "No answer".
    """
    _clear_fleet(db)
    logged_in("operator")

    fresh = _host(db, "answering", seen_minutes_ago=1)
    gone = _host(db, "silent", seen_minutes_ago=600, poll_interval=60)
    for h in (fresh, gone):
        h.updates_assessed_ok = True
    db.commit()

    risk = client.get("/dashboard").json()["risk"]

    assert risk["verified_current"] == 1, "only the host still answering is verifiably current"
