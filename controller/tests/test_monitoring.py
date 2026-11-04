from datetime import datetime, timedelta

from app import models, monitoring
from conftest import make_host


def _make_job_with_stage(db, host, stage_name, executor, started_minutes_ago):
    """current_stage_index must point at stage_name -- that's how the
    engine (and monitoring.py) knows which stage is actually 'in flight'
    for this job, same as advance_job() sets it in production."""
    target_index = [name for name, _ in models.STAGE_SEQUENCE].index(stage_name)
    job = models.Job(host_id=host.id, ticket_id="", status="running", current_stage_index=target_index)
    db.add(job)
    db.commit()
    db.refresh(job)

    for i, (name, ex) in enumerate(models.STAGE_SEQUENCE):
        status = "pending"
        started_at = None
        if name == stage_name:
            status = "running"
            started_at = datetime.utcnow() - timedelta(minutes=started_minutes_ago)
        db.add(models.JobStage(job_id=job.id, stage_index=i, name=name, executor=ex,
                                status=status, started_at=started_at))
    db.commit()
    db.refresh(job)
    return job


def test_connectivity_tier_healthy_stale_offline(db):
    host, _ = make_host(db)
    host.poll_interval_seconds = 100

    host.last_seen = datetime.utcnow()
    assert monitoring.connectivity_tier(host) == "healthy"

    host.last_seen = datetime.utcnow() - timedelta(seconds=250)  # > 2x baseline
    assert monitoring.connectivity_tier(host) == "stale"

    host.last_seen = datetime.utcnow() - timedelta(seconds=500)  # > 4x baseline
    assert monitoring.connectivity_tier(host) == "offline"

    host.last_seen = None
    assert monitoring.connectivity_tier(host) == "offline"


def test_is_stage_stuck_uses_shorter_reboot_threshold(db):
    host, _ = make_host(db)

    job = _make_job_with_stage(db, host, "reboot", "agent", started_minutes_ago=20)
    stage = job.stages[4]  # reboot is index 4 in STAGE_SEQUENCE
    assert stage.name == "reboot"
    assert monitoring.is_stage_stuck(stage) is True  # 20 > STUCK_REBOOT_MINUTES (15)

    other, _ = make_host(db)      # one active run per machine
    job2 = _make_job_with_stage(db, other, "patch", "agent", started_minutes_ago=20)
    stage2 = job2.stages[3]
    assert stage2.name == "patch"
    assert monitoring.is_stage_stuck(stage2) is False  # 20 < STUCK_STAGE_MINUTES (60)


def test_is_stage_stuck_ignores_non_running_and_controller_stages(db):
    host, _ = make_host(db)
    job = _make_job_with_stage(db, host, "snapshot", "controller", started_minutes_ago=999)
    stage = next(s for s in job.stages if s.name == "snapshot")
    assert monitoring.is_stage_stuck(stage) is False  # controller-executed, not agent


def test_detect_and_log_transitions_logs_stuck_stage_once(db):
    """
    Scoped to this test's own host/stage via the detail string rather than
    a before/after global count -- other tests in this file also leave
    'running' reboot stages behind in the shared DB (never rolled back
    between tests), which a global count would wrongly pick up too.
    """
    host, _ = make_host(db)
    job = _make_job_with_stage(db, host, "reboot", "agent", started_minutes_ago=99)
    stage_id = job.stages[4].id

    monitoring.detect_and_log_transitions(db)
    monitoring.detect_and_log_transitions(db)  # second pass must not double-log

    matches = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.action == "stage_stuck", models.AuditLog.detail.like(f"%{host.hostname}%"))
        .all()
    )
    assert len(matches) == 1
    assert stage_id in monitoring._stuck_seen


def test_detect_and_log_transitions_logs_host_offline_only_on_transition(db):
    """Scoped by hostname in the detail string, same reasoning as the
    stuck-stage test above -- a brand-new host has no entry in
    monitoring._last_tier yet, so no need to clear it."""
    host, _ = make_host(db)
    host.poll_interval_seconds = 60
    host.last_seen = datetime.utcnow() - timedelta(seconds=1000)  # already offline
    db.commit()

    def offline_events():
        return (
            db.query(models.AuditLog)
            .filter(models.AuditLog.action == "host_offline", models.AuditLog.detail.like(f"%{host.hostname}%"))
            .count()
        )

    monitoring.detect_and_log_transitions(db)  # first observation: no prior tier, no transition logged
    assert offline_events() == 0

    host.last_seen = datetime.utcnow()  # comes back healthy
    db.commit()
    monitoring.detect_and_log_transitions(db)

    host.last_seen = datetime.utcnow() - timedelta(seconds=1000)  # goes offline again -> real transition
    db.commit()
    monitoring.detect_and_log_transitions(db)
    assert offline_events() == 1


def test_render_metrics_exposes_expected_series(db):
    make_host(db)
    body = monitoring.render_metrics(db).decode()
    assert "kite_hosts_connectivity" in body
    assert "kite_hosts_status" in body
    assert "kite_jobs_status" in body
    assert "kite_jobs_stuck" in body


def test_metrics_endpoint_is_reachable_without_auth(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "kite_hosts_connectivity" in resp.text
