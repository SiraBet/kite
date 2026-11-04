"""A failed run must not leave its host locked ("Patching") forever."""
from app import jobs_engine, models, monitoring
from conftest import make_host


def _job(db, host, status="running"):
    job = models.Job(host_id=host.id, hostname=host.hostname, ticket_id="CHG-1", status=status)
    db.add(job)
    db.flush()
    db.add(models.JobStage(job_id=job.id, stage_index=0, name="patch", executor="agent", status="running"))
    db.commit()
    db.refresh(job)
    return job


def test_agent_reported_failure_releases_the_lock(db):
    host, _ = make_host(db)
    host.status = "locked"
    job = _job(db, host)
    jobs_engine.report_agent_stage(db, job, "patch", "failed", "dnf exploded")
    db.refresh(host)
    assert job.status == "failed" and host.status == "unknown"


def test_monitor_releases_an_orphaned_lock_but_not_a_live_one(db):
    stuck, _ = make_host(db)
    stuck.status = "locked"
    live, _ = make_host(db)
    live.status = "locked"
    _job(db, live)
    _job(db, stuck, status="failed")
    assert monitoring.release_orphaned_locks(db) >= 1
    db.refresh(stuck)
    db.refresh(live)
    assert stuck.status == "unknown" and live.status == "locked"
    assert db.query(models.AuditLog).filter(models.AuditLog.action == "host_unlocked",
                                            models.AuditLog.detail.contains(stuck.hostname)).count() == 1
