"""
Covers app/jobs_engine.py — the state machine every run walks through.
Constructs Job/JobStage rows directly (mirroring what routers/runs.py's
create_run does) rather than going through the HTTP API, so these tests
exercise the engine in isolation from ticket/checklist gating.
"""
import time
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app import models, jobs_engine
from conftest import make_host


def _make_job(db, host):
    job = models.Job(host_id=host.id, ticket_id="TEST-1", operator="tester", operator_role="admin")
    db.add(job)
    db.commit()
    db.refresh(job)
    for i, (name, executor) in enumerate(models.STAGE_SEQUENCE):
        db.add(models.JobStage(job_id=job.id, stage_index=i, name=name, executor=executor))
    db.commit()
    db.refresh(job)
    return job


def _stage(job, name):
    return next(s for s in job.stages if s.name == name)


@pytest.fixture(autouse=True)
def _no_real_snapshot_or_sleep():
    """Every test in this file drives the full pipeline, so keep the
    controller-side stages fast and network-free unconditionally. The
    snapshot stage now dispatches through app.rollback -> app.proxmox
    (see jobs_engine.py) rather than calling create_snapshot directly,
    so that's the patch target now. No task id comes back, so the stage
    finishes inline; waiting on a real task is tested on its own below."""
    with patch("app.proxmox.create_snapshot", return_value={}), \
         patch("app.proxmox.resolve_vm_node", return_value="pve1"), \
         patch("app.jobs_engine.settings") as mock_settings:
        mock_settings.soak_seconds = 0
        yield


def test_advance_stops_at_first_agent_stage(db):
    host, _ = make_host(db)
    job = _make_job(db, host)

    job = jobs_engine.advance_job(db, job)

    assert job.status == "running"
    assert _stage(job, "preflight").status == "running"
    assert _stage(job, "excludes").status == "pending"


def test_report_done_advances_to_next_agent_stage(db):
    host, _ = make_host(db)
    job = _make_job(db, host)
    job.rollback_backend = "none"        # the snapshot stage in between finishes inline
    db.commit()
    jobs_engine.advance_job(db, job)

    job = jobs_engine.report_agent_stage(db, job, "preflight", "done", "all good")

    assert _stage(job, "preflight").status == "done"
    assert _stage(job, "preflight").output == "all good"
    # the snapshot (controller, done inline here) comes before excludes now
    assert _stage(job, "snapshot").status == "done"
    assert _stage(job, "excludes").status == "running"


def test_reporting_wrong_stage_name_raises(db):
    host, _ = make_host(db)
    job = _make_job(db, host)
    jobs_engine.advance_job(db, job)  # now sitting at preflight

    with pytest.raises(ValueError):
        jobs_engine.report_agent_stage(db, job, "patch", "done", "wrong stage entirely")


def test_report_failed_stops_the_job(db):
    host, _ = make_host(db)
    job = _make_job(db, host)
    jobs_engine.advance_job(db, job)

    job = jobs_engine.report_agent_stage(db, job, "preflight", "failed", "disk full")

    assert job.status == "failed"
    assert _stage(job, "preflight").status == "failed"
    assert _stage(job, "excludes").status == "pending"  # never dispatched

    # Calling advance_job again on an already-failed job is a no-op, not
    # a crash or a silent resurrection of the run.
    job = jobs_engine.advance_job(db, job)
    assert job.status == "failed"


def test_full_pipeline_reaches_done_and_updates_host(db, legacy_proxmox):
    host, _ = make_host(db)
    host.proxmox_vmid = 100  # snapshot stage refuses to run without one — see jobs_engine.py
    db.commit()
    job = _make_job(db, host)
    job = jobs_engine.advance_job(db, job)

    for stage_name, executor in models.STAGE_SEQUENCE:
        if executor != "agent":
            continue  # controller stages (snapshot/soak) advance on their own
        assert _stage(job, stage_name).status == "running", f"expected {stage_name} to be running"
        job = jobs_engine.report_agent_stage(db, job, stage_name, "done", f"{stage_name} ok")

    assert job.status == "done"
    db.refresh(host)
    assert host.status == "healthy"
    assert host.last_patched is not None


def test_os_script_flips_from_untested_to_tested_on_first_success(db):
    host, _ = make_host(db, os_family="rocky9")
    script = models.OsScript(os_family="rocky9", stage_name="preflight", content="#!/bin/bash\nexit 0\n")
    db.add(script)
    db.commit()

    job = _make_job(db, host)
    jobs_engine.advance_job(db, job)
    jobs_engine.report_agent_stage(db, job, "preflight", "done", "ran the custom script")

    db.refresh(script)
    assert script.tested is True


def _drive_to_soak(db, host):
    """Walk a job through every agent stage so it's sitting on soak."""
    job = _make_job(db, host)
    job = jobs_engine.advance_job(db, job)
    for stage_name, executor in models.STAGE_SEQUENCE:
        if executor == "agent":
            job = jobs_engine.report_agent_stage(db, job, stage_name, "done", f"{stage_name} ok")
    return job


def test_soak_defers_instead_of_blocking_the_reporting_request(db, legacy_proxmox):
    """
    The healthcheck report is what pushes a job onto soak, and the agent
    sends it with a 15s client timeout. A blocking sleep here made every
    successful run look like a failed report to the agent — so the stage
    must come back 'running', promptly, with the job not yet done.
    """
    host, _ = make_host(db)
    host.proxmox_vmid = 100
    db.commit()
    with patch("app.jobs_engine.settings") as mock_settings:
        mock_settings.soak_seconds = 300
        started = time.monotonic()
        job = _drive_to_soak(db, host)
        elapsed = time.monotonic() - started

    assert elapsed < 1, f"reporting blocked for {elapsed:.1f}s instead of deferring the wait"
    assert job.status == "running"
    assert _stage(job, "soak").status == "running"
    assert _stage(job, "soak").started_at is not None


def test_deferred_soak_completes_only_once_the_wait_has_elapsed(db, legacy_proxmox):
    host, _ = make_host(db)
    host.proxmox_vmid = 100
    db.commit()
    with patch("app.jobs_engine.settings") as mock_settings:
        mock_settings.soak_seconds = 300
        job = _drive_to_soak(db, host)

        # Nothing to do yet — the soak only just started.
        jobs_engine.complete_due_controller_stages(db)
        db.refresh(job)
        assert job.status == "running"
        assert _stage(job, "soak").status == "running"

        # Backdate past the threshold rather than actually waiting 300s.
        soak = _stage(job, "soak")
        soak.started_at = datetime.utcnow() - timedelta(seconds=301)
        db.commit()

        jobs_engine.complete_due_controller_stages(db)

    db.refresh(job)
    assert job.status == "done"
    assert _stage(job, "soak").status == "done"
    db.refresh(host)
    assert host.status == "healthy"
    assert host.last_patched is not None


def test_deferred_soak_pass_ignores_jobs_waiting_on_an_agent(db):
    """A job parked on an agent stage must never be swept up by the
    deferred pass — that stage completes only when the host reports."""
    host, _ = make_host(db)
    job = _make_job(db, host)
    jobs_engine.advance_job(db, job)  # sitting on preflight, an agent stage

    jobs_engine.complete_due_controller_stages(db)

    db.refresh(job)
    assert job.status == "running"
    assert _stage(job, "preflight").status == "running"
    assert job.current_stage_index == 0


def test_late_report_after_job_already_failed_does_not_resurrect_it(db):
    host, _ = make_host(db)
    job = _make_job(db, host)
    jobs_engine.advance_job(db, job)
    jobs_engine.report_agent_stage(db, job, "preflight", "failed", "boom")

    # A stale/late report for the stage that already failed the job.
    with pytest.raises(ValueError):
        jobs_engine.report_agent_stage(db, job, "excludes", "done", "too late")


def _drive_to_snapshot(db, host, upid="UPID:pve1:0001:snap"):
    """Report the agent stage before the snapshot, with Proxmox handing back a task id."""
    job = _make_job(db, host)
    job.rollback_backend = "proxmox"
    db.commit()
    job = jobs_engine.advance_job(db, job)
    with patch("app.proxmox.create_snapshot", return_value={"data": upid}):
        job = jobs_engine.report_agent_stage(db, job, "preflight", "done", "preflight ok")
    return job


def test_snapshot_waits_for_its_proxmox_task_before_patching(db, legacy_proxmox):
    """Proxmox only accepts the snapshot request; patching must not start until the task has finished."""
    host, _ = make_host(db)
    host.proxmox_vmid = 100
    db.commit()
    job = _drive_to_snapshot(db, host)
    assert _stage(job, "snapshot").status == "running"
    assert _stage(job, "excludes").status == "pending"

    with patch("app.proxmox.task_finished", return_value=False) as asked:
        jobs_engine.complete_due_controller_stages(db)
    assert asked.call_args.args[1:] == ("pve1", "UPID:pve1:0001:snap")
    db.refresh(job)
    assert _stage(job, "snapshot").status == "running"
    assert _stage(job, "excludes").status == "pending"

    with patch("app.proxmox.task_finished", return_value=True):
        jobs_engine.complete_due_controller_stages(db)
    db.refresh(job)
    assert _stage(job, "snapshot").status == "done"
    assert "created for VM 100" in _stage(job, "snapshot").output
    assert _stage(job, "excludes").status == "running"


def test_failed_snapshot_task_stops_the_run_before_patching(db, legacy_proxmox):
    from app.proxmox import ProxmoxTaskFailed
    host, _ = make_host(db)
    host.proxmox_vmid = 100
    host.status = "locked"
    db.commit()
    job = _drive_to_snapshot(db, host)

    with patch("app.proxmox.task_finished", side_effect=ProxmoxTaskFailed("Proxmox task failed: storage full")):
        jobs_engine.complete_due_controller_stages(db)
    db.refresh(job)
    db.refresh(host)
    assert job.status == "failed"
    assert _stage(job, "snapshot").status == "failed"
    assert "storage full" in _stage(job, "snapshot").output
    assert _stage(job, "excludes").status == "pending"
    assert host.status == "unknown"


def test_unreachable_proxmox_keeps_waiting_until_the_timeout(db, legacy_proxmox):
    from app import rollback
    host, _ = make_host(db)
    host.proxmox_vmid = 100
    db.commit()
    job = _drive_to_snapshot(db, host)

    with patch("app.proxmox.task_finished", side_effect=ConnectionError("no route")):
        jobs_engine.complete_due_controller_stages(db)
        db.refresh(job)
        assert job.status == "running"
        assert _stage(job, "snapshot").status == "running"

        snap = _stage(job, "snapshot")
        snap.started_at = datetime.utcnow() - timedelta(seconds=rollback.SNAPSHOT_TIMEOUT_SECONDS + 1)
        db.commit()
        jobs_engine.complete_due_controller_stages(db)
    db.refresh(job)
    assert job.status == "failed"
    assert "wasn't confirmed by Proxmox" in _stage(job, "snapshot").output
    assert _stage(job, "excludes").status == "pending"


def test_a_report_for_another_stage_is_a_409_not_a_500(client, db):
    host, secret = make_host(db)
    job = _make_job(db, host)
    jobs_engine.advance_job(db, job)  # on preflight
    r = client.post(f"/agent/{host.id}/jobs/{job.id}/stages/patch/report",
                    headers={"Authorization": f"Bearer {secret}"}, json={"status": "done", "output": "late"})
    assert r.status_code == 409 and "preflight" in r.json()["detail"]


def test_a_cancelled_run_never_moves_on(db):
    host, _ = make_host(db)
    job = _make_job(db, host)
    jobs_engine.advance_job(db, job)
    job.status = "cancelled"
    _stage(job, "preflight").status = "done"
    db.commit()
    jobs_engine.advance_job(db, job)
    assert job.status == "cancelled" and _stage(job, "excludes").status == "pending"


# ---------- runs nobody collected ----------
# A step handed to an agent waits to be polled for. With the machine off,
# the run used to wait for good and start whenever the agent came back.

def _waiting_run(db, hours_ago, last_seen_hours_ago=None, poll_interval=900):
    from app.settings_store import set_setting
    set_setting(db, "run_start_timeout_hours", "4")
    host, _ = make_host(db)
    host.status, host.poll_interval_seconds, host.rollback_backend = "locked", poll_interval, "none"
    now = datetime.utcnow()
    host.last_seen = None if last_seen_hours_ago is None else now - timedelta(hours=last_seen_hours_ago)
    job = _make_job(db, host)
    jobs_engine.advance_job(db, job)
    stage = _stage(job, "preflight")
    assert stage.status == "running"
    stage.started_at = now - timedelta(hours=hours_ago)
    db.commit()
    return host, job, stage


def test_a_run_its_machine_never_collected_is_cancelled(db):
    host, job, stage = _waiting_run(db, hours_ago=5, last_seen_hours_ago=9)
    assert jobs_engine.expire_unstarted_runs(db) >= 1
    db.refresh(job)
    db.refresh(host)
    assert job.status == "cancelled" and stage.status == "failed" and "Expired" in stage.output
    assert host.status == "unknown"                       # free for another run
    expired = db.query(models.AuditLog).filter(models.AuditLog.action == "run_expired").all()
    assert any(host.hostname in (r.detail or "") for r in expired)


def test_a_run_inside_its_wait_is_left_alone(db):
    _, job, _ = _waiting_run(db, hours_ago=3, last_seen_hours_ago=9)
    jobs_engine.expire_unstarted_runs(db)
    db.refresh(job)
    assert job.status == "running"


def test_a_run_the_machine_has_polled_for_is_never_expired(db):
    """It may be doing the work: slow or dead is a person's call, not a timer's."""
    _, job, _ = _waiting_run(db, hours_ago=30, last_seen_hours_ago=29)
    jobs_engine.expire_unstarted_runs(db)
    db.refresh(job)
    assert job.status == "running"


def test_a_machine_that_checks_in_rarely_gets_two_of_its_own_intervals(db):
    _, job, _ = _waiting_run(db, hours_ago=5, last_seen_hours_ago=9, poll_interval=6 * 3600)
    jobs_engine.expire_unstarted_runs(db)
    db.refresh(job)
    assert job.status == "running"                        # 5h waited, but it only checks in every 6h


def test_expiry_can_be_turned_off_and_the_setting_is_validated(db, client, logged_in):
    from app.settings_store import set_setting
    _, job, _ = _waiting_run(db, hours_ago=500, last_seen_hours_ago=600)
    set_setting(db, "run_start_timeout_hours", "0")
    assert jobs_engine.expire_unstarted_runs(db) == 0
    db.refresh(job)
    assert job.status == "running"

    logged_in(role="admin", username="expiry-admin")
    assert client.put("/settings/run_start_timeout_hours", json={"value": "soon"}).status_code == 400
    assert client.put("/settings/run_start_timeout_hours", json={"value": "12"}).status_code == 200
    job.status = "cancelled"                              # don't leave a 500-hour-old run for other tests' passes
    db.commit()
