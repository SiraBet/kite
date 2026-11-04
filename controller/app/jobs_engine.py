"""
Core run engine.

A Job walks STAGE_SEQUENCE in order. Each stage is either:
  - 'controller': executed here (currently: snapshot, soak)
  - 'agent': the controller marks it 'running' and waits — the target
    host's agent polls, sees it, executes locally (dnf, reboot, etc.),
    and reports back via /agent/jobs/{id}/stages/{name}/report, which
    calls advance_job() again to keep the pipeline moving.

A controller stage finishes one of two ways. Most run inline and are
done by the time advance_job() returns. A stage that has to wait --
soak for time to pass, a Proxmox snapshot for Proxmox to finish taking
it -- instead returns WAITING: it stays 'running' with a started_at,
and complete_due_controller_stages() finishes it once the wait is over. Nothing blocks the request that triggered it
— see WAITING below for why that matters.

This keeps the split explicit: nothing here ever tries to SSH into a
host directly. The agent owns the guest; the controller owns the
hypervisor (Proxmox) and orchestration.
"""
import asyncio
from datetime import datetime

from sqlalchemy.orm import Session

from . import models, audit, groups, monitoring, rollback, snapshot_retention
from .config import settings
from .logging_config import logger

# _run_controller_stage outcomes.
DONE, FAILED, WAITING = "done", "failed", "waiting"


def _release_host_after_failure(job: models.Job):
    """
    A run locks its host at creation (routers/runs.py) and only success
    unlocked it, so every failed run left its host shown as "Patching"
    indefinitely. A failed run leaves the host in whatever state the
    failure left it -- the same honest "unknown" a force-stop sets, never
    "healthy". Only a lock is released: a status something else set since
    is left alone.
    """
    if job.host and job.host.status == "locked":
        job.host.status = "unknown"


def _run_controller_stage(db: Session, job: models.Job, stage: models.JobStage) -> str:
    """
    Execute a controller-side stage. Returns DONE, FAILED, or WAITING
    (stage left 'running' for complete_due_controller_stages to finish).
    """
    stage.status = "running"
    stage.started_at = datetime.utcnow()
    db.commit()

    host = job.host
    try:
        if stage.name == "snapshot":
            # Frozen at job creation (see routers/runs.py) rather than
            # re-resolved here — a mid-run Settings change can't leave
            # this stage's already-fixed 'controller' executor pointing
            # at a backend that actually needed the agent instead.
            backend_name = job.rollback_backend or rollback.resolve_backend_name(db, host)
            stage.output = rollback.run_controller_snapshot(db, job, backend_name)
            if rollback.snapshot_pending(stage.output):
                # Proxmox took the request; patching waits until the
                # snapshot actually exists, without blocking the agent's
                # report that got us here.
                db.commit()
                return WAITING

        elif stage.name == "soak":
            # A deliberate wait, not work, so it must not block the
            # request that triggered it. That request is the agent's
            # healthcheck report, sent with a 15s client timeout, while
            # soak_seconds defaults to 20 and is configurable higher:
            # sleeping inline would time the agent out on every
            # otherwise-successful run and hold a threadpool worker idle
            # for the duration. Deferring also lets the wait survive a
            # controller restart, which an in-process sleep cannot.
            if settings.soak_seconds > 0:
                return WAITING
            stage.output = _soak_output()

        else:
            raise RuntimeError(f"Unknown controller stage '{stage.name}'")

        stage.status = "done"
        stage.finished_at = datetime.utcnow()
        db.commit()
        return DONE

    except Exception as e:  # noqa: BLE001 — surface any failure to the job record
        _fail_controller_stage(db, job, stage, str(e))
        return FAILED


def _fail_controller_stage(db: Session, job: models.Job, stage: models.JobStage, error: str):
    stage.status = "failed"
    stage.output = error
    stage.finished_at = datetime.utcnow()
    job.status = "failed"
    _release_host_after_failure(job)
    db.commit()
    audit.log(db, actor="system", role="controller", action="stage_failed",
              detail=f"job {job.id} — {stage.name}: {error}", tone="danger")
    monitoring.stage_failures_total.labels(stage=stage.name).inc()


def _soak_output() -> str:
    return f"Waited {settings.soak_seconds}s after the health check before calling the run done"


def job_finished(db: Session, job: models.Job):
    """A run ended (done, failed or force-stopped). If it's one machine of a batch, the batch moves on."""
    if job.batch_id:
        from . import batches   # local: batches starts runs through routers/runs.py, which imports this module
        batches.on_job_finished(db, job)


def advance_job(db: Session, job: models.Job):
    """
    Move a job forward as far as it can go right now.
    Call this after job creation, and again every time an agent reports
    a stage as done — it's idempotent-ish: safe to call repeatedly.
    """
    if job.status in ("failed", "done", "cancelled"):
        return job

    stages = sorted(job.stages, key=lambda s: s.stage_index)

    while job.current_stage_index < len(stages):
        stage = stages[job.current_stage_index]

        if stage.status == "done":
            job.current_stage_index += 1
            db.commit()
            continue

        if stage.status in ("pending",):
            job.status = "running"
            db.commit()
            if stage.executor == "controller":
                result = _run_controller_stage(db, job, stage)
                if result == FAILED:
                    job_finished(db, job)
                if result in (FAILED, WAITING):
                    return job
                job.current_stage_index += 1
                db.commit()
                continue
            else:
                # agent stage: mark running, wait for the agent to report back
                stage.status = "running"
                stage.started_at = datetime.utcnow()
                db.commit()
                return job

        if stage.status == "running":
            # Already dispatched — either an agent stage awaiting its
            # report, or a WAITING controller stage that
            # complete_due_controller_stages() will finish. Either way,
            # nothing to do from here.
            return job

        if stage.status == "failed":
            job.status = "failed"
            _release_host_after_failure(job)
            db.commit()
            job_finished(db, job)
            return job

    # walked off the end — all stages done
    job.status = "done"
    job.updated_at = datetime.utcnow()
    host = job.host
    host.last_patched = datetime.utcnow()
    host.status = "healthy"
    db.commit()
    audit.log(db, actor="system", role="controller", action="run_completed",
              detail=f"{host.hostname} — job {job.id}, ticket {job.ticket_id}", tone="success")
    if host.proxmox_vmid and snapshot_retention.policy(db)["enabled"]:
        snapshot_retention.clean_after_run(host.id)
    job_finished(db, job)
    return job


def _stamp_container_captures(db: Session, job: models.Job):
    """
    Record when each selected service's rollback point was taken.

    The agent reports whether a capture exists, but not its age — the
    capture is a tag on an image whose own creation date is the image's,
    not the tag's. The controller knows when the run that took it
    finished, which is the number an operator actually wants.
    """
    chosen = {n.strip() for n in (job.container_selection or "").splitlines() if n.strip()}
    rows = db.query(models.Container).filter(models.Container.host_id == job.host_id).all()
    now = datetime.utcnow()
    for row in rows:
        if chosen and row.name not in chosen:
            continue
        if row.managed_by == "compose":
            row.rollback_available = True
            row.rollback_captured_at = now
    db.commit()


def _waited_long_enough(stage: models.JobStage, now: datetime) -> bool:
    if not stage.started_at:
        return True  # no start time to measure against — don't strand the job
    return (now - stage.started_at).total_seconds() >= settings.soak_seconds


def complete_due_controller_stages(db: Session) -> int:
    """
    Finish every WAITING controller stage whose wait is over -- a soak
    that has run its time, a snapshot Proxmox has finished taking -- and
    push its job forward (or fail it, when the snapshot failed). Driven by deferred_loop() below, but written as
    a plain function so it's directly testable and so a controller
    restart mid-wait resumes from DB state rather than losing the stage.
    Returns how many stages were completed.
    """
    now = datetime.utcnow()
    completed = 0
    for job in db.query(models.Job).filter(models.Job.status == "running").all():
        stages = sorted(job.stages, key=lambda s: s.stage_index)
        if job.current_stage_index >= len(stages):
            continue
        stage = stages[job.current_stage_index]
        if stage.executor != "controller" or stage.status != "running":
            continue
        if stage.name == "soak":
            if not _waited_long_enough(stage, now):
                continue
            output = _soak_output()
        elif stage.name == "snapshot" and rollback.snapshot_pending(stage.output):
            waited = (now - stage.started_at).total_seconds() if stage.started_at else 0
            try:
                output = rollback.snapshot_progress(db, job, stage.output, waited)
            except Exception as e:  # noqa: BLE001 — the run stops here, before patching
                _fail_controller_stage(db, job, stage, str(e))
                job_finished(db, job)
                completed += 1
                continue
            if output is None:
                continue
        else:
            continue
        stage.status = "done"
        stage.output = output
        stage.finished_at = now
        db.commit()
        advance_job(db, job)
        completed += 1
    return completed


async def deferred_loop():
    """
    Started as a background asyncio task on app startup (see main.py).
    Short interval by design — this is what turns a job's soak wait into
    job completion, so it's the floor on how quickly a finished run shows
    as finished. Same never-die-on-one-bad-pass handling as the monitor
    and scheduler loops.
    """
    from .db import SessionLocal

    def one_pass():
        db = SessionLocal()
        try:
            return complete_due_controller_stages(db)
        finally:
            db.close()

    while True:
        try:
            # In a thread: a pass can ask Proxmox about snapshot tasks,
            # and the server must keep answering while it waits.
            completed = await asyncio.to_thread(one_pass)
            if completed:
                logger.info("deferred_stages_completed count=%s", completed)
        except Exception:  # noqa: BLE001 — one bad pass must never kill the loop
            logger.exception("deferred controller-stage pass failed")
        await asyncio.sleep(settings.deferred_stage_interval_seconds)


def report_agent_stage(db: Session, job: models.Job, stage_name: str, status: str, output: str):
    """Called from the agent-facing API when a host reports stage completion."""
    stages = sorted(job.stages, key=lambda s: s.stage_index)
    current = stages[job.current_stage_index]
    if current.name != stage_name:
        raise ValueError(f"Agent reported stage '{stage_name}' but job is on '{current.name}'")

    current.output = output
    current.finished_at = datetime.utcnow()
    if status == "done":
        current.status = "done"
        # If an OS-specific script was used for this stage, this is proof it
        # works on at least one real host — clear the "untested" warning.
        if current.name == "containers" and (job.container_action or "update") == "update":
            _stamp_container_captures(db, job)
        os_script = groups.script_for(db, job.host, current.name)
        # Only the script that ran: one uploaded after this stage started
        # replaced it, and hasn't been run by anything yet.
        ran_it = os_script and (not current.started_at or not os_script.uploaded_at
                                or os_script.uploaded_at <= current.started_at)
        if ran_it and not os_script.tested:
            os_script.tested = True
        db.commit()
        audit.log(db, actor=job.operator, role=job.operator_role, action="stage_done",
                  detail=f"job {job.id} — {stage_name}", tone="neutral")
        return advance_job(db, job)
    else:
        current.status = "failed"
        job.status = "failed"
        _release_host_after_failure(job)
        db.commit()
        audit.log(db, actor=job.operator, role=job.operator_role, action="stage_failed",
                  detail=f"job {job.id} — {stage_name}: {output}", tone="danger")
        monitoring.stage_failures_total.labels(stage=stage_name).inc()
        job_finished(db, job)
        return job
