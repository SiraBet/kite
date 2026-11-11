"""
Recurring patch runs -- "patch Tuesday, automatically". See
models.Schedule for the data model and the trade-offs baked into it
(weekly-only, UTC, no "Nth weekday of the month" support yet).

Job creation here deliberately mirrors routers/runs.py's create_run
rather than calling it -- a schedule firing skips two things a real
human-initiated run always does: the maintenance-window check (the
schedule's own day/hour IS the intended window, there's no "outside
window" concept for something that chose its own time) and checklist
confirmation by an actual person (nobody's there to click checkboxes at
3am UTC on a schedule). Ticket gating is NOT skipped -- see _ticket_ok.
Keeping this separate from create_run, instead of threading skip-window/
auto-confirm flags through it, keeps the human-initiated path's logic
untouched and exactly as tested.
"""
import asyncio
from datetime import datetime
from types import SimpleNamespace

from sqlalchemy.exc import IntegrityError

from . import models, audit, batches, jobs_engine, rollback
from .config import settings
from .logging_config import logger
from .settings_store import get_setting


def _hosts_in_scope(db, schedule: models.Schedule):
    q = db.query(models.Host)
    if schedule.team:
        q = q.filter(models.Host.team == schedule.team)
    return q.all()


def _ticket_ok(db, schedule: models.Schedule):
    """Checked fresh every time a schedule is about to fire, not just
    when it was created -- a ticket approved last week could have been
    revoked, expired, or never actually gotten approved."""
    if get_setting(db, "require_ticket") != "true":
        return True, None
    if not schedule.ticket_id:
        return False, "require_ticket is on and this schedule has no ticket_id set"
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_id == schedule.ticket_id).first()
    if not ticket:
        return False, f"ticket {schedule.ticket_id} not found"
    if ticket.status != "Approved":
        return False, f"ticket {schedule.ticket_id} is not Approved (status: {ticket.status})"
    return True, None


def _container_selection_for(db, host, scope, selection):
    """
    Newline-separated container names this scheduled run may update, or
    None when the host has nothing it can update and the run would be
    pointless.

    Resolved per host at fire time, not when the schedule was created: a
    weekly schedule across a team should pick up whatever each host is
    running that week, and a container added since then is exactly what
    the schedule is for.
    """
    if scope == models.SCOPE_OS:
        return ""
    updatable = sorted(
        c.name for c in db.query(models.Container).filter(models.Container.host_id == host.id).all()
        if c.updatable
    )
    chosen = [n.strip() for n in (selection or "").splitlines() if n.strip()]
    if chosen:
        updatable = [n for n in updatable if n in chosen]
    if not updatable:
        return None if scope == models.SCOPE_CONTAINERS else ""
    return "\n".join(updatable)


NO_CONTAINERS = "it has no compose-managed containers to update"
ALREADY_RUNNING = "it already has a run in progress"


def _run_spec(db, schedule: models.Schedule) -> dict:
    """
    What every run this firing starts has in common. A plain dict, because
    a staged rollout keeps it on its batch and starts the later machines'
    runs from it long after this pass has returned.
    """
    return {
        "name": schedule.name, "ticket_id": schedule.ticket_id or "",
        "scope": schedule.scope or models.SCOPE_OS,
        "container_selection": schedule.container_selection or "",
        "severity_filter": schedule.severity_filter or "",
        "checklist": [item.text for item in db.query(models.ChecklistItem).order_by(models.ChecklistItem.id).all()],
    }


def start_host_run(db, host: models.Host, spec: dict, batch_id: int = None):
    """Start one machine's scheduled run. Returns None, or why it didn't start."""
    already_active = (
        db.query(models.Job)
        .filter(models.Job.host_id == host.id, models.Job.status.in_(["queued", "running"]))
        .first()
    )
    if already_active:
        return ALREADY_RUNNING  # same guard routers/runs.py's create_run uses -- don't stack a second run on a locked host

    backend_name = rollback.resolve_backend_name(db, host)
    scope = spec["scope"]
    selection = _container_selection_for(db, host, scope, spec["container_selection"])
    if selection is None:
        # This schedule updates containers, and this host has none it can
        # update: a run would have nothing to do.
        return NO_CONTAINERS
    job = models.Job(
        host_id=host.id, hostname=host.hostname, ticket_id=spec["ticket_id"],
        operator="system", operator_role="admin", rollback_backend=backend_name,
        scope=scope, container_selection=selection,
        severity_filter=spec["severity_filter"], batch_id=batch_id,
    )
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()   # a run was started on it just now: same as already_active above
        return ALREADY_RUNNING
    db.refresh(job)

    for i, (name, executor) in enumerate(models.stages_for(scope)):
        if name == "snapshot":
            executor = rollback.stage_executor_for(backend_name)
        db.add(models.JobStage(job_id=job.id, stage_index=i, name=name, executor=executor))
    for i, text in enumerate(spec["checklist"]):
        # Visibly not a human confirmation -- confirmed_by says so
        # explicitly rather than attributing it to whichever admin
        # happened to create the schedule.
        db.add(models.ChecklistConfirmation(
            job_id=job.id, item_index=i, item_text=text, confirmed_by="system (scheduled)",
        ))
    db.commit()
    db.refresh(job)

    host.status = "locked"
    db.commit()

    jobs_engine.advance_job(db, job)
    return None


def _fire_schedule(db, schedule: models.Schedule):
    ok, reason = _ticket_ok(db, schedule)
    if not ok:
        audit.log(db, actor="system", role="controller", action="schedule_skipped",
                  detail=f"{schedule.name} — {reason}", tone="warning")
        logger.warning("schedule_skipped name=%s reason=%s", schedule.name, reason)
        schedule.last_fired_at = datetime.utcnow()  # still counts as "handled this slot" -- don't retry every tick for the rest of the hour
        db.commit()
        return

    spec = _run_spec(db, schedule)
    # By name, so a staged rollout goes through the fleet in an order
    # someone can predict and read back from the batch page.
    hosts = sorted(_hosts_in_scope(db, schedule), key=lambda h: h.hostname)

    if (schedule.rollout or models.BATCH_PARALLEL) == models.BATCH_ONE_AT_A_TIME and len(hosts) > 1:
        # One machine at a time, as a batch: the next starts only when the
        # one before it finished cleanly, and a failure pauses the rest
        # for someone to look at (app/batches.py) instead of repeating
        # itself on every machine in scope.
        batches.stop_superseded(db, schedule.id)
        batch = batches.start(
            db, SimpleNamespace(username="system", role="admin"), [h.id for h in hosts],
            models.BATCH_ONE_AT_A_TIME,
            {"ticket_id": spec["ticket_id"], "scope": spec["scope"], "severity_filter": spec["severity_filter"],
             "scheduled": dict(spec, schedule_id=schedule.id)},
        )
        schedule.last_fired_at = datetime.utcnow()
        db.commit()
        audit.log(db, actor="system", role="controller", action="schedule_fired",
                  detail=f"{schedule.name} — batch {batch.id}: {len(hosts)} machines, one at a time", tone="success")
        logger.info("schedule_fired name=%s batch=%d hosts=%d", schedule.name, batch.id, len(hosts))
        return

    fired_for = []
    for host in hosts:
        why = start_host_run(db, host, spec)
        if why == NO_CONTAINERS:
            # Say so: a silently absent run is indistinguishable from a
            # broken schedule.
            audit.log(db, actor="system", role="controller", action="schedule_skipped",
                      detail=f"{schedule.name} — {host.hostname} has no compose-managed containers",
                      tone="warning")
        if not why:
            fired_for.append(host.hostname)

    schedule.last_fired_at = datetime.utcnow()
    db.commit()
    if fired_for:
        audit.log(db, actor="system", role="controller", action="schedule_fired",
                  detail=f"{schedule.name} — started {len(fired_for)} run(s): {audit.names(fired_for)}", tone="success")
        logger.info("schedule_fired name=%s runs=%d hosts=%s", schedule.name, len(fired_for), audit.names(fired_for))


def run_scheduler_pass(db):
    now = datetime.utcnow()
    start_of_hour = now.replace(minute=0, second=0, microsecond=0)
    for schedule in db.query(models.Schedule).filter(models.Schedule.enabled == True).all():  # noqa: E712 -- SQLAlchemy filter, not a real Python bool comparison
        if schedule.day_of_week != now.weekday() or schedule.hour != now.hour:
            continue
        if schedule.last_fired_at and schedule.last_fired_at >= start_of_hour:
            continue  # already handled this hour's slot
        _fire_schedule(db, schedule)


async def scheduler_loop():
    from .db import SessionLocal

    def one_pass():
        db = SessionLocal()
        try:
            run_scheduler_pass(db)
        finally:
            db.close()

    while True:
        try:
            # In a thread: starting runs can ask Proxmox for snapshots and
            # send notifications, and the server must keep answering meanwhile.
            await asyncio.to_thread(one_pass)
        except Exception:  # noqa: BLE001 — one bad pass must never kill the loop
            logger.exception("scheduler pass failed")
        await asyncio.sleep(settings.scheduler_interval_seconds)
