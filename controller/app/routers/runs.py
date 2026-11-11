from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas, audit, jobs_engine, rollback
from ..db import get_db
from ..maintenance_windows import within_window
from ..auth import get_current_user, ROLE_RANK
from ..settings_store import get_setting

router = APIRouter(prefix="/runs", tags=["runs"])


def _normalise_severity_filter(raw) -> str:
    """
    '' for everything, 'security' for advisories only, otherwise a
    lower-cased severity list.

    Validated against the vocabulary the package managers actually
    publish, so a typo ('hihg') is refused here rather than silently
    matching nothing and patching an empty set while reporting success.
    """
    value = (raw or "").strip().lower()
    if value in ("", models.SEVERITY_ALL):
        return ""
    if value == models.SEVERITY_SECURITY:
        return models.SEVERITY_SECURITY
    levels = [level.strip() for level in value.split(",") if level.strip()]
    unknown = [level for level in levels if level not in models.SEVERITY_RANK]
    if unknown:
        raise HTTPException(
            400,
            f"Unknown severity: {', '.join(sorted(unknown))}. "
            f"Use one of {', '.join(models.SEVERITY_RANK)}, or 'security' for all advisories.",
        )
    return ",".join(levels)


def _resolve_container_selection(db: Session, host: models.Host, scope: str, requested,
                                  action: str = "update") -> str:
    """
    Freeze which containers a run may update, as newline-separated names.

    Resolved at creation rather than at execution so the set cannot shift
    underneath a run: a container started after the operator confirmed
    the checklist should not be swept into it. An empty result for a
    scope that includes containers is refused outright — a run whose
    whole purpose is updating containers must not report success having
    updated nothing.
    """
    if scope == models.SCOPE_OS:
        return ""

    eligible = [c for c in db.query(models.Container).filter(models.Container.host_id == host.id).all()
                if c.updatable]
    if action == "rollback":
        # Only services that actually have a capture. Offering the rest
        # would produce a run that fails on the host for a reason the
        # controller already knew about.
        eligible = [c for c in eligible if c.rollback_available]
    by_name = {c.name: c for c in eligible}

    if requested:
        unknown = [n for n in requested if n not in by_name]
        if unknown and action == "rollback":
            raise HTTPException(
                400,
                f"No rollback capture on {host.hostname} for: {', '.join(sorted(unknown))}. "
                "A capture is taken by the update that would need undoing, so a service "
                "kite has never updated has nothing to restore.",
            )
        if unknown:
            raise HTTPException(
                400,
                f"Not updatable on {host.hostname}: {', '.join(sorted(unknown))}. "
                "Only compose-managed containers can be updated — a standalone container's "
                "creation flags aren't recorded anywhere, and an orchestrated one belongs to "
                "its orchestrator.",
            )
        chosen = list(requested)
    else:
        chosen = sorted(by_name)

    if not chosen and action == "rollback":
        raise HTTPException(
            409,
            f"{host.hostname} has no container rollback points. One is captured "
            "automatically by each container update, so there is nothing to roll back to yet.",
        )
    if not chosen:
        raise HTTPException(
            409,
            f"{host.hostname} has no compose-managed containers to update. "
            "Run with scope 'os' to patch the host itself.",
        )
    return "\n".join(chosen)


def check_run_request(db: Session, user: models.User, payload) -> dict:
    """
    The parts of starting a run that don't depend on the host: ticket and
    window, checklist, scope and severity. Shared by a single run and a
    batch (routers/batches.py). Returns the normalised settings.
    """
    require_ticket = get_setting(db, "require_ticket") == "true"
    if require_ticket:
        if not payload.ticket_id:
            raise HTTPException(400, "A ticket is required (see /settings to make it optional)")
        ticket = db.query(models.Ticket).filter(models.Ticket.ticket_id == payload.ticket_id).first()
        if not ticket:
            raise HTTPException(404, f"Ticket {payload.ticket_id} not found")
        if ticket.status != "Approved":
            raise HTTPException(409, f"Ticket {payload.ticket_id} is not Approved (status: {ticket.status})")

        if not within_window(ticket) and not payload.window_override_reason:
            raise HTTPException(
                409,
                f"Outside approved window ({ticket.window_start:02d}:00-{ticket.window_end:02d}:00). "
                "Provide window_override_reason to proceed (requires lead/admin role).",
            )
        if payload.window_override_reason and ROLE_RANK.get(user.role, -1) < ROLE_RANK["lead"]:
            raise HTTPException(403, "Overriding the maintenance window requires lead role or higher")

    if not payload.checklist and db.query(models.ChecklistItem).count():
        raise HTTPException(400, "At least one checklist item must be confirmed before a run can start")

    scope = payload.scope or models.SCOPE_OS
    if scope not in models.RUN_SCOPES:
        raise HTTPException(400, f"scope must be one of {models.RUN_SCOPES}")
    action = getattr(payload, "container_action", None) or "update"
    if action not in ("update", "rollback"):
        raise HTTPException(400, "container_action must be 'update' or 'rollback'")
    if action == "rollback" and scope != models.SCOPE_CONTAINERS:
        # Rolling images back while also patching the OS mixes an undo
        # with a change, in one run, under one audit entry. Keep them
        # separate so what happened stays legible.
        raise HTTPException(400, "A container rollback must run on its own (scope 'containers')")
    severity_filter = _normalise_severity_filter(payload.severity_filter)
    if scope == models.SCOPE_CONTAINERS and severity_filter:
        raise HTTPException(400, "severity_filter applies to OS packages; this run patches none")
    return {"ticket_id": payload.ticket_id or "", "window_override_reason": payload.window_override_reason,
            "scope": scope, "action": action, "severity_filter": severity_filter,
            "checklist": [(i.item_index, i.item_text) for i in payload.checklist]}


def check_host_ready(db: Session, host: models.Host, settings: dict, containers=()) -> str:
    """Per-host checks; returns the frozen container selection. Raises HTTPException when it can't run."""
    container_selection = _resolve_container_selection(db, host, settings["scope"], list(containers),
                                                       settings["action"])
    existing_running = (
        db.query(models.Job)
        .filter(models.Job.host_id == host.id, models.Job.status.in_(["queued", "running"]))
        .first()
    )
    if existing_running:
        raise HTTPException(409, f"{host.hostname} already has an active run (job {existing_running.id})")
    return container_selection


def start_job(db: Session, user_name: str, user_role: str, host: models.Host, settings: dict,
              containers=(), batch_id: int = None) -> models.Job:
    """Create, lock and start one host's run. Raises HTTPException when the host can't run now."""
    container_selection = check_host_ready(db, host, settings, containers)
    scope, action, severity_filter = settings["scope"], settings["action"], settings["severity_filter"]

    # Resolved once, here, and frozen on the job -- see models.py's
    # Job.rollback_backend for why this isn't re-resolved live later.
    backend_name = rollback.resolve_backend_name(db, host)

    job = models.Job(
        host_id=host.id, hostname=host.hostname, ticket_id=settings["ticket_id"], operator=user_name,
        operator_role=user_role, window_override_reason=settings["window_override_reason"],
        rollback_backend=backend_name, scope=scope, container_selection=container_selection,
        container_action=action, severity_filter=severity_filter, batch_id=batch_id,
    )
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        # Another request started one between check_host_ready and here.
        db.rollback()
        raise HTTPException(409, f"{host.hostname} already has an active run") from None
    db.refresh(job)

    for i, (name, executor) in enumerate(models.stages_for(scope)):
        if name == "snapshot":
            executor = rollback.stage_executor_for(backend_name)
        db.add(models.JobStage(job_id=job.id, stage_index=i, name=name, executor=executor))
    for item_index, item_text in settings["checklist"]:
        # confirmed_by is always the authenticated session's user - not client-supplied,
        # since only one person is actually the one clicking "Continue" on this checklist.
        db.add(models.ChecklistConfirmation(
            job_id=job.id, item_index=item_index,
            item_text=item_text, confirmed_by=user_name,
        ))
    db.commit()
    db.refresh(job)

    host.status = "locked"
    db.commit()

    ticket_id = settings["ticket_id"]
    ticket_desc = f"via {ticket_id}" if ticket_id else "no ticket (require_ticket disabled)"
    scope_desc = {
        models.SCOPE_OS: "OS packages",
        models.SCOPE_CONTAINERS: "container rollback" if action == "rollback" else "containers only",
        models.SCOPE_BOTH: "OS packages + containers",
    }[scope]
    if severity_filter:
        scope_desc += f" ({severity_filter} only)"
    batch_desc = f", batch {batch_id}" if batch_id else ""
    audit.log(db, actor=user_name, role=user_role, action="run_started",
              detail=f"{host.hostname} {ticket_desc}, scope: {scope_desc}, "
                     f"{len(settings['checklist'])} checklist items confirmed{batch_desc}")
    if settings["window_override_reason"]:
        audit.log(db, actor=user_name, role=user_role, action="window_override",
                  detail=f"{host.hostname} - {settings['window_override_reason']}", tone="warning")

    return jobs_engine.advance_job(db, job)


@router.post("", response_model=schemas.JobOut)
def create_run(payload: schemas.RunCreate, db: Session = Depends(get_db),
               user: models.User = Depends(get_current_user)):
    host = db.query(models.Host).filter(models.Host.id == payload.host_id).first()
    if not host:
        raise HTTPException(404, "Host not found")
    settings = check_run_request(db, user, payload)
    return start_job(db, user.username, user.role, host, settings, payload.containers)


@router.get("/{job_id}", response_model=schemas.JobOut)
def get_run(job_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    job = db.query(models.Job).filter(models.Job.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.get("", response_model=List[schemas.JobOut])
def list_runs(host_id: int = None, limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
              db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Newest first. Every run carries each stage's output, so the list is paged rather than whole."""
    q = db.query(models.Job)
    if host_id:
        q = q.filter(models.Job.host_id == host_id)
    return q.order_by(models.Job.id.desc()).offset(offset).limit(limit).all()


@router.post("/{job_id}/cancel", response_model=schemas.JobOut)
def cancel_run(job_id: int, db: Session = Depends(get_db),
               user: models.User = Depends(get_current_user)):
    """
    "Force stop" — but be precise about what this actually does. The
    controller has no channel to reach into a host and kill a command
    that's genuinely executing there. This only stops KITE from
    tracking/blocking on the job and frees the host up for a new run.
    If the agent is mid dnf-update when this is called, that process
    keeps running on the host regardless — this just stops waiting on it.

    Requires lead+ — same tier as overriding a maintenance window, since
    it's a similarly consequential override of the normal flow.
    """
    if ROLE_RANK.get(user.role, -1) < ROLE_RANK["lead"]:
        raise HTTPException(403, "Force-stopping a run requires lead role or higher")

    job = db.query(models.Job).filter(models.Job.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status not in ("queued", "running"):
        raise HTTPException(400, f"Job is already {job.status} — nothing to stop")

    stages = sorted(job.stages, key=lambda s: s.stage_index)
    if job.current_stage_index < len(stages):
        current = stages[job.current_stage_index]
        if current.status in ("pending", "running"):
            current.status = "failed"
            current.output = (current.output + " " if current.output else "") + \
                f"[cancelled by {user.username}] — kite stopped tracking this stage; " \
                "if a command was actually executing on the host it was NOT killed."

    job.status = "cancelled"
    host = job.host
    # Honest, not optimistic: we don't actually know what state the host is
    # in after a forced cancellation, so don't claim 'healthy'.
    host.status = "unknown"
    db.commit()

    audit.log(db, actor=user.username, role=user.role, action="run_cancelled",
              detail=f"{host.hostname} — job {job.id} force-stopped (tracking only, host process not killed)",
              tone="danger")
    jobs_engine.job_finished(db, job)
    db.refresh(job)
    return job
