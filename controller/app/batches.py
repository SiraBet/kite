"""
Several machines patched together (models.Batch), one at a time or in
parallel. Each machine gets an ordinary run (routers/runs.py start_job);
this decides when each one starts:

  parallel       every run starts at once; the batch is done when the
                 last one ends, whatever its result.
  one at a time  the next run starts when the previous one finishes
                 cleanly. A failed or force-stopped run pauses the batch:
                 someone continues with the next machine or stops the rest.

A machine that can't start when its turn comes (it has another run going,
or no containers to update) is skipped and noted, and the batch moves on.
"""
import json
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from . import audit, models

_ENDED = ("done", "failed", "cancelled")


def _json(text, default):
    try:
        return json.loads(text or "")
    except ValueError:
        return default


def host_ids(b: models.Batch) -> list:
    return [int(h) for h in _json(b.host_ids, [])]


def _settings(b: models.Batch) -> dict:
    s = _json(b.settings, {})
    s["checklist"] = [tuple(i) for i in s.get("checklist", [])]
    return s


def _skip(db: Session, b: models.Batch, host_id: int, why: str):
    skipped = _json(b.skipped, {})
    skipped[str(host_id)] = why
    b.skipped = json.dumps(skipped)
    db.commit()
    audit.log(db, actor="system", role="controller", action="batch_host_skipped",
              detail=f"batch {b.id} — host {host_id}: {why}", tone="warning")


def _start_host(db: Session, b: models.Batch, host_id: int) -> bool:
    from .routers.runs import start_job   # local: routers.runs -> jobs_engine -> this module
    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host:
        _skip(db, b, host_id, "no longer in the fleet")
        return False
    try:
        start_job(db, b.operator, b.operator_role, host, _settings(b), (), batch_id=b.id)
        return True
    except HTTPException as e:
        _skip(db, b, host_id, str(e.detail))
        return False


def _start_next(db: Session, b: models.Batch) -> bool:
    """One at a time: start the next machine that can start. False when none are left."""
    ids = host_ids(b)
    while b.next_index < len(ids):
        host_id = ids[b.next_index]
        b.next_index += 1
        db.commit()
        if _start_host(db, b, host_id):
            return True
    return False


def _finish(db: Session, b: models.Batch, status: str = "done"):
    b.status, b.finished_at = status, datetime.utcnow()
    db.commit()
    jobs = db.query(models.Job).filter(models.Job.batch_id == b.id).all()
    ok = sum(1 for j in jobs if j.status == "done")
    audit.log(db, actor="system", role="controller", action="batch_finished",
              detail=f"batch {b.id} — {ok} of {len(host_ids(b))} machines patched",
              tone="success" if ok == len(host_ids(b)) else "warning")


def start(db: Session, user: models.User, ids: list, rollout: str, settings: dict) -> models.Batch:
    b = models.Batch(rollout=rollout, status="running", host_ids=json.dumps(ids),
                     settings=json.dumps(settings), operator=user.username, operator_role=user.role)
    db.add(b)
    db.commit()
    db.refresh(b)
    audit.log(db, actor=user.username, role=user.role, action="batch_started",
              detail=f"batch {b.id} — {len(ids)} machines, "
                     f"{'one at a time' if rollout == models.BATCH_ONE_AT_A_TIME else 'in parallel'}")
    if rollout == models.BATCH_PARALLEL:
        for host_id in ids:
            _start_host(db, b, host_id)
        b.next_index = len(ids)
        db.commit()
        _maybe_done_parallel(db, b)
    elif not _start_next(db, b):
        _finish(db, b)
    return b


def _maybe_done_parallel(db: Session, b: models.Batch):
    jobs = db.query(models.Job).filter(models.Job.batch_id == b.id).all()
    if b.status in ("running", "stopped") and b.finished_at is None and all(j.status in _ENDED for j in jobs):
        _finish(db, b, "done" if b.status == "running" else "stopped")


def on_job_finished(db: Session, job: models.Job):
    b = db.query(models.Batch).filter(models.Batch.id == job.batch_id).first()
    if not b:
        return
    if b.rollout == models.BATCH_PARALLEL:
        _maybe_done_parallel(db, b)
        return
    if b.status != "running":
        return
    if job.status == "done":
        if not _start_next(db, b):
            _finish(db, b)
        return
    what = "failed" if job.status == "failed" else "was stopped"
    b.status = "paused"
    b.paused_reason = f"{job.hostname}'s run {what}"
    db.commit()
    audit.log(db, actor="system", role="controller", action="batch_paused",
              detail=f"batch {b.id} — {b.paused_reason}; waiting for someone to continue or stop", tone="warning")


def resume(db: Session, b: models.Batch, user: models.User):
    b.status, b.paused_reason = "running", ""
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="batch_continued", detail=f"batch {b.id}")
    if not _start_next(db, b):
        _finish(db, b)


def stop(db: Session, b: models.Batch, user: models.User):
    """Nothing more starts. Runs already going carry on -- force-stop those individually."""
    audit.log(db, actor=user.username, role=user.role, action="batch_stopped", detail=f"batch {b.id}",
              tone="warning")
    b.status = "stopped"
    db.commit()
    jobs = db.query(models.Job).filter(models.Job.batch_id == b.id).all()
    if all(j.status in _ENDED for j in jobs):
        b.finished_at = datetime.utcnow()
        db.commit()


def view(db: Session, b: models.Batch) -> dict:
    """The batch page: every machine in rollout order with where it's at."""
    jobs = {j.host_id: j for j in db.query(models.Job).filter(models.Job.batch_id == b.id).all()}
    skipped = _json(b.skipped, {})
    hosts = {h.id: h for h in db.query(models.Host).filter(models.Host.id.in_(host_ids(b))).all()}
    rows = []
    for i, host_id in enumerate(host_ids(b)):
        job, host = jobs.get(host_id), hosts.get(host_id)
        if job:
            stages = sorted(job.stages, key=lambda s: s.stage_index)
            current = stages[job.current_stage_index] if job.current_stage_index < len(stages) else None
            state = job.status
        else:
            current, stages = None, []
            state = "skipped" if str(host_id) in skipped else ("not started" if b.status in ("stopped", "done") else "waiting")
        rows.append({
            "host_id": host_id, "hostname": job.hostname if job else (host.hostname if host else f"host {host_id}"),
            "state": state, "job_id": job.id if job else None,
            "stage": current.name if current and job.status in ("queued", "running") else "",
            "stage_index": job.current_stage_index if job else 0, "stage_count": len(stages),
            "skipped": skipped.get(str(host_id), ""), "order": i + 1,
        })
    counts = {k: sum(1 for r in rows if r["state"] == k) for k in ("done", "failed", "cancelled", "running", "queued", "waiting", "skipped", "not started")}
    return {"id": b.id, "rollout": b.rollout, "status": b.status, "paused_reason": b.paused_reason or "",
            "operator": b.operator, "created_at": b.created_at, "finished_at": b.finished_at,
            "settings": {k: v for k, v in _json(b.settings, {}).items() if k != "checklist"},
            "hosts": rows, "counts": counts}
