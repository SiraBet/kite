"""
Reliability and observability.

Two things live here:

1. Stuck-stage detection — nothing about advance_job()/report_agent_stage()
   ever times out on its own (see jobs_engine.py): an agent stage sits at
   'running' until the agent reports back, however long that takes. If an
   agent dies, a host never comes back from reboot, or a custom OS script
   hangs, the job just sits there silently forever. This module doesn't
   change that behavior (no auto-failing a stage — a human should decide
   that, the controller can't tell "legitimately slow" from "actually
   dead"); it detects and surfaces it: an audit-log entry, an operational
   log line, and a Prometheus gauge/counter so external tooling can alert
   on it.

2. A Prometheus /metrics endpoint (see main.py) exposing fleet
   connectivity, host/job status counts, and stuck-stage/offline-host
   counters. Outbound alerting on top of these signals lives in
   app/notifications.py; this module makes the state observable, it
   does not deliver anything.

Host connectivity tiering (connectivity_tier below) intentionally mirrors
connectivityTier() in frontend/kite.html (search that file for
"Three tiers rather than a binary online/offline") — same formula, same
reasoning, kept in sync by hand since the frontend has no import of this.
"""
import asyncio
from datetime import datetime

from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest
from sqlalchemy import func

from . import models, audit
from .config import settings
from .logging_config import logger

registry = CollectorRegistry()

hosts_connectivity = Gauge(
    "kite_hosts_connectivity", "Current host count by connectivity tier",
    ["tier"], registry=registry,
)
hosts_status = Gauge(
    "kite_hosts_status", "Current host count by patch/lock status",
    ["status"], registry=registry,
)
jobs_by_status = Gauge(
    "kite_jobs_status", "Current job count by status",
    ["status"], registry=registry,
)
jobs_stuck = Gauge(
    "kite_jobs_stuck", "Jobs currently stuck on an agent stage past its threshold",
    registry=registry,
)
stage_failures_total = Counter(
    "kite_stage_failures_total", "Cumulative stage failures since process start",
    ["stage"], registry=registry,
)
stage_stuck_total = Counter(
    "kite_stage_stuck_total", "Cumulative stages newly detected as stuck since process start",
    ["stage"], registry=registry,
)
pending_updates = Gauge(
    "kite_pending_updates", "Pending package updates across the fleet by severity",
    ["severity"], registry=registry,
)
hosts_unassessed = Gauge(
    "kite_hosts_unassessed",
    "Hosts whose package manager could not be queried — their pending count is unknown, not zero",
    registry=registry,
)
containers_total = Gauge(
    "kite_containers", "Containers reported across the fleet by management type",
    ["managed_by"], registry=registry,
)
containers_outdated = Gauge(
    "kite_containers_outdated",
    "Containers whose image tag has demonstrably moved upstream",
    registry=registry,
)
host_offline_total = Counter(
    "kite_host_offline_transitions_total", "Cumulative host healthy/stale -> offline transitions",
    registry=registry,
)

DEFAULT_POLL_INTERVAL_SECONDS = 900  # matches the frontend's fallback for hosts that haven't reported one yet

STUCK_THRESHOLD_MINUTES = {
    "reboot": settings.stuck_reboot_minutes,
    "__default__": settings.stuck_stage_minutes,
}

# In-memory only — resets on restart, which just means a stage or host
# already flagged before a restart may log once more after it. Kept out
# of the database deliberately: this is transient detection state, not
# fleet history, and re-notifying once after the rare restart costs less
# than carrying a table that has to be pruned.
_stuck_seen: set = set()
_last_tier: dict = {}


def connectivity_tier(host: models.Host) -> str:
    if not host.last_seen:
        return "offline"
    baseline = host.poll_interval_seconds or DEFAULT_POLL_INTERVAL_SECONDS
    age_sec = (datetime.utcnow() - host.last_seen).total_seconds()
    if age_sec > baseline * 4:
        return "offline"
    if age_sec > baseline * 2:
        return "stale"
    return "healthy"


def is_stage_stuck(stage: models.JobStage) -> bool:
    if stage.status != "running" or stage.executor != "agent" or not stage.started_at:
        return False
    threshold_min = STUCK_THRESHOLD_MINUTES.get(stage.name, STUCK_THRESHOLD_MINUTES["__default__"])
    age_min = (datetime.utcnow() - stage.started_at).total_seconds() / 60
    return age_min > threshold_min


def refresh_gauges(db):
    """
    Recomputed straight from the DB every call — used both by the
    background monitor pass and directly at /metrics scrape time, so a
    scrape is never more stale than the last DB write regardless of how
    long the monitor interval is set to.
    """
    hosts_connectivity.clear()
    hosts_status.clear()
    jobs_by_status.clear()

    tier_counts = {"healthy": 0, "stale": 0, "offline": 0}
    status_counts: dict = {}
    for host in db.query(models.Host).all():
        tier_counts[connectivity_tier(host)] += 1
        status_counts[host.status or "unknown"] = status_counts.get(host.status or "unknown", 0) + 1
    for tier, count in tier_counts.items():
        hosts_connectivity.labels(tier=tier).set(count)
    for status, count in status_counts.items():
        hosts_status.labels(status=status).set(count)

    job_status_counts: dict = {}
    stuck_count = 0
    for (status, count) in db.query(models.Job.status, func.count()).group_by(models.Job.status).all():
        job_status_counts[status] = count
    for status, count in job_status_counts.items():
        jobs_by_status.labels(status=status).set(count)

    for job in db.query(models.Job).filter(models.Job.status == "running").all():
        stages = sorted(job.stages, key=lambda s: s.stage_index)
        if job.current_stage_index < len(stages) and is_stage_stuck(stages[job.current_stage_index]):
            stuck_count += 1
    jobs_stuck.set(stuck_count)

    # Risk and container posture. `hosts_unassessed` is deliberately its
    # own series rather than being folded into a severity bucket: those
    # hosts have an unknown number pending, and an alert rule that treats
    # unknown as zero is the one that lets a fleet rot quietly.
    pending_updates.clear()
    severity_counts = dict(
        db.query(models.PendingUpdate.severity, func.count())
        .group_by(models.PendingUpdate.severity).all()
    )
    for level in models.SEVERITY_RANK:
        pending_updates.labels(severity=level).set(severity_counts.get(level, 0))
    hosts_unassessed.set(
        db.query(func.count()).select_from(models.Host)
        .filter(models.Host.updates_assessed_ok.is_(False)).scalar() or 0
    )

    containers_total.clear()
    for managed_by, count in (db.query(models.Container.managed_by, func.count())
                              .group_by(models.Container.managed_by).all()):
        containers_total.labels(managed_by=managed_by or "unknown").set(count)
    containers_outdated.set(
        db.query(func.count()).select_from(models.Container)
        .filter(models.Container.update_available.is_(True)).scalar() or 0
    )


def release_orphaned_locks(db) -> int:
    """
    A host is locked only while a run is in flight. One still locked with
    no queued or running job is left over from a path that never released
    it -- until this existed, any failed run -- and would show as
    "Patching" forever. Release it to "unknown" and say so. Returns how
    many were released.
    """
    active = {host_id for (host_id,) in
              db.query(models.Job.host_id).filter(models.Job.status.in_(["queued", "running"])).all()}
    released = 0
    for host in db.query(models.Host).filter(models.Host.status == "locked").all():
        if host.id in active:
            continue
        host.status = "unknown"
        released += 1
        audit.log(db, actor="system", role="controller", action="host_unlocked",
                  detail=f"{host.hostname} — was still marked as patching with no run in progress; released",
                  tone="warning")
        logger.warning("host_unlocked host=%s reason=no_active_run", host.hostname)
    return released


def detect_and_log_transitions(db):
    """
    Only called from the background monitor loop (not from /metrics) —
    this is the side-effecting half: audit-log entries, operational log
    lines, and counter increments, each exactly once per new detection
    via the in-memory dedupe sets above.
    """
    for job in db.query(models.Job).filter(models.Job.status == "running").all():
        stages = sorted(job.stages, key=lambda s: s.stage_index)
        if job.current_stage_index >= len(stages):
            continue
        stage = stages[job.current_stage_index]
        if not is_stage_stuck(stage):
            continue
        if stage.id in _stuck_seen:
            continue
        _stuck_seen.add(stage.id)
        threshold_min = STUCK_THRESHOLD_MINUTES.get(stage.name, STUCK_THRESHOLD_MINUTES["__default__"])
        host = job.host
        detail = (
            f"{host.hostname} — job {job.id}, stage '{stage.name}' still running after "
            f"{threshold_min}+ minutes"
        )
        audit.log(db, actor="system", role="controller", action="stage_stuck", detail=detail, tone="warning")
        logger.warning("stage_stuck job_id=%s host=%s stage=%s threshold_min=%s",
                        job.id, host.hostname, stage.name, threshold_min)
        stage_stuck_total.labels(stage=stage.name).inc()

    release_orphaned_locks(db)

    for host in db.query(models.Host).all():
        tier = connectivity_tier(host)
        previous = _last_tier.get(host.id)
        _last_tier[host.id] = tier
        if tier == "offline" and previous is not None and previous != "offline":
            audit.log(db, actor="system", role="controller", action="host_offline",
                      detail=f"{host.hostname} — no contact since {host.last_seen}", tone="warning")
            logger.warning("host_offline host=%s last_seen=%s", host.hostname, host.last_seen)
            host_offline_total.inc()


def render_metrics(db) -> bytes:
    refresh_gauges(db)
    return generate_latest(registry)


async def monitor_loop():
    """
    Started as a background asyncio task on app startup (see main.py),
    cancelled on shutdown. A bad pass must never kill the loop — a
    transient DB hiccup here shouldn't take stuck-stage/offline detection
    down until the next restart, so exceptions are logged and swallowed.

    Also where expired session rows get reaped — housekeeping that needs
    a periodic pass rather than a request, and this is the only one that
    runs on a human timescale.
    """
    from .auth import purge_expired_sessions
    from .db import SessionLocal

    def one_pass():
        from . import jobs_engine   # local: jobs_engine imports this module
        db = SessionLocal()
        try:
            detect_and_log_transitions(db)
            jobs_engine.expire_unstarted_runs(db)
            purged = purge_expired_sessions(db)
            if purged:
                logger.info("expired_sessions_purged count=%s", purged)
        finally:
            db.close()

    while True:
        try:
            # In a thread: a pass can send notifications (webhook, email),
            # and the server must keep answering while they're on the way.
            await asyncio.to_thread(one_pass)
        except Exception:  # noqa: BLE001 — one bad pass must never kill the loop
            logger.exception("monitor pass failed")
        await asyncio.sleep(settings.monitor_interval_seconds)
