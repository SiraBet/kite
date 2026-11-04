"""
The home dashboard's data, as one aggregated response.

Deliberately a single endpoint rather than the frontend fanning out to
/hosts + /runs + /audit + /schedules and stitching the result together
client-side. Three reasons, in order of how much they matter:

  1. The landing page is the most-loaded view in the app — it's what
     every login lands on. Four round trips on every visit, each with
     its own latency and its own failure mode, is the wrong shape for
     that.
  2. Several of these numbers need the whole table to compute but only
     yield a count (jobs by status, activity in the last 24h). Sending
     every job and every audit row to the browser so it can reduce them
     to integers wastes the transfer and puts the aggregation somewhere
     it can't be tested.
  3. Connectivity tiering already exists twice — app/monitoring.py's
     connectivity_tier() and the frontend's own copy — and the comment
     in monitoring.py notes they're kept in sync by hand. This reuses
     the Python one rather than adding a third caller of the JS one.

Read-only, and visible to any authenticated user. Nothing here is
role-gated because nothing here is more sensitive than the /hosts and
/runs listings every role can already read; the actions a dashboard card
links to stay gated at their own endpoints.
"""
from collections import Counter
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session, selectinload

from .. import models, monitoring
from ..auth import get_current_user
from ..db import get_db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# How far back "recent activity" and the 24h counters look.
ACTIVITY_WINDOW_HOURS = 24
# A host not patched in this long is called out. Matches the 30-day
# threshold the Overview page has always used for "overdue".
STALE_PATCH_DAYS = 30

RECENT_ACTIVITY_LIMIT = 12
ATTENTION_LIMIT = 8


class FleetSummary(BaseModel):
    total: int
    healthy: int
    stale: int
    offline: int
    # Percentage of hosts currently reachable — the headline number.
    # 100 when there are no hosts at all, rather than 0: an empty fleet
    # has nothing wrong with it, and showing a red 0% on a fresh install
    # would be alarming for no reason.
    compliance_pct: int
    never_patched: int
    overdue: int  # patched, but longer ago than STALE_PATCH_DAYS
    avg_days_since_patched: Optional[int]
    by_platform: dict
    by_team: dict


class RunsSummary(BaseModel):
    active: int          # queued or running right now
    completed_24h: int
    failed_24h: int
    stuck: int           # active, on an agent stage past its threshold


class AttentionItem(BaseModel):
    """One host that a human should probably look at, and why."""
    host_id: int
    hostname: str
    reason: str
    tone: str  # danger | warning — matches the frontend's badge classes


class ActivityItem(BaseModel):
    ts: datetime
    actor: str
    action: str
    detail: str
    tone: str

    model_config = ConfigDict(from_attributes=True)


class ActiveRun(BaseModel):
    job_id: int
    hostname: str
    stage: str
    stage_index: int
    total_stages: int
    started_at: Optional[datetime]


class RecentRun(BaseModel):
    """One recently-touched job, for the Overview's Recent runs list.
    Ordered by id, so the newest runs show regardless of status — the
    Overview wants "what ran lately", including the ones that failed."""
    job_id: int
    hostname: str
    status: str          # queued / running / done / failed / cancelled
    scope: str           # os | containers | both
    severity_filter: str
    operator: str        # empty means it was started by a schedule, not a person
    stage_index: int
    total_stages: int
    updated_at: Optional[datetime]


class UpcomingSchedule(BaseModel):
    id: int
    name: str
    team: str
    day_name: str
    hour: int
    next_fire: datetime
    host_count: int


class ContainerSummary(BaseModel):
    """
    Fleet-wide container position. `outdated` counts only containers
    whose tag has demonstrably moved upstream; `unknown` is counted
    separately rather than folded in, because "we could not reach the
    registry" is not the same claim as "this is current".
    """
    total: int
    hosts_with_containers: int
    outdated: int
    unknown: int
    pinned: int
    by_management: dict
    # Hosts carrying at least one outdated container, worst first.
    worst_hosts: List[dict]


class RiskSummary(BaseModel):
    """
    Outstanding patch risk across the fleet.

    `unassessed` is reported separately and never folded into the
    counts: a host whose package manager could not be queried has an
    unknown number of pending updates, not zero, and a dashboard that
    quietly treats the two the same is worse than one that says nothing.
    """
    total: int
    security: int
    by_severity: dict
    hosts_with_critical: int
    hosts_with_important: int
    unassessed: int
    # Hosts we actually confirmed are up to date: assessed AND nothing
    # pending. Never inferred from "no pending rows" alone — a host whose
    # assessment failed is unassessed, not current. Defaulted so an older
    # payload without it doesn't break the console.
    verified_current: int = 0
    worst_hosts: List[dict]


class DashboardOut(BaseModel):
    generated_at: datetime
    fleet: FleetSummary
    runs: RunsSummary
    attention: List[AttentionItem]
    activity: List[ActivityItem]
    active_runs: List[ActiveRun]
    recent_runs: List[RecentRun]
    upcoming: List[UpcomingSchedule]
    agent_versions: dict
    containers: ContainerSummary
    risk: RiskSummary


def _days_since(value: Optional[datetime], now: datetime) -> Optional[int]:
    if not value:
        return None
    return (now - value).days


def _platform(os_family: str) -> str:
    """
    Mirrors osPlatform() in frontend/kite.html. Kept coarse on
    purpose — the dashboard wants "Linux vs Windows vs not yet
    reported", not a distro breakdown.
    """
    family = (os_family or "").lower()
    if not family:
        return "unknown"
    if family.startswith("win"):
        return "windows"
    return "linux"


def _fleet_summary(hosts, now: datetime) -> FleetSummary:
    tiers = Counter(monitoring.connectivity_tier(h) for h in hosts)
    total = len(hosts)

    ages = [_days_since(h.last_patched, now) for h in hosts]
    patched_ages = [a for a in ages if a is not None]

    return FleetSummary(
        total=total,
        healthy=tiers["healthy"],
        stale=tiers["stale"],
        offline=tiers["offline"],
        compliance_pct=round(tiers["healthy"] / total * 100) if total else 100,
        never_patched=sum(1 for a in ages if a is None),
        overdue=sum(1 for a in patched_ages if a > STALE_PATCH_DAYS),
        avg_days_since_patched=round(sum(patched_ages) / len(patched_ages)) if patched_ages else None,
        by_platform=dict(Counter(_platform(h.os_family) for h in hosts)),
        by_team=dict(Counter(h.team or "Unassigned" for h in hosts)),
    )


def _attention(hosts, now: datetime) -> List[AttentionItem]:
    """
    Offline hosts first, then stale, then long-unpatched — the order a
    person would actually work the list in. Capped, because a dashboard
    that lists 400 problems is a dashboard nobody reads; the Fleet page
    is where the full list lives.
    """
    items = []
    for host in hosts:
        tier = monitoring.connectivity_tier(host)
        age = _days_since(host.last_patched, now)
        if tier == "offline":
            items.append((0, AttentionItem(host_id=host.id, hostname=host.hostname,
                                           reason="offline", tone="danger")))
        elif tier == "stale":
            items.append((1, AttentionItem(host_id=host.id, hostname=host.hostname,
                                           reason="not confirmed recently", tone="warning")))
        elif age is None:
            items.append((2, AttentionItem(host_id=host.id, hostname=host.hostname,
                                           reason="never patched", tone="warning")))
        elif age > STALE_PATCH_DAYS:
            items.append((3, AttentionItem(host_id=host.id, hostname=host.hostname,
                                           reason=f"{age}d since patched", tone="warning")))
    items.sort(key=lambda pair: (pair[0], pair[1].hostname))
    return [item for _, item in items[:ATTENTION_LIMIT]]


def _active_runs(db: Session, jobs) -> List[ActiveRun]:
    out = []
    for job in jobs:
        stages = sorted(job.stages, key=lambda s: s.stage_index)
        # This job's own stages, not the template's: a run's pipeline
        # depends on its scope (see models.stages_for), so a
        # containers-only run legitimately has fewer.
        total_stages = len(stages)
        current = stages[job.current_stage_index] if job.current_stage_index < len(stages) else None
        out.append(ActiveRun(
            job_id=job.id,
            # Falls back to the live host row for jobs created before
            # Job.hostname was denormalized -- see models.py.
            hostname=job.hostname or (job.host.hostname if job.host else "(host removed)"),
            stage=current.name if current else "finishing",
            stage_index=job.current_stage_index,
            total_stages=total_stages,
            started_at=job.created_at,
        ))
    return out


RECENT_RUNS_LIMIT = 6
# How many rows the Overview's worst-off table shows.
WORST_HOSTS_LIMIT = 6


def _recent_runs(db: Session) -> List[RecentRun]:
    jobs = db.query(models.Job).order_by(models.Job.id.desc()).limit(RECENT_RUNS_LIMIT).all()
    out = []
    for job in jobs:
        total_stages = len(job.stages)
        out.append(RecentRun(
            job_id=job.id,
            hostname=job.hostname or (job.host.hostname if job.host else "(host removed)"),
            status=job.status,
            scope=job.scope or "os",
            severity_filter=job.severity_filter or "",
            operator=job.operator or "",
            stage_index=job.current_stage_index,
            total_stages=total_stages,
            updated_at=job.updated_at,
        ))
    return out


def _next_fire(schedule: models.Schedule, now: datetime) -> datetime:
    """
    Next UTC datetime this weekly schedule fires. Mirrors the matching
    rule in app/scheduler.py: same weekday, same hour, and a slot is
    considered handled once last_fired_at lands inside it.
    """
    days_ahead = (schedule.day_of_week - now.weekday()) % 7
    candidate = (now + timedelta(days=days_ahead)).replace(
        hour=schedule.hour, minute=0, second=0, microsecond=0)
    start_of_slot = candidate
    already_fired = schedule.last_fired_at is not None and schedule.last_fired_at >= start_of_slot
    if candidate < now or already_fired:
        candidate += timedelta(days=7)
    return candidate


def _container_summary(db: Session) -> ContainerSummary:
    rows = db.query(models.Container).all()
    outdated_by_host = Counter()
    host_names = {h.id: h.hostname for h in db.query(models.Host).all()}

    outdated = unknown = pinned = 0
    for row in rows:
        if row.pinned:
            pinned += 1
        if row.update_available is True:
            outdated += 1
            outdated_by_host[row.host_id] += 1
        elif row.update_available is None and not row.pinned:
            unknown += 1

    worst = [
        {"host_id": host_id, "hostname": host_names.get(host_id, "(removed)"), "outdated": count}
        for host_id, count in outdated_by_host.most_common(5)
    ]
    return ContainerSummary(
        total=len(rows),
        hosts_with_containers=len({r.host_id for r in rows}),
        outdated=outdated,
        unknown=unknown,
        pinned=pinned,
        by_management=dict(Counter(r.managed_by or "standalone" for r in rows)),
        worst_hosts=worst,
    )


def _risk_summary(db: Session, hosts) -> RiskSummary:
    rows = db.query(models.PendingUpdate).all()
    host_by_id = {h.id: h for h in hosts}

    by_severity = Counter(r.severity or "none" for r in rows)
    per_host = {}
    for row in rows:
        entry = per_host.setdefault(row.host_id, Counter())
        entry[row.severity or "none"] += 1

    def weight(counts):
        # Rank by what is most severe first, then volume — a host with one
        # critical outranks a host with forty moderates.
        return tuple(counts.get(level, 0) for level in models.SEVERITY_RANK)

    def host_fields(host):
        # The columns the Overview's worst-off table needs beyond the
        # counts: who owns it and what it runs. Kept here so the row is
        # self-contained and the frontend does no second lookup.
        return {
            "os": (host.os_version or host.os_family or "") if host else "",
            "team": (host.team or "") if host else "",
        }

    # Pending-bearing hosts, worst severity first — these become the
    # "Urgent"/"Due" rows.
    worst_rows = []
    for host_id, counts in sorted(per_host.items(), key=lambda kv: weight(kv[1]), reverse=True):
        host = host_by_id.get(host_id)
        tier = monitoring.connectivity_tier(host) if host else "offline"
        # An unreachable host's pending list is a stale snapshot — its
        # real status is "no answer", not a severity we can stand behind.
        status = "no_answer" if tier in ("offline", "stale") else (
            "urgent" if (counts.get("critical") or counts.get("important")) else "due")
        worst_rows.append({
            "host_id": host_id,
            "hostname": host.hostname if host else "(removed)",
            "critical": counts.get("critical", 0),
            "important": counts.get("important", 0),
            "total": sum(counts.values()),
            "status": status,
            **host_fields(host),
        })

    # Unreachable hosts with nothing pending on record still belong in the
    # worst-off list — "we can't see them" is itself a worst-off state, and
    # the mockup's table mixes them in rather than hiding them on another card.
    seen = set(per_host)
    for host in hosts:
        if host.id in seen:
            continue
        if monitoring.connectivity_tier(host) in ("offline", "stale"):
            worst_rows.append({
                "host_id": host.id, "hostname": host.hostname,
                "critical": 0, "important": 0, "total": None,
                "status": "no_answer", **host_fields(host),
            })

    # Pick WHICH rows survive before deciding what order to show them in.
    # Sorting unreachable-first and then truncating meant a fleet with six or
    # more silent hosts pushed every Critical host off the Overview's only
    # risk table — under a heading that says "ranked by severity". Reserve a
    # small quota for unreachable hosts so they can report themselves without
    # crowding out the ones carrying actual advisories.
    unreachable = [r for r in worst_rows if r["status"] == "no_answer"]
    by_severity_rank = [r for r in worst_rows if r["status"] != "no_answer"]
    quota = max(1, WORST_HOSTS_LIMIT // 3)
    selected = unreachable[:quota]
    selected += by_severity_rank[:WORST_HOSTS_LIMIT - len(selected)]
    if len(selected) < WORST_HOSTS_LIMIT:
        # Few or no advisory-bearing hosts — give the rest of the table back
        # to the unreachable ones rather than showing a short list.
        chosen = {r["host_id"] for r in selected}
        selected += [r for r in unreachable if r["host_id"] not in chosen][
            :WORST_HOSTS_LIMIT - len(selected)]

    # No-answer first, then urgent, then due — the order a person works
    # the list. Within a tier the pending-severity sort above is preserved.
    tier_rank = {"no_answer": 0, "urgent": 1, "due": 2}
    selected.sort(key=lambda r: tier_rank.get(r["status"], 3))

    return RiskSummary(
        total=len(rows),
        security=sum(1 for r in rows if r.is_security),
        by_severity=dict(by_severity),
        hosts_with_critical=sum(1 for c in per_host.values() if c.get("critical")),
        hosts_with_important=sum(1 for c in per_host.values() if c.get("important")),
        # False and None both mean "we don't know what's pending here".
        unassessed=sum(1 for h in hosts if not h.updates_assessed_ok),
        # Assessed, nothing pending, AND still answering. Dropping the
        # connectivity test counted a host that went silent a week ago with a
        # clean last assessment as "Verified current" while the table right
        # below it listed the same host as "No answer" — and the fleet view
        # calls it unreachable, not current. A stale clean scan is not
        # evidence the host is current now.
        verified_current=sum(
            1 for h in hosts
            if h.updates_assessed_ok
            and h.id not in per_host
            and monitoring.connectivity_tier(h) == "healthy"
        ),
        worst_hosts=selected,
    )


@router.get("", response_model=DashboardOut)
def get_dashboard(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    now = datetime.utcnow()
    since = now - timedelta(hours=ACTIVITY_WINDOW_HOURS)

    hosts = db.query(models.Host).all()
    active_jobs = (
        db.query(models.Job)
        .options(selectinload(models.Job.stages))   # one query for every run's stages, not one per run
        .filter(models.Job.status.in_(["queued", "running"]))
        .order_by(models.Job.id.desc())
        .all()
    )
    recent_jobs = db.query(models.Job).filter(models.Job.updated_at >= since).all()

    stuck = 0
    for job in active_jobs:
        stages = sorted(job.stages, key=lambda s: s.stage_index)
        if job.current_stage_index < len(stages) and monitoring.is_stage_stuck(stages[job.current_stage_index]):
            stuck += 1

    schedules = db.query(models.Schedule).filter(models.Schedule.enabled == True).all()  # noqa: E712 — SQLAlchemy filter
    team_sizes = Counter(h.team or "" for h in hosts)
    upcoming = sorted(
        (
            UpcomingSchedule(
                id=s.id, name=s.name, team=s.team or "",
                day_name=models.DAY_NAMES[s.day_of_week], hour=s.hour,
                next_fire=_next_fire(s, now),
                host_count=team_sizes[s.team] if s.team else len(hosts),
            )
            for s in schedules
        ),
        key=lambda s: s.next_fire,
    )[:5]

    return DashboardOut(
        generated_at=now,
        fleet=_fleet_summary(hosts, now),
        runs=RunsSummary(
            active=len(active_jobs),
            completed_24h=sum(1 for j in recent_jobs if j.status == "done"),
            failed_24h=sum(1 for j in recent_jobs if j.status == "failed"),
            stuck=stuck,
        ),
        attention=_attention(hosts, now),
        activity=(
            db.query(models.AuditLog)
            # By timestamp, not by id like /audit does. They agree for
            # rows the app writes (ts defaults to insert time), but
            # "recent activity" means recent in time, and a row with an
            # explicitly-set ts — a backfill, a seeded dev fleet —
            # should sort by when it happened, not when it was written.
            # id breaks ties, since ts has no uniqueness guarantee.
            .order_by(models.AuditLog.ts.desc(), models.AuditLog.id.desc())
            .limit(RECENT_ACTIVITY_LIMIT)
            .all()
        ),
        active_runs=_active_runs(db, active_jobs),
        recent_runs=_recent_runs(db),
        upcoming=upcoming,
        agent_versions=dict(Counter(h.agent_version or "unreported" for h in hosts)),
        containers=_container_summary(db),
        risk=_risk_summary(db, hosts),
    )
