from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from .. import agent_releases, audit, groups, models, schemas, jobs_engine, vulnerabilities
from ..db import get_db
from ..deps import get_current_agent_host
from ..settings_store import get_setting

router = APIRouter(prefix="/agent/{host_id}", tags=["agent"])

# Header the agent checks after every poll to learn it should self-update
# -- a header rather than a body field so it rides along
# without changing /jobs/next's existing JSON response shape (which is
# `Optional[AgentJobStageInstruction]`, i.e. sometimes just `null`, with
# no room to also carry a self-update signal in the body).
SELF_UPDATE_HEADER = "X-Kite-Self-Update"


@router.post("/heartbeat")
def heartbeat(host_id: int, payload: schemas.AgentHeartbeat,
              host: models.Host = Depends(get_current_agent_host), db: Session = Depends(get_db)):
    """
    Kept for backward compatibility / explicit pings, but the agent's main
    loop no longer calls this — /jobs/next updates last_seen on every
    request now (see below), so a separate heartbeat call is redundant
    for a long-polling agent.
    """
    host.last_seen = datetime.utcnow()
    db.commit()
    return {"ok": True}


def _selected_containers(db: Session, job: models.Job, host: models.Host):
    """
    Which containers this job may update.

    Filtered to compose-managed here rather than left to the agent:
    standalone containers cannot be recreated safely and orchestrated
    ones belong to their orchestrator, so they must never reach an agent
    as an instruction to act on. An empty selection on the job means
    "every updatable container", which is resolved now — at instruction
    time — against what the host currently reports.
    """
    rows = (
        db.query(models.Container)
        .filter(models.Container.host_id == host.id, models.Container.managed_by == "compose")
        .all()
    )
    chosen = {n.strip() for n in (job.container_selection or "").splitlines() if n.strip()}
    if chosen:
        rows = [c for c in rows if c.name in chosen]
    return rows


def _find_ready_instruction(db: Session, host: models.Host):
    """One lookup attempt — called repeatedly by the long-poll loop below."""
    job = (
        db.query(models.Job)
        .filter(models.Job.host_id == host.id, models.Job.status == "running")
        .order_by(models.Job.id.desc())
        .first()
    )
    if not job:
        return None

    stages = sorted(job.stages, key=lambda s: s.stage_index)
    if job.current_stage_index >= len(stages):
        return None
    stage = stages[job.current_stage_index]
    if stage.executor != "agent" or stage.status != "running":
        return None

    # every rule with no targets, and those whose OS families, groups or machines include this one
    defs = groups.rules_for(db, host)
    custom_script = None
    if stage.name in models.SCRIPTABLE_STAGES:
        os_script = groups.script_for(db, host, stage.name)
        if os_script:
            custom_script = os_script.content

    containers = []
    if stage.name == "containers":
        containers = [
            {
                "name": c.name,
                "image": c.image,
                "managed_by": c.managed_by,
                "compose_project": c.compose_project,
                "compose_service": c.compose_service,
                "compose_working_dir": c.compose_working_dir,
            }
            for c in _selected_containers(db, job, host)
        ]

    return schemas.AgentJobStageInstruction(
        job_id=job.id,
        stage_name=stage.name,
        excludes=[{"pkg_pattern": d.pkg_pattern, "mode": d.mode, "version": d.version} for d in defs],
        hostname=host.hostname,
        custom_script=custom_script,
        containers=containers,
        container_action=job.container_action or "update",
        severity_filter=job.severity_filter or "",
        skip_uninstallable=stage.name == "patch" and get_setting(db, "patch_skip_uninstallable") == "true",
    )


@router.get("/jobs/next", response_model=Optional[schemas.AgentJobStageInstruction])
def next_job_stage(host_id: int, response: Response, interval: Optional[int] = None,
                    agent_version: Optional[str] = None,
                    host: models.Host = Depends(get_current_agent_host), db: Session = Depends(get_db)):
    """
    Plain quick poll — checks once, returns immediately. No held-open
    connection (that was the long-poll design; dropped it — held-open
    HTTP is exactly the kind of thing corporate proxies/NAT/load
    balancers silently kill on real networks, which is a bad trade for
    what it bought). The agent now polls on a long, configurable
    interval as a baseline, and has a local trigger file for instant
    on-demand wake instead — see the agent's README.

    `interval` is the agent's own currently-configured poll_interval,
    sent on every call — the controller stores it so offline-detection
    thresholds (see the frontend) can be calibrated correctly per host,
    since this is configurable per-agent and can be changed after
    enrollment without the controller otherwise knowing.

    `agent_version` is likewise self-reported every call —
    shown on the Fleet page, and compared against Settings ->
    agent_target_version to decide whether to set SELF_UPDATE_HEADER on
    the response (see below). Older agent builds that don't send this
    param just never self-update and never show a version — no breakage,
    same as any other agent.conf field that predates a given release.

    last_seen is updated immediately on every call (success or empty) —
    this fold-in from the long-poll design was worth keeping regardless
    of the polling model, since it means the dashboard's "last seen"
    reflects actual live contact without a separate /heartbeat call.
    """
    host.last_seen = datetime.utcnow()
    if interval is not None and interval > 0:
        host.poll_interval_seconds = interval
    if agent_version:
        host.agent_version = agent_version
        # A per-host update is done once the agent reports that version (or newer).
        if host.agent_update_to and agent_releases.version_key(agent_version) >= agent_releases.version_key(host.agent_update_to):
            host.agent_update_to = None
    db.commit()

    instruction = _find_ready_instruction(db, host)

    # Self-update is only ever signaled on an otherwise-idle poll —
    # never alongside a real job-stage instruction, so it can't preempt
    # or race an in-flight patch run. The agent decides what to do with
    # it (currently: dnf-only, see agent-linux/agent.py).
    if instruction is None and agent_version:
        target = agent_releases.target_for(db, host)
        if target:
            response.headers[SELF_UPDATE_HEADER] = target

    return instruction


def _assessed_sources(payload):
    """
    Which update sources this report may replace, and their errors.

    Returns (ok_sources, source_errors): the set of source names whose
    query succeeded this round, and a name->error map for the ones that
    failed. Only ok sources get their rows replaced; a failed source
    keeps whatever was last stored for it.

    Two shapes are accepted, so a mixed fleet works during a rollout:

      - New agents send update_sources, a per-manager ok/error list.
      - Older agents send only updates_ok/updates_error, which is a single
        'os' source -- exactly what those agents assess. update_sources
        being empty is the tell, not updates_ok being None, so an agent
        that explicitly reports the OS source through the new field is not
        second-guessed.
    """
    if payload.update_sources:
        ok = {src.name for src in payload.update_sources if src.ok}
        errors = {src.name: src.error for src in payload.update_sources if not src.ok}
        return ok, errors
    if payload.updates_ok is None:
        return set(), {}
    if payload.updates_ok:
        return {"os"}, {}
    return set(), {"os": payload.updates_error}


# Linux's ephemeral port range starts here. Listeners above it are
# usually short-lived (a dev server, an RPC callback), so they're recorded
# but not announced -- announcing every one would bury the ones that matter.
ANNOUNCE_PORT_BELOW = 32768
ANNOUNCE_PORTS_SHOWN = 8


def _store_network(db: Session, host: models.Host, net: schemas.AgentNetwork, now: datetime):
    """
    Record what the agent saw on the network. Interfaces are replaced
    wholesale; listening ports are diffed so first_seen survives, which is
    what makes "a new port opened" detectable without anyone looking.

    A failed collection (ok=False) keeps the last good picture, the same
    as a failed update assessment: "could not tell" must not read as "no
    ports open". The first good report is the baseline and announces
    nothing -- every port on it is new to the controller, not to the host.
    """
    had_baseline = host.network_ok is True and host.network_reported_at is not None
    host.network_reported_at = now
    host.network_ok = net.ok
    host.network_error = "" if net.ok else net.error
    if not net.ok:
        return
    host.default_gateway = net.default_gateway

    db.query(models.HostInterface).filter(models.HostInterface.host_id == host.id).delete()
    for iface in net.interfaces:
        db.add(models.HostInterface(host_id=host.id, name=iface.name, mac=iface.mac, kind=iface.kind,
                                    is_up=iface.up, addresses="\n".join(iface.addresses), reported_at=now))

    existing = {(p.proto, p.address, p.port): p for p in
                db.query(models.HostListeningPort).filter(models.HostListeningPort.host_id == host.id).all()}
    opened = []
    for sock in {(s.proto, s.address, s.port): s for s in net.listening}.values():
        row = existing.pop((sock.proto, sock.address, sock.port), None)
        if row:
            row.last_seen, row.process, row.loopback = now, sock.process, sock.loopback
            continue
        db.add(models.HostListeningPort(host_id=host.id, proto=sock.proto, address=sock.address, port=sock.port,
                                        process=sock.process, loopback=sock.loopback, first_seen=now, last_seen=now))
        if had_baseline and not sock.loopback and sock.port < ANNOUNCE_PORT_BELOW:
            opened.append(sock)
    for gone in existing.values():
        db.delete(gone)

    if opened:
        opened.sort(key=lambda s: (s.port, s.proto))
        shown = ", ".join(f"{s.proto}/{s.port}" + (f" ({s.process})" if s.process else "")
                          for s in opened[:ANNOUNCE_PORTS_SHOWN])
        more = f" (+{len(opened) - ANNOUNCE_PORTS_SHOWN} more)" if len(opened) > ANNOUNCE_PORTS_SHOWN else ""
        audit.log(db, actor="system", role="controller", action="port_opened",
                  detail=f"{host.hostname} — newly listening on {shown}{more}", tone="warning")


@router.post("/inventory")
def report_inventory(host_id: int, payload: schemas.AgentInventory,
                     host: models.Host = Depends(get_current_agent_host), db: Session = Depends(get_db)):
    """
    Replace this host's container inventory with what the agent just
    observed.

    Replace rather than merge, deliberately: the agent reports its
    complete current set, so anything missing from it is genuinely gone
    and should stop being displayed. Merging would accumulate phantom
    containers that no longer exist on the host.

    Not audit-logged. Containers are created and destroyed constantly by
    normal operation, and a log of that would bury the change-control
    trail the audit log exists to provide.
    """
    host.container_runtime = payload.runtime
    previous_captures = {
        c.name: c.rollback_captured_at
        for c in db.query(models.Container).filter(models.Container.host_id == host.id).all()
    }
    db.query(models.Container).filter(models.Container.host_id == host.id).delete()
    now = datetime.utcnow()
    for item in payload.containers:
        db.add(models.Container(
            host_id=host.id, container_id=item.container_id, name=item.name,
            image=item.image, image_digest=item.image_digest, state=item.state,
            managed_by=item.managed_by, compose_project=item.compose_project,
            compose_service=item.compose_service, compose_working_dir=item.compose_working_dir,
            rollback_available=item.rollback_available,
            # Preserved across the replace: the agent reports whether a
            # capture exists, but not when it was taken -- that is the
            # controller's own record of the run that took it.
            rollback_captured_at=previous_captures.get(item.name) if item.rollback_available else None,
            pinned=item.pinned, update_available=item.update_available,
            reported_at=now,
        ))
    # Pending updates ride along on the same report, per source. A
    # source's list is only replaced when that source's query actually
    # succeeded: a failed query must leave that source's last known list
    # in place rather than blanking it, which would read as "nothing from
    # here is pending" when the truth is "we could not tell". One source
    # failing never touches another's rows.
    ok_sources, source_errors = _assessed_sources(payload)
    if ok_sources:
        # What was already known for the sources being refreshed, so only
        # genuinely new findings are announced. Without this every poll
        # would re-report the same advisories and the notification channel
        # would become noise nobody reads.
        known = {
            (u.package, u.severity)
            for u in db.query(models.PendingUpdate)
            .filter(models.PendingUpdate.host_id == host.id,
                    models.PendingUpdate.source.in_(ok_sources))
            .all()
        }
        db.query(models.PendingUpdate).filter(
            models.PendingUpdate.host_id == host.id,
            models.PendingUpdate.source.in_(ok_sources),
        ).delete(synchronize_session=False)
        for update in payload.updates:
            # A row is trusted only for a source that reported ok this
            # round; anything tagged for a failed source is dropped rather
            # than stored against an assessment we know we cannot trust.
            if (update.source or "os") not in ok_sources:
                continue
            db.add(models.PendingUpdate(
                host_id=host.id, package=update.package, new_version=update.new_version,
                advisory=update.advisory, severity=update.severity,
                is_security=update.is_security, source=update.source or "os",
                current_version=update.current_version, reported_at=now,
            ))
        newly_serious = sorted({
            u.package for u in payload.updates
            if (u.source or "os") in ok_sources
            and u.severity in ("critical", "important")
            and (u.package, u.severity) not in known
        })
        if newly_serious:
            shown = ", ".join(newly_serious[:8])
            more = f" (+{len(newly_serious) - 8} more)" if len(newly_serious) > 8 else ""
            audit.log(
                db, actor="system", role="controller", action="critical_update_found",
                detail=f"{host.hostname} — new high-severity updates available: {shown}{more}",
                tone="danger",
            )

    # The host-level assessment flags track the OS source specifically:
    # that is what the Fleet page's "updates" health has always meant, and
    # third-party sources are shown per-source in the host's pending list
    # rather than folded into one host-wide verdict.
    if payload.updates_ok is not None:
        host.updates_assessed_ok = payload.updates_ok
        host.updates_assessed_at = now
        host.updates_error = payload.updates_error if not payload.updates_ok else source_errors.get("os", "")

    if payload.network is not None:
        _store_network(db, host, payload.network, now)

    # Authenticated as this host by its own credential, so adopting the
    # hardware id it reports is as safe as at enrollment; never replaced.
    if payload.smbios_uuid and not host.smbios_uuid:
        host.smbios_uuid = payload.smbios_uuid.strip().lower()

    software_resend = False
    if payload.software is not None:
        software_resend = _store_software(db, host, payload.software, now)

    db.commit()
    # Matched only once the report is saved: a matching failure rolls its
    # own work back, and must not take the containers, updates, network
    # and software just reported with it.
    if payload.software is not None and payload.software.items is not None:
        vulnerabilities.match_host_safely(db, host)
    return {"ok": True, "stored": len(payload.containers), "updates": len(payload.updates),
            "software_resend": software_resend}


def _store_software(db: Session, host: models.Host, software: schemas.AgentSoftware, now: datetime) -> bool:
    """
    Replace the host's software list when the agent sent one. With only a
    hash, check it's the list we hold; if not (a restored database, a
    report that never landed), ask for the full list next time.
    """
    if software.items is None:
        return software.hash != host.software_hash
    db.query(models.HostSoftware).filter(models.HostSoftware.host_id == host.id).delete(synchronize_session=False)
    db.bulk_insert_mappings(models.HostSoftware, [
        dict(host_id=host.id, kind=i.kind, name=i.name, version=i.version, arch=i.arch,
             source_name=i.source_name, source_version=i.source_version, publisher=i.publisher)
        for i in software.items])
    host.software_hash = software.hash
    host.software_reported_at = now
    return False


@router.post("/jobs/{job_id}/stages/{stage_name}/report")
def report_stage(host_id: int, job_id: int, stage_name: str, payload: schemas.AgentStageReport,
                  host: models.Host = Depends(get_current_agent_host), db: Session = Depends(get_db)):
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.host_id == host.id).first()
    if not job:
        return {"ok": False, "error": "job not found for this host"}
    if job.status not in ("queued", "running"):
        # Job was force-stopped (or otherwise concluded) while the agent was
        # still working — this is a late report for something that no
        # longer matters to the controller. Acknowledge, don't error; the
        # agent has no way to know the job moved on without it.
        return {"ok": True, "note": f"job already {job.status}, report ignored"}
    try:
        jobs_engine.report_agent_stage(db, job, stage_name, payload.status, payload.output)
    except ValueError as e:
        # A report for a stage the run isn't on: stale, or from a confused
        # agent. Say so plainly rather than with a 500.
        raise HTTPException(409, str(e)) from None
    return {"ok": True}
