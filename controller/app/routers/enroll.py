import hmac
from datetime import datetime, timedelta

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..db import get_db
from ..config import settings
from ..auth import require_role
from ..security import generate_enrollment_token, generate_secret, hash_secret
from ..rate_limit import limiter
from .. import proxmox, proxmox_connections

router = APIRouter(tags=["enrollment"])


def _try_auto_resolve_vmid(db: Session, host: models.Host):
    """
    Best-effort — never lets a Proxmox problem break enrollment. Only
    attempts this if we don't already have a vmid, we do have a UUID to
    look up, and Proxmox creds are actually configured (DB via Settings,
    or the legacy .env path — see rollback.resolve_proxmox_config).
    """
    if host.proxmox_vmid or not host.smbios_uuid:
        return
    try:
        # Every connection is searched: the VM may be on any cluster or
        # standalone host, and its vmid only means something on that one.
        conn, vmid, _ = proxmox_connections.find_vm_by_smbios(db, host.smbios_uuid)
        if vmid:
            host.proxmox_vmid, host.proxmox_connection_id = vmid, conn.id
            db.commit()
            audit.log(db, actor="system", role="controller", action="vmid_auto_resolved",
                      detail=f"{host.hostname} -> VM {vmid} on {conn.name} (matched by SMBIOS UUID)", tone="success")
    except (proxmox.ProxmoxError, requests.exceptions.RequestException):
        # Silent — this is a convenience, not a requirement; the admin can
        # set the VMID manually. requests.RequestException is caught
        # alongside ProxmoxError because proxmox.py only wraps HTTP-status
        # failures in ProxmoxError, not network-level ones (connect
        # timeout, DNS, refused). A configured-but-unreachable Proxmox
        # must never be able to break (nor 500) host enrollment.
        pass


def _enforce_host_identity(db: Session, host: models.Host, incoming_uuid: str, shared_secret: bool = False):
    """
    Trust-on-first-use hardware binding, so holding the bootstrap
    credential (a one-time token or the shared self-enroll secret) is not
    enough to seize an already-enrolled host's record.

    Re-enrollment re-issues that host's per-host secret and thereby
    redirects its job stream (custom root scripts included) to whoever
    just enrolled. Without a binding, anyone who can enroll at all could
    re-enroll under an existing hostname and hijack it or lock the real
    agent out. So once a host has recorded a SMBIOS UUID (its first
    enrollment), every later enrollment for that hostname must present the
    same one:

      - stored UUID set, incoming differs or is absent  -> refuse (409);
        moving a hostname to genuinely new hardware is an explicit admin
        action: remove the old host record first, then enroll.
      - stored UUID empty (legacy host, or hardware that reports none):
        with a one-time token -> allowed, since an admin issued it for
        this hostname; the incoming UUID (if any) is adopted below so the
        host becomes bound from now on. With the shared secret -> refused:
        that secret is in every install command, and would otherwise let
        anyone holding it take over any host with nothing to bind against
        (a host whose agent never reported one).
    """
    if shared_secret and not host.smbios_uuid:
        audit.log(db, actor="system", role="controller", action="enroll_identity_mismatch",
                  detail=f"{host.hostname} — re-enrollment with the shared secret refused: no hardware id "
                         f"on record to check it against", tone="danger")
        db.commit()
        raise HTTPException(
            409,
            "This hostname is already enrolled, and there's no hardware id on record to prove this is the "
            "same machine. Re-enroll it with a one-time token from the console (Fleet → Add machine).",
        )
    if host.smbios_uuid and host.smbios_uuid != incoming_uuid:
        audit.log(db, actor="system", role="controller", action="enroll_identity_mismatch",
                  detail=f"{host.hostname} — enrollment refused: SMBIOS UUID does not match the "
                         f"one recorded at first enrollment", tone="danger")
        db.commit()
        raise HTTPException(
            409,
            "This hostname is already enrolled to different hardware. To move it, an admin must "
            "remove the existing host record first.",
        )


def _next_host_id(db: Session) -> int:
    """
    One past every id a host has ever had. hosts.id isn't AUTOINCREMENT,
    so SQLite would hand a deleted top host's id to the next one; jobs keep
    the id of the host they ran on, so they're the record of ids used.
    """
    from sqlalchemy import func
    top = max(db.query(func.max(models.Host.id)).scalar() or 0,
              db.query(func.max(models.Job.host_id)).scalar() or 0)
    return top + 1


def _upsert_host(db: Session, hostname: str, team: str, role: str,
                  os_version: str, os_family: str, smbios_uuid: str,
                  poll_interval_seconds, proxmox_vmid, shared_secret: bool = False) -> tuple:
    """
    Shared by both enrollment paths (one-time token and shared-secret
    self-enroll): create the host if it's new, or re-issue a credential
    for an existing one if it's re-enrolling. Always returns a freshly
    generated per-host secret — this is the thing that replaces whatever
    bootstrap credential got you in the door, same as Wazuh's agent-auth
    handshake.

    `proxmox_vmid` is the VM id the enrolling agent claims as its own. It
    decides which VM the controller snapshots, prunes snapshots on and
    offers to restore for this host, so a wrong value points all of that
    at somebody else's machine. It is therefore only taken on trust from
    a one-time token, which an admin issued for this hostname, and only
    to fill in a link that isn't there yet: an existing link is never
    replaced from here (PATCH /hosts/{id} is how an admin moves one). The
    shared secret is in every install command, so a VM id sent with it is
    dropped; those hosts are linked by SMBIOS UUID or by an admin.
    """
    host = db.query(models.Host).filter(models.Host.hostname == hostname).first()
    secret = generate_secret()
    now = datetime.utcnow()
    claimed_vmid = proxmox_vmid
    if shared_secret:
        proxmox_vmid = None
    if host:
        _enforce_host_identity(db, host, smbios_uuid or "", shared_secret=shared_secret)
        host.agent_secret_hash = hash_secret(secret)
        host.os_version = os_version
        host.os_family = os_family or host.os_family
        host.smbios_uuid = smbios_uuid or host.smbios_uuid
        if poll_interval_seconds:
            host.poll_interval_seconds = poll_interval_seconds
        host.proxmox_vmid = host.proxmox_vmid or proxmox_vmid
        host.enrolled_at = now
        host.last_seen = now
        host.status = "healthy"
    else:
        host = models.Host(
            # Never a removed host's id: its run history (and anything else
            # still keyed by it) would read as this new machine's.
            id=_next_host_id(db),
            hostname=hostname, team=team, role=role,
            os_version=os_version, os_family=os_family or "",
            smbios_uuid=smbios_uuid or "",
            poll_interval_seconds=poll_interval_seconds or 900,
            proxmox_vmid=proxmox_vmid,
            agent_secret_hash=hash_secret(secret), enrolled_at=now,
            # Enrolling IS contact from the host — it just completed a
            # request. Leaving last_seen NULL until the first /jobs/next
            # poll made a freshly enrolled host show as 'offline' (see
            # monitoring.connectivity_tier), so the dashboard read 0%
            # reachable immediately after a successful enrollment.
            last_seen=now,
            status="healthy",
        )
        db.add(host)
    db.commit()
    db.refresh(host)
    if claimed_vmid and host.proxmox_vmid != claimed_vmid:
        audit.log(db, actor="system", role="controller", action="enroll_vmid_ignored",
                  detail=f"{host.hostname} — the agent reported VM {claimed_vmid}, which was not applied: "
                         + ("a VM id isn't accepted with the shared secret" if shared_secret
                            else f"this machine is already linked to VM {host.proxmox_vmid}"),
                  tone="warning")
    _try_auto_resolve_vmid(db, host)
    return host, secret


@router.post("/enroll/tokens", response_model=schemas.EnrollTokenOut)
def create_enrollment_token(payload: schemas.EnrollTokenCreate, db: Session = Depends(get_db),
                             user: models.User = Depends(require_role("admin"))):
    """
    Admin-side: generate a one-time token for a specific hostname.
    Hand this to whoever is installing the agent on that host (or bake
    it into the install command). It's single-use and expires. Still
    the tightest-scoped option — use this over self-enroll when you
    want each host individually authorized rather than sharing one
    secret across the fleet. Admin-only: issuing a host credential is
    a privileged action, same tier as editing patch definitions.
    """
    token = generate_enrollment_token()
    expires = datetime.utcnow() + timedelta(minutes=settings.enrollment_token_ttl_minutes)
    row = models.EnrollmentToken(
        token=hash_secret(token), hostname=payload.hostname, team=payload.team,   # only the digest is kept
        role=payload.role, created_by=user.username, expires_at=expires,
    )
    db.add(row)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="enroll_token_created",
              detail=f"for {payload.hostname}, expires {expires.isoformat()}")
    return schemas.EnrollTokenOut(token=token, hostname=payload.hostname, expires_at=expires)


@router.post("/agent/enroll", response_model=schemas.AgentEnrollResponse)
@limiter.limit("20/minute")
def agent_enroll(request: Request, payload: schemas.AgentEnrollRequest, db: Session = Depends(get_db)):
    """
    Agent-side: redeem a one-time token for a long-lived per-host secret.
    The secret is returned exactly once — the agent must store it locally
    (e.g. /etc/kite/agent.conf, root-readable only) and use it as a
    Bearer token on every subsequent call.
    """
    tok = db.query(models.EnrollmentToken).filter(models.EnrollmentToken.token == hash_secret(payload.token)).first()
    if not tok:
        raise HTTPException(404, "Unknown enrollment token")
    if tok.used:
        raise HTTPException(409, "Token already used")
    if tok.expires_at and tok.expires_at < datetime.utcnow():
        raise HTTPException(410, "Token expired")

    host, secret = _upsert_host(
        db, hostname=tok.hostname, team=tok.team, role=tok.role,
        os_version=payload.os_version, os_family=payload.os_family,
        smbios_uuid=payload.smbios_uuid, poll_interval_seconds=payload.poll_interval_seconds,
        proxmox_vmid=payload.proxmox_vmid,
    )

    tok.used = True
    db.commit()
    audit.log(db, actor="system", role="agent", action="host_enrolled",
              detail=f"{host.hostname} ({payload.os_version}) via one-time token", tone="success")
    return schemas.AgentEnrollResponse(host_id=host.id, agent_secret=secret)


@router.post("/agent/self-enroll", response_model=schemas.AgentEnrollResponse)
@limiter.limit("20/minute")
def agent_self_enroll(request: Request, payload: schemas.AgentSelfEnrollRequest, db: Session = Depends(get_db)):
    """
    Shared-secret enrollment — same pattern as Wazuh's authd password or
    Qualys's Activation ID: one secret, configured once on the controller,
    reused across every host's install command. Bootstraps enrollment
    only — the response is a fresh, unique per-host credential that
    replaces this shared secret for everything the agent does afterward.

    Self-enroll is always reachable, gated only by knowing the current
    secret — which is either what you pinned in .env, or an unpredictable
    one generated fresh each process start (see config.py). Rotate a
    pinned secret by changing .env and restarting; an unpinned one
    rotates itself on every restart automatically.
    """
    # Constant-time compare — same reasoning as the ticket webhook secret
    # elsewhere in this codebase: a plain `!=` short-circuits on the
    # first differing byte, which is a (slow, but real) timing side
    # channel on a secret gating unauthenticated host enrollment.
    if not hmac.compare_digest(payload.secret.encode(), settings.enroll_secret.encode()):
        raise HTTPException(401, "Invalid enrollment secret")

    host, secret = _upsert_host(
        db, hostname=payload.hostname, team=payload.team, role=payload.role,
        os_version=payload.os_version, os_family=payload.os_family,
        smbios_uuid=payload.smbios_uuid, poll_interval_seconds=payload.poll_interval_seconds,
        proxmox_vmid=payload.proxmox_vmid, shared_secret=True,
    )

    audit.log(db, actor="system", role="agent", action="host_enrolled",
              detail=f"{host.hostname} ({payload.os_version}) via shared secret", tone="warning")
    return schemas.AgentEnrollResponse(host_id=host.id, agent_secret=secret)
