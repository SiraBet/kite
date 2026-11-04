"""
Cleaning up the Proxmox snapshots kite takes before each run.

A snapshot is a way back from a bad patch, useful for the days right
after it -- not a backup. Left alone they pile up: every one pins the
blocks that changed since, and long chains slow qcow2 disks. So kite
keeps the newest few per VM, none past an age (Settings -> Policy), and
removes the rest of its own -- never one it didn't take, and never one
a person might still need:

  - from a run that failed, was force-stopped, or is still going
    (that's the rollback point someone may be about to use)
  - marked Keep on the machine page

Runs after each successful run and once a day; each removal is audited.
"""
import asyncio
import re
import threading
from datetime import datetime

from sqlalchemy.orm import Session

from . import audit, models
from .db import SessionLocal
from .logging_config import logger
from .settings_store import get_setting

NAME = re.compile(r"^kite-job(\d+)-(\d+)$")
STARTUP_DELAY_SECONDS = 600
PASS_SECONDS = 24 * 3600
_ACTIVE = ("queued", "running")


def policy(db: Session) -> dict:
    def num(key, default):
        try:
            return max(0, int(get_setting(db, key) or default))
        except ValueError:
            return default
    return {"enabled": get_setting(db, "snapshot_cleanup") != "false",
            "keep_count": num("snapshot_keep_count", 2), "keep_days": num("snapshot_keep_days", 7)}


def host_vm(db: Session, host: models.Host):
    """(Proxmox config, node) for the host's VM. Raises RuntimeError when it can't be resolved."""
    from . import proxmox
    from .proxmox_connections import connection_for_host, list_connections
    if not host.proxmox_vmid:
        raise RuntimeError(f"{host.hostname} isn't linked to a Proxmox VM")
    conn = connection_for_host(db, host)
    if not conn:
        if not list_connections(db):
            raise RuntimeError("No Proxmox connection is configured — add one in Settings → Connections.")
        raise RuntimeError(f"{host.hostname} has VM {host.proxmox_vmid} but no Proxmox connection chosen, and "
                           "there's more than one — pick its connection on the machine page.")
    node = host.proxmox_node
    if not node:
        try:
            node = proxmox.resolve_vm_node(conn.cfg, host.proxmox_vmid)
        except proxmox.ProxmoxError:
            node = None
    return conn.cfg, node


def decide(rows: list, pol: dict, now: datetime) -> list:
    """
    Mark each of kite's snapshots keep/remove, newest first. Protected
    ones (pinned, or from a run that isn't a clean success) never count
    against the limit and are never removed.
    """
    rows = sorted(rows, key=lambda r: r["taken_at"], reverse=True)
    kept = 0
    for r in rows:
        status = r.get("job_status")
        if r.get("kept"):
            r.update(remove=False, reason="marked Keep")
        elif "job_status" in r and status is None:
            # A kite name, but no run on this machine with that number
            # (another install's, or from before a database restore).
            r.update(remove=False, reason="not from a run recorded for this machine — left alone")
        elif status in _ACTIVE:
            r.update(remove=False, reason="its run is still going")
        elif status in ("failed", "cancelled"):
            r.update(remove=False, reason=f"its run {'failed' if status == 'failed' else 'was stopped'} — the way back if needed")
        elif not pol["enabled"]:
            r.update(remove=False, reason="automatic cleanup is off")
        else:
            age = (now - r["taken_at"]).days
            if pol["keep_count"] and kept >= pol["keep_count"]:
                r.update(remove=True, reason=f"more than {pol['keep_count']} newer ones")
            elif pol["keep_days"] and age > pol["keep_days"]:
                r.update(remove=True, reason=f"older than {pol['keep_days']} days")
            else:
                r.update(remove=False, reason="recent")
                kept += 1
    return rows


def snapshots_for(db: Session, host: models.Host, now: datetime = None) -> list:
    """kite's snapshots of this host's VM, with what cleanup would do to each."""
    from . import proxmox
    cfg, node = host_vm(db, host)
    rows = []
    for s in proxmox.list_snapshots(cfg, host.proxmox_vmid, node):
        m = NAME.match(s.get("name") or "")
        if not m:
            continue   # not ours: never listed, never touched
        job_id = int(m.group(1))
        job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.host_id == host.id).first()
        taken = datetime.utcfromtimestamp(int(s.get("snaptime") or m.group(2)))
        rows.append({"name": s["name"], "job_id": job_id, "job_status": job.status if job else None,
                     "kept": bool(job and job.snapshot_keep), "taken_at": taken,
                     "description": s.get("description") or ""})
    return decide(rows, policy(db), now or datetime.utcnow())


def delete(db: Session, host: models.Host, name: str, actor: str, role: str, why: str):
    from . import proxmox
    cfg, node = host_vm(db, host)
    proxmox.delete_snapshot(cfg, host.proxmox_vmid, name, node)
    audit.log(db, actor=actor, role=role, action="snapshot_deleted",
              detail=f"{host.hostname} — {name} ({why})")


def clean_host(db: Session, host: models.Host) -> list:
    """Remove what the policy says to. Returns the names removed."""
    if not policy(db)["enabled"] or not host.proxmox_vmid:
        return []
    removed = []
    for r in snapshots_for(db, host):
        if r["remove"]:
            delete(db, host, r["name"], actor="system", role="controller", why=r["reason"])
            removed.append(r["name"])
    return removed


def clean_all():
    db = SessionLocal()
    try:
        if not policy(db)["enabled"]:
            return
        for host in db.query(models.Host).filter(models.Host.proxmox_vmid.isnot(None)).all():
            try:
                clean_host(db, host)
            except Exception as e:  # noqa: BLE001 -- one unreachable VM mustn't stop the rest
                logger.warning("snapshot cleanup skipped %s: %s", host.hostname, e)
    finally:
        db.close()


def clean_after_run(host_id: int):
    """After a successful run: tidy that VM in the background, off the agent's report request."""
    def work():
        db = SessionLocal()
        try:
            host = db.query(models.Host).filter(models.Host.id == host_id).first()
            if host:
                clean_host(db, host)
        except Exception as e:  # noqa: BLE001
            logger.warning("snapshot cleanup after run failed for host %s: %s", host_id, e)
        finally:
            db.close()
    threading.Thread(target=work, daemon=True, name=f"snapshot-cleanup-{host_id}").start()


async def retention_loop():
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            await asyncio.to_thread(clean_all)
        except Exception:  # noqa: BLE001 -- one bad pass must never kill the loop
            logger.exception("snapshot cleanup pass failed")
        await asyncio.sleep(PASS_SECONDS)
