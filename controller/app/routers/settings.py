from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DbSession

from .. import crypto, friendly_errors, models, schemas, audit, proxmox, proxmox_connections, proxmox_inventory, vulnerabilities
from ..config import settings as app_settings
from ..db import get_db
from ..auth import get_current_user, require_role, ROLE_RANK
from ..settings_store import DEFAULTS, SECRET_KEYS, SECRET_NAMES, set_setting, set_secret

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_model=List[schemas.SettingOut])
def list_settings(db: DbSession = Depends(get_db), user: models.User = Depends(get_current_user)):
    out = {k: v for k, v in DEFAULTS.items() if k not in SECRET_KEYS}
    secret_rows = {}
    for row in db.query(models.Setting).all():
        if row.key in SECRET_KEYS:
            secret_rows[row.key] = row.value
            continue
        out[row.key] = row.value
    # Never expose the encrypted blob itself -- just whether one is set,
    # same as how a UI shows "API key: ****configured****" rather than
    # the key, for every secret this app knows about (not just Proxmox's).
    for name in SECRET_NAMES:
        out[f"{name}_set"] = "true" if secret_rows.get(f"{name}_enc") else "false"
    return [schemas.SettingOut(key=k, value=v) for k, v in out.items()]


@router.put("/secret/{name}")
def set_secret_setting(name: str, payload: schemas.SettingUpdate, db: DbSession = Depends(get_db),
                        user: models.User = Depends(require_role("admin"))):
    """
    Write-only by design, for any of SECRET_NAMES: stores an encrypted
    value (see app/crypto.py) and never returns it back to the browser —
    the generic GET /settings only ever reports "{name}_set" (a
    boolean). Pass an empty value to clear it. Safe to register in any
    order relative to PUT /{key} below despite both being under
    /settings/ -- {key} only ever captures one path segment, and this
    path has two ("secret", then {name}), so they're structurally
    different routes, not just parameter-vs-literal on the same shape
    (see the comment on /rollback-proxmox-secret for the case where that
    distinction actually mattered).
    """
    if name not in SECRET_NAMES:
        raise HTTPException(404, f"Unknown secret setting '{name}' — must be one of {sorted(SECRET_NAMES)}")
    is_set = set_secret(db, name, payload.value)
    audit.log(db, actor=user.username, role=user.role, action="setting_changed",
              detail=f"{name} {'set' if is_set else 'cleared'}")
    return {"ok": True, "set": is_set}


@router.put("/rollback-proxmox-secret")
def set_rollback_proxmox_secret(payload: schemas.SettingUpdate, db: DbSession = Depends(get_db),
                                 user: models.User = Depends(require_role("admin"))):
    """
    Kept as its own stable path (the frontend calls it) rather than
    folded into the generic /settings/secret/{name} above; both go
    through the same set_secret().

    Must stay registered BEFORE the generic PUT /{key} below. Starlette
    matches routes in registration order, so with the order reversed a
    request here matches PUT /{key} with key="rollback-proxmox-secret"
    and stores the token in plaintext under that literal key.
    """
    is_set = set_secret(db, "rollback_proxmox_token_secret", payload.value)
    audit.log(db, actor=user.username, role=user.role, action="setting_changed",
              detail=f"rollback_proxmox_token_secret {'set' if is_set else 'cleared'}")
    return {"ok": True, "set": is_set}


# What each use of the connection needs, in the words the test reports.
# Sys.Audit lets the token read the node list; VM.Audit the guests and
# their config; VM.Snapshot and VM.PowerMgmt are the only ones that change anything.
PROXMOX_USES = [
    ("VM.Audit", "Coverage, Topology, network discovery and VM-id lookup"),
    ("Sys.Audit", "node status and network config in Topology"),
    # Since Proxmox 8, local bridges (vmbr*) are SDN resources: without
    # this the node's network listing silently omits every bridge.
    ("SDN.Audit", "seeing bridges, and so VLANs, in Topology's network view"),
    ("VM.Snapshot", "snapshots before a patch, and restoring one (the Proxmox rollback backend)"),
    # Optional: a restored snapshot (taken without RAM) leaves the VM off.
    ("VM.PowerMgmt", "starting a VM again after restoring a snapshot"),
]


@router.post("/proxmox-test")
def test_proxmox_connection(payload: schemas.ProxmoxTest, db: DbSession = Depends(get_db),
                            user: models.User = Depends(require_role("admin"))):
    """
    Try a Proxmox connection without saving it: reach the cluster, count
    what the token can see, and say which uses its privileges cover.
    Read-only on the Proxmox side. The secret in the request is used for
    this one call and never stored or logged.
    """
    saved_conn = proxmox_connections.get_connection(db, payload.connection_id) if payload.connection_id else None
    saved = saved_conn.cfg if saved_conn else proxmox.ProxmoxConfig()
    cfg = proxmox.ProxmoxConfig(
        host=(payload.host or "").strip() or saved.host,
        node=saved.node,
        token_id=(payload.token_id or "").strip() or saved.token_id,
        token_secret=payload.token_secret or saved.token_secret,
        verify_ssl=saved.verify_ssl if payload.verify_ssl is None else payload.verify_ssl,
    )
    missing = [label for label, value in (("address", cfg.host), ("token ID", cfg.token_id),
                                           ("token secret", cfg.token_secret)) if not value]
    if missing:
        return {"ok": False, "error": f"Missing {', '.join(missing)}"}
    try:
        rows = proxmox.list_cluster_resources(cfg)
    except (proxmox.ProxmoxError, OSError) as e:
        return {"ok": False, "error": friendly_errors.report(e, context=f"connection test {cfg.host}:8006",
                                                             token_hint="Check the token ID and secret.")}
    try:
        privs = proxmox.token_privileges(cfg)
    except (proxmox.ProxmoxError, OSError):
        privs = None  # the connection works; the permission readout is a bonus
    # A standalone host that has since joined a cluster is reachable
    # through both connections, and every VM on it would show twice.
    nodes = {r["node"] for r in rows if r.get("type") == "node"}
    overlaps = []
    for other in proxmox_connections.list_connections(db):
        if other.id is None or other.id == payload.connection_id:
            continue
        _, other_rows = proxmox_inventory._connection_rows(other)
        shared = nodes & {r["node"] for r in other_rows if r.get("type") == "node"}
        if shared:
            overlaps.append({"connection": other.name, "nodes": sorted(shared)})
    return {
        "ok": True,
        "overlaps": overlaps,
        "nodes": sum(1 for r in rows if r.get("type") == "node"),
        "guests": sum(1 for r in rows if r.get("type") in ("qemu", "lxc") and not r.get("template")),
        "uses": None if privs is None else [
            {"privilege": p, "use": use, "granted": p in privs} for p, use in PROXMOX_USES],
    }


def _connection_out(db: DbSession, row: models.ProxmoxConnection) -> dict:
    # VMs and containers seen on this connection, from the NICs network
    # discovery last read (no live Proxmox call just to list settings).
    guests = db.query(models.ProxmoxGuestNic.vmid).filter(
        models.ProxmoxGuestNic.connection_id == row.id).distinct().count()
    return dict(id=row.id, name=row.name, host=row.host, node=row.node or "", token_id=row.token_id,
                guests=guests,
                verify_ssl=bool(row.verify_ssl), secret_set=bool(row.token_secret_enc),
                secret_from_env=not row.token_secret_enc and bool(app_settings.proxmox_token_secret),
                linked_hosts=db.query(models.Host).filter(models.Host.proxmox_connection_id == row.id).count(),
                created_by=row.created_by or "", created_at=row.created_at)


@router.get("/proxmox-connections", response_model=List[schemas.ProxmoxConnectionOut])
def list_proxmox_connections(db: DbSession = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    """Every Proxmox connection; secrets only as whether one is set."""
    return [_connection_out(db, r) for r in db.query(models.ProxmoxConnection).order_by(models.ProxmoxConnection.id)]


def _name_taken(db: DbSession, name: str, other_than: int = None) -> bool:
    q = db.query(models.ProxmoxConnection).filter(models.ProxmoxConnection.name == name)
    if other_than is not None:
        q = q.filter(models.ProxmoxConnection.id != other_than)
    return q.first() is not None


@router.post("/proxmox-connections", response_model=schemas.ProxmoxConnectionOut)
def create_proxmox_connection(payload: schemas.ProxmoxConnectionIn, db: DbSession = Depends(get_db),
                              user: models.User = Depends(require_role("admin"))):
    if not payload.token_secret:
        raise HTTPException(400, "The token secret is required for a new connection")
    if _name_taken(db, payload.name):
        raise HTTPException(409, f"A connection named '{payload.name}' already exists")
    # Adding to a list that's still empty: the old single connection (if
    # any) becomes the first row now rather than at the next restart, so
    # the two never coexist with one of them unnumbered.
    proxmox_connections.adopt_legacy_connection(db)
    row = models.ProxmoxConnection(name=payload.name, host=payload.host, node=payload.node or "",
                                   token_id=payload.token_id, token_secret_enc=crypto.encrypt(payload.token_secret),
                                   verify_ssl=payload.verify_ssl, created_by=user.username)
    db.add(row)
    db.commit()
    db.refresh(row)
    proxmox_inventory.clear_cache()
    audit.log(db, actor=user.username, role=user.role, action="proxmox_connection_added",
              detail=f"'{row.name}' ({row.host}, token {row.token_id})")
    return _connection_out(db, row)


@router.patch("/proxmox-connections/{connection_id}", response_model=schemas.ProxmoxConnectionOut)
def update_proxmox_connection(connection_id: int, payload: schemas.ProxmoxConnectionPatch,
                              db: DbSession = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    row = db.query(models.ProxmoxConnection).filter(models.ProxmoxConnection.id == connection_id).first()
    if not row:
        raise HTTPException(404, "Connection not found")
    fields = payload.model_dump(exclude_unset=True)
    if fields.get("name") and _name_taken(db, fields["name"], other_than=row.id):
        raise HTTPException(409, f"A connection named '{fields['name']}' already exists")
    secret = fields.pop("token_secret", None)
    for key, value in fields.items():
        if value is not None:
            setattr(row, key, value)
    if secret:  # blank keeps the saved secret, as everywhere secrets are write-only
        row.token_secret_enc = crypto.encrypt(secret)
    db.commit()
    db.refresh(row)
    proxmox_inventory.clear_cache()
    changed = sorted(list(fields) + (["token_secret"] if secret else []))
    audit.log(db, actor=user.username, role=user.role, action="proxmox_connection_updated",
              detail=f"'{row.name}': {', '.join(changed) or 'nothing'}")
    return _connection_out(db, row)


@router.delete("/proxmox-connections/{connection_id}")
def delete_proxmox_connection(connection_id: int, db: DbSession = Depends(get_db),
                              user: models.User = Depends(require_role("admin"))):
    """
    Remove a connection and everything learned through it. Machines whose
    VM was on it lose that link (their vmid only meant something there) --
    they keep their run history, and re-link on their own if their VM
    turns up on another connection.
    """
    row = db.query(models.ProxmoxConnection).filter(models.ProxmoxConnection.id == connection_id).first()
    if not row:
        raise HTTPException(404, "Connection not found")
    unlinked = db.query(models.Host).filter(models.Host.proxmox_connection_id == row.id) \
        .update({models.Host.proxmox_connection_id: None, models.Host.proxmox_vmid: None,
                 models.Host.proxmox_node: None}, synchronize_session=False)
    for model in (models.ProxmoxBridge, models.ProxmoxGuestNic, models.ProxmoxIgnoredGuest, models.ProxmoxGuestFlag):
        db.query(model).filter(model.connection_id == row.id).delete(synchronize_session=False)
    name = row.name
    db.delete(row)
    db.commit()
    proxmox_inventory.clear_cache()
    audit.log(db, actor=user.username, role=user.role, action="proxmox_connection_removed",
              detail=f"'{name}'" + (f" — {unlinked} machine(s) unlinked from their VM" if unlinked else ""),
              tone="warning")
    return {"ok": True, "unlinked_hosts": unlinked}


@router.put("/{key}", response_model=schemas.SettingOut)
def update_setting(key: str, payload: schemas.SettingUpdate, db: DbSession = Depends(get_db),
                    user: models.User = Depends(require_role("admin"))):
    if key in SECRET_KEYS or key in SECRET_NAMES:
        raise HTTPException(400, "Use PUT /settings/secret/{name} to set this value — it needs encrypting, not a plain write.")
    if key in ("snapshot_keep_count", "snapshot_keep_days") and not (payload.value.isdigit() and int(payload.value) <= 1000):
        raise HTTPException(400, f"{key} must be a whole number from 0 to 1000 (0 = no limit)")
    if key == "run_start_timeout_hours" and not (payload.value.isdigit() and int(payload.value) <= 720):
        raise HTTPException(400, "run_start_timeout_hours must be a whole number of hours from 0 to 720 (0 = never expire)")
    if key == "db_backup_keep" and not (payload.value.isdigit() and int(payload.value) <= 365):
        raise HTTPException(400, "db_backup_keep must be a whole number from 0 to 365 (0 = no backups)")
    if key == "audit_keep_days" and not (payload.value.isdigit() and int(payload.value) <= 3650):
        raise HTTPException(400, "audit_keep_days must be a whole number of days from 0 to 3650 (0 = keep all)")
    if key in ("require_ticket", "patch_skip_uninstallable", "snapshot_cleanup", "vuln_feed_enabled",
               "notify_smtp_verify_cert") and payload.value not in ("true", "false"):
        raise HTTPException(400, f"{key} must be 'true' or 'false'")
    if key == "ldap_default_role" and payload.value not in ROLE_RANK:
        raise HTTPException(400, f"ldap_default_role must be one of {list(ROLE_RANK)}")
    row = set_setting(db, key, payload.value)
    audit.log(db, actor=user.username, role=user.role, action="setting_changed", detail=f"{key} = {payload.value}")
    if key == "vuln_feed_enabled":
        if payload.value == "true":
            vulnerabilities.refresh_in_background()
        else:
            db.query(models.HostVuln).delete(synchronize_session=False)
            db.query(models.Host).update({"vulns_matched_at": None}, synchronize_session=False)
            db.commit()
    return schemas.SettingOut(key=row.key, value=row.value)
