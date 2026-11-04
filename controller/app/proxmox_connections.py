"""
The Proxmox connections kite reads from: clusters and standalone
hosts side by side, each with its own API token.

Everything that talks to Proxmox goes through here rather than reading a
single config:

  - list_connections(): every configured connection. Before the first
    startup on this version (or on an install with nothing in the table
    yet), the old single connection from Settings or .env is returned as
    one connection with id None -- so nothing breaks in between.
  - connection_for_host(): the connection a host's VM id belongs to.
  - adopt_legacy_connection(): run at startup; turns that old single
    connection into the first row, once.

A VM id only means something within one connection, so anything keyed by
vmid is keyed by (connection id, vmid). A host, bridge, NIC or ignored
guest with connection id None belongs to "the only connection" -- the
state every install had before this existed.
"""
from dataclasses import dataclass
from typing import List, Optional

from sqlalchemy.orm import Session

from . import crypto, friendly_errors, models
from .config import settings
from . import rollback
from .proxmox import ProxmoxConfig


@dataclass
class Connection:
    id: Optional[int]
    name: str
    cfg: ProxmoxConfig
    env_secret: bool = False   # secret comes from PROXMOX_TOKEN_SECRET, not the DB

    @property
    def configured(self) -> bool:
        return bool(self.cfg.host and self.cfg.token_id and self.cfg.token_secret)


def _from_row(row: models.ProxmoxConnection) -> Connection:
    if row.token_secret_enc:
        secret, env = crypto.decrypt(row.token_secret_enc), False
    else:
        # Configured through .env: the secret stays there.
        secret, env = settings.proxmox_token_secret, True
    return Connection(id=row.id, name=row.name, env_secret=env, cfg=ProxmoxConfig(
        host=row.host, node=row.node or "", token_id=row.token_id, token_secret=secret,
        verify_ssl=bool(row.verify_ssl)))


def list_connections(db: Session) -> List[Connection]:
    rows = db.query(models.ProxmoxConnection).order_by(models.ProxmoxConnection.id).all()
    if rows:
        return [_from_row(r) for r in rows]
    # Looked up through the package at call time (not imported by name),
    # so there's one place that defines "the old single connection".
    legacy = rollback.resolve_proxmox_config(db)
    if legacy.host or legacy.token_id:
        return [Connection(id=None, name=legacy.host or "Proxmox", cfg=legacy,
                           env_secret=not _legacy_secret_in_db(db))]
    return []


def get_connection(db: Session, connection_id: Optional[int]) -> Optional[Connection]:
    return next((c for c in list_connections(db) if c.id == connection_id), None)


def effective_connection_id(host_connection_id: Optional[int], connections: List[Connection]) -> Optional[int]:
    """
    The connection a host's vmid belongs to: its own if set, else the only
    connection there is. None when that can't be told (several
    connections, none chosen) -- the host's vmid is then ambiguous.
    """
    if host_connection_id is not None:
        return host_connection_id
    return connections[0].id if len(connections) == 1 else None


def connection_for_host(db: Session, host: models.Host) -> Optional[Connection]:
    conns = list_connections(db)
    if host.proxmox_connection_id is not None:
        return next((c for c in conns if c.id == host.proxmox_connection_id), None)
    return conns[0] if len(conns) == 1 else None


def _legacy_secret_in_db(db: Session) -> bool:
    from .settings_store import get_setting
    return bool(get_setting(db, "rollback_proxmox_token_secret_enc"))


def adopt_legacy_connection(db: Session) -> Optional[models.ProxmoxConnection]:
    """
    Once, at startup: if the table is empty and the old single connection
    is configured (Settings or .env), make it the first row, and point
    everything that predates connections at it. Copies the encrypted
    secret as-is when it was in the DB; leaves it blank -- read from the
    environment -- when it came from .env.
    """
    if db.query(models.ProxmoxConnection).first():
        return None
    from .settings_store import get_setting
    legacy = rollback.resolve_proxmox_config(db)
    if not (legacy.host and legacy.token_id):
        return None
    row = models.ProxmoxConnection(
        name=legacy.host, host=legacy.host, node=legacy.node or "", token_id=legacy.token_id,
        token_secret_enc=get_setting(db, "rollback_proxmox_token_secret_enc") or "",
        verify_ssl=legacy.verify_ssl, created_by="system (upgrade)")
    db.add(row)
    db.flush()
    db.query(models.Host).filter(models.Host.proxmox_vmid.isnot(None),
                                 models.Host.proxmox_connection_id.is_(None)) \
        .update({models.Host.proxmox_connection_id: row.id}, synchronize_session=False)
    for model in (models.ProxmoxBridge, models.ProxmoxGuestNic, models.ProxmoxIgnoredGuest, models.ProxmoxGuestFlag):
        db.query(model).filter(model.connection_id.is_(None)) \
            .update({model.connection_id: row.id}, synchronize_session=False)
    db.commit()
    return row


def find_vm_by_smbios(db: Session, smbios_uuid: str):
    """
    Search every connection for the VM whose SMBIOS UUID the agent
    reported. Returns (connection, vmid, errors): connection and vmid are
    None when no connection had it; errors lists the connections that
    couldn't be searched, so "not found" and "couldn't look" stay apart.
    """
    import requests
    from . import proxmox
    errors = []
    for conn in list_connections(db):
        if not conn.configured:
            continue
        try:
            vmid = proxmox.find_vmid_by_smbios_uuid(conn.cfg, smbios_uuid)
        except (proxmox.ProxmoxError, requests.exceptions.RequestException) as e:
            errors.append(f"{conn.name}: " + friendly_errors.report(e, context="VMID lookup"))
            continue
        if vmid:
            return conn, vmid, errors
    return None, None, errors
