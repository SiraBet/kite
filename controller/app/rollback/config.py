"""
Resolves Proxmox connection config field-by-field: DB (Settings ->
Rollback, set via the UI) if present, else .env / systemd credential
-- so an existing deployment with
PROXMOX_* already in .env keeps working with zero migration, and a
fresh one can configure entirely through the UI instead of editing files
and restarting. Mixing sources (e.g. host/node from .env, token entered
later via the UI) works fine since each field falls back independently.
"""
from .. import crypto
from ..config import settings
from ..proxmox import ProxmoxConfig
from ..settings_store import get_setting


def resolve_proxmox_config(db) -> ProxmoxConfig:
    host = get_setting(db, "rollback_proxmox_host") or settings.proxmox_host
    node = get_setting(db, "rollback_proxmox_node") or settings.proxmox_node
    token_id = get_setting(db, "rollback_proxmox_token_id") or settings.proxmox_token_id

    verify_raw = get_setting(db, "rollback_proxmox_verify_ssl")
    verify_ssl = (verify_raw == "true") if verify_raw != "" else settings.proxmox_verify_ssl

    encrypted_secret = get_setting(db, "rollback_proxmox_token_secret_enc")
    token_secret = crypto.decrypt(encrypted_secret) if encrypted_secret else settings.proxmox_token_secret

    return ProxmoxConfig(host=host, node=node, token_id=token_id, token_secret=token_secret, verify_ssl=verify_ssl)
