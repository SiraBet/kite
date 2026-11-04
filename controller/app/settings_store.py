"""
Shared home for the generic Setting key/value store (routers/settings.py
serves it over HTTP; app/rollback/ and app/notifications.py also read
from it directly, so this lives below all of them rather than inside
the router module).
"""
from sqlalchemy.orm import Session as DbSession

from . import models

DEFAULTS = {
    # Off by default -- most self-hosted/homelab installs don't run an
    # ITSM behind this and shouldn't be forced through a ticket just to
    # patch their own fleet. Change control is still fully available,
    # just opt-in (Settings -> "Require an approved ticket to run a
    # patch") for anyone who does want it -- nothing about the feature
    # itself was removed, only the default.
    "require_ticket": "false",
    "rollback_default_backend": "proxmox",  # 'proxmox' | 'dnf_history' | 'none' -- see app/rollback/
    # Off by default: an update that can't be installed (built for a newer
    # OS, a vendor repo missing a dependency) fails the patch stage loudly.
    # On, dnf hosts run with --nobest --skip-broken and the stage lists
    # what it left behind. apt already holds such packages back.
    "patch_skip_uninstallable": "false",
    # Snapshot cleanup (app/snapshot_retention.py): keep the newest N of
    # kite's own snapshots per VM and none older than D days; 0 = no
    # limit of that kind. Snapshots from failed/stopped/running runs and
    # ones marked Keep are never removed.
    "snapshot_cleanup": "true",
    "snapshot_keep_count": "2",
    "snapshot_keep_days": "7",
    # Daily database backups kept (app/db_backups.py); 0 turns them off.
    "db_backup_keep": "7",
    # Days of activity log kept; older entries are removed daily. 0 keeps all.
    "audit_keep_days": "365",
    # Vulnerability matching (app/vulnerabilities.py). Off by default: on,
    # the controller downloads the distributions' security data from OSV
    # daily -- its only connection to the internet.
    "vuln_feed_enabled": "false",
    "rollback_proxmox_host": "",
    "rollback_proxmox_node": "",
    "rollback_proxmox_token_id": "",
    # Deliberately "" (not "true"/"false") when unset -- lets
    # resolve_proxmox_config() tell "never configured, fall back to
    # PROXMOX_VERIFY_SSL in .env" apart from "explicitly set to false via
    # the UI". A non-empty default here would silently defeat that
    # fallback for every existing .env-configured deployment.
    "rollback_proxmox_verify_ssl": "",

    # --- Notifications ---
    "notify_on_success": "false",  # run_completed is opt-in -- see app/notifications.py
    "notify_smtp_host": "",
    "notify_smtp_port": "",
    "notify_smtp_username": "",
    "notify_smtp_from": "",
    "notify_smtp_to": "",
    "notify_smtp_use_tls": "",  # "" = default on, same blank-means-default convention as rollback_proxmox_verify_ssl

    # --- Agent self-update ---
    # '' = disabled, the default -- nothing changes for anyone who
    # doesn't opt in. Set to a version string (e.g. "0.1.6") matching a
    # build actually published in the dnf repo to have every dnf-based
    # agent self-update to it on its next idle poll. See app/routers/agent.py.
    "agent_target_version": "",

    # --- SSO / LDAP ---
    "ldap_enabled": "false",
    "ldap_server_uri": "",       # e.g. "ldaps://dc.example.com:636" or "ldap://dc.example.com:389"
    "ldap_bind_dn": "",          # service account for the search bind; blank = search anonymously
    "ldap_user_base_dn": "",     # e.g. "ou=people,dc=example,dc=com"
    "ldap_user_filter": "(uid={username})",  # '{username}' is filter-escaped before substitution -- see app/ldap_auth.py
    "ldap_default_role": "operator",  # role assigned the first time a given LDAP user logs in
}

# Base names for secrets that get encrypted (app/crypto.py) and stored
# under "{name}_enc" -- never exposed via the generic GET/PUT /settings
# endpoints, only as a "{name}_set" boolean, and only writable through
# their own dedicated endpoint. See routers/settings.py.
SECRET_NAMES = {
    "rollback_proxmox_token_secret",
    "notify_generic_webhook",
    "notify_slack_webhook",
    "notify_smtp_password",
    "ticket_webhook_secret",
    "ldap_bind_password",
}
SECRET_KEYS = {f"{name}_enc" for name in SECRET_NAMES}


def get_setting(db: DbSession, key: str) -> str:
    row = db.query(models.Setting).filter(models.Setting.key == key).first()
    return row.value if row else DEFAULTS.get(key, "")


def set_setting(db: DbSession, key: str, value: str) -> models.Setting:
    row = db.query(models.Setting).filter(models.Setting.key == key).first()
    if row:
        row.value = value
    else:
        row = models.Setting(key=key, value=value)
        db.add(row)
    db.commit()
    return row


def get_secret(db: DbSession, name: str) -> str:
    """Decrypts a value stored via set_secret(). '' if never set."""
    from . import crypto
    encrypted = get_setting(db, f"{name}_enc")
    return crypto.decrypt(encrypted) if encrypted else ""


def set_secret(db: DbSession, name: str, value: str) -> bool:
    """Encrypts and stores; pass '' to clear. Returns whether a value is set afterward."""
    from . import crypto
    encrypted = crypto.encrypt(value) if value else ""
    set_setting(db, f"{name}_enc", encrypted)
    return bool(encrypted)
