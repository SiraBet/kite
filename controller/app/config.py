import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv

from .security import cli_safe_token

# Loaded from environment. Copy .env.example to .env and fill in once
# you've created the Proxmox API token and know your VM IDs.
load_dotenv()


def _read_credential(name: str) -> str:
    """
    Prefer a systemd LoadCredential= file over a plaintext env var, for
    deployments that opt into it (see the commented-out LoadCredential=
    lines in kite-controller.service). Returns '' if this unit has
    no credentials directory at all (LoadCredential= not used) or this
    specific credential wasn't configured — the caller falls back to the
    env var in that case, so .env keeps working unchanged for everyone
    who doesn't opt in.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not creds_dir:
        return ""
    try:
        return (Path(creds_dir) / name).read_text().strip()
    except FileNotFoundError:
        return ""


# Where auto-generated secrets are kept so they survive a restart.
# Defaults to the directory holding the database, which is the one place
# every install path already guarantees is writable and persistent: the
# systemd unit's WorkingDirectory, and the mounted volume under Docker
# (KITE_DB=/app/data/kite.db — see docker-compose.yml).
STATE_DIR = Path(
    os.environ.get("KITE_STATE_DIR")
    or Path(os.environ.get("KITE_DB", "kite.db")).resolve().parent
)


def _persisted(name: str) -> str:
    try:
        return (STATE_DIR / name).read_text().strip()
    except OSError:
        return ""


def _persist(name: str, value: str) -> bool:
    """
    Store an auto-generated secret so the next start reuses it. Best
    effort, and deliberately so: a read-only or missing state directory
    is not a reason to refuse to boot — it just means falling back to the
    old regenerate-every-restart behavior, which the caller then says out
    loud. Created 0600 before any content is written to it.
    """
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(STATE_DIR / name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(value)
        return True
    except OSError:
        return False


def _resolve_enroll_secret() -> tuple:
    """
    If KITE_ENROLL_SECRET isn't set (env or systemd credential),
    generate one rather than making "pick a secret" a blocking decision
    on first install — the same behavior Wazuh's manager has for its
    authd password.

    An auto-generated secret is written to STATE_DIR so it survives a
    restart. Without that, every install command carrying it would stop
    working the next time the controller came back up — most visibly on
    the Docker path, where restarting is the normal way to apply a
    setting. A secret pinned in the environment takes priority.

    Returns (value, newly_generated, persisted).
    """
    configured = _read_credential("enroll_secret") or os.environ.get("KITE_ENROLL_SECRET", "")
    if configured:
        return configured, False, False
    stored = _persisted("enroll_secret")
    if stored:
        return stored, False, True
    generated = cli_safe_token(24)
    return generated, True, _persist("enroll_secret", generated)


def _resolve_secret_key() -> tuple:
    """
    Key for app/crypto.py — encrypts secrets that need to be read back
    (currently: a Proxmox API token entered via Settings → Connections, and
    the notification webhook/SMTP secrets), unlike agent secrets and
    passwords, which are hashed one-way and never decrypted.

    Same resolve-then-persist pattern as _resolve_enroll_secret, and
    persistence matters more here than anywhere else: if this key
    changes, everything encrypted under it becomes permanently
    unreadable — a saved Proxmox token, the notification webhook URLs
    and SMTP password. A key pinned in the environment takes priority,
    and is the right choice when it should live somewhere other than
    beside the database it protects.

    Returns (value, newly_generated, persisted).
    """
    configured = _read_credential("secret_key") or os.environ.get("KITE_SECRET_KEY", "")
    if configured:
        return configured, False, False
    stored = _persisted("secret_key")
    if stored:
        return stored, False, True
    generated = Fernet.generate_key().decode()
    return generated, True, _persist("secret_key", generated)


def _announce(label: str, env_var: str, filename: str, value: str, persisted: bool, warning: str = ""):
    """
    Printed once, on the run that generates the secret — never again on
    later starts, since it's stable from then on. Goes to stdout so it
    lands in `journalctl -u kite-controller` and in
    `docker compose logs` identically.
    """
    print("=" * 72)
    print(f"kite: {env_var} was not set — generated {label}:")
    print(f"    {value}")
    if persisted:
        print(f"Saved to {STATE_DIR / filename} and reused on every restart.")
        print(f"To manage it yourself instead, set {env_var} in .env.")
    else:
        print(f"COULD NOT SAVE IT — {STATE_DIR} is not writable, so this changes on")
        print(f"every restart. Pin it now by adding to .env:  {env_var}={value}")
        if warning:
            print(warning)
    print("=" * 72)


_enroll_secret, _enroll_new, _enroll_persisted = _resolve_enroll_secret()
if _enroll_new:
    _announce("a host-enrollment secret", "KITE_ENROLL_SECRET", "enroll_secret",
              _enroll_secret, _enroll_persisted)

_secret_key, _key_new, _key_persisted = _resolve_secret_key()
if _key_new:
    _announce("an encryption key", "KITE_SECRET_KEY", "secret_key", _secret_key, _key_persisted,
              warning="Anything encrypted under it (a saved Proxmox token, webhook URLs) "
                      "becomes unreadable the moment it changes.")


@dataclass
class Settings:
    proxmox_host: str = os.environ.get("PROXMOX_HOST", "")            # e.g. "10.0.0.5" or "proxmox.lab"
    proxmox_node: str = os.environ.get("PROXMOX_NODE", "")            # Proxmox node name hosting the VMs
    proxmox_token_id: str = os.environ.get("PROXMOX_TOKEN_ID", "")    # e.g. "kite@pve!snap"
    proxmox_token_secret: str = _read_credential("proxmox_token_secret") or os.environ.get("PROXMOX_TOKEN_SECRET", "")
    proxmox_verify_ssl: bool = os.environ.get("PROXMOX_VERIFY_SSL", "false").lower() == "true"

    enrollment_token_ttl_minutes: int = int(os.environ.get("ENROLL_TOKEN_TTL_MIN", "60"))
    soak_seconds: int = int(os.environ.get("SOAK_SECONDS", "20"))  # shortened for lab use

    # How often the background pass finishes soak stages whose wait has
    # elapsed (app/jobs_engine.py's deferred_loop). The soak wait is no
    # longer a blocking sleep inside the agent's report request, so this
    # interval — not soak_seconds — is what bounds how quickly a finished
    # run actually shows as 'done'. Keep it well under soak_seconds.
    deferred_stage_interval_seconds: int = int(os.environ.get("DEFERRED_STAGE_INTERVAL_SECONDS", "5"))

    # Shared self-enrollment secret — same pattern as Wazuh's authd
    # registration password. Auto-generated on first start if not set in
    # .env and then persisted, so it stays stable across restarts (see
    # _resolve_enroll_secret above). Self-enroll is always enabled;
    # anyone holding this secret can enroll a host under any hostname —
    # reasonable for a single-operator lab on a private network, not for
    # anything wider. Rotate by deleting the state file (or changing the
    # pinned value) and restarting.
    #
    # The _generated flag below means "generated AND could not be saved",
    # i.e. it really will change on the next restart — not merely "not
    # configured by hand".
    enroll_secret: str = _enroll_secret
    enroll_secret_generated: bool = _enroll_new and not _enroll_persisted

    # Empty by default = no cross-origin browser access at all. The
    # controller serves its own frontend same-origin (see main.py's
    # index() route), so nothing needs this unless you're running a
    # separate frontend/integration on another origin — set
    # CORS_ORIGINS to a comma-separated allowlist of exact origins
    # (e.g. "https://kite.example.com") for that case, or "*" for
    # any origin.
    #
    # "*" is safe here specifically because the CORS middleware is added
    # without allow_credentials (see main.py): browsers won't attach the
    # session cookie to a cross-origin request either way, so a wildcard
    # grants read access to unauthenticated endpoints only, not to
    # anyone's session. Adding allow_credentials later would change that
    # — a wildcard origin and credentials together is the combination to
    # avoid, and browsers reject that pairing outright.
    cors_origins: str = os.environ.get("CORS_ORIGINS", "")

    # --- Monitoring ---

    # How often the background monitor pass runs: stuck-stage detection
    # and host-offline-transition detection (see app/monitoring.py). Also
    # the effective floor on how quickly either gets audit-logged.
    monitor_interval_seconds: int = int(os.environ.get("MONITOR_INTERVAL_SECONDS", "300"))

    # An agent stage sitting at 'running' longer than this is flagged
    # stuck. General default is generous — a real `dnf update` on a host
    # with a lot of pending packages can legitimately run for a while.
    stuck_stage_minutes: int = int(os.environ.get("STUCK_STAGE_MINUTES", "60"))

    # 'reboot' gets its own, SHORTER threshold — this is the stage the
    # roadmap called out specifically. A host that's actually coming back
    # from a normal reboot does so in a few minutes; one still not back
    # after stuck_reboot_minutes is much more likely to indicate a host
    # that isn't coming back at all than a slow-but-fine reboot.
    stuck_reboot_minutes: int = int(os.environ.get("STUCK_REBOOT_MINUTES", "15"))

    log_format: str = os.environ.get("KITE_LOG_FORMAT", "text")  # "text" or "json"
    log_level: str = os.environ.get("KITE_LOG_LEVEL", "INFO")

    # --- Rollback ---
    secret_key: str = _secret_key
    secret_key_generated: bool = _key_new and not _key_persisted

    # --- Scheduling ---
    # How often the background loop checks schedules against the current
    # UTC day/hour. Shorter than an hour so a schedule reliably fires
    # near the top of its target hour rather than being missed between
    # checks; app/scheduler.py's own dedup (Schedule.last_fired_at)
    # keeps a shorter interval from firing the same slot twice.
    scheduler_interval_seconds: int = int(os.environ.get("SCHEDULER_INTERVAL_SECONDS", "300"))


settings = Settings()
