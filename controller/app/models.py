"""
Database models for kite-controller.

Design note on jobs/stages: STAGE_SEQUENCE is the canonical patch pipeline.
Each stage is tagged with an executor — 'agent' (runs on the target Rocky
host, reported back over the agent API) or 'controller' (runs here, e.g.
the Proxmox snapshot, which needs hypervisor access the agent never has).
The job engine (see jobs_engine.py) walks this sequence per job.
"""
from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Index, Text, UniqueConstraint, text
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

STAGE_SEQUENCE = [
    ("preflight", "agent"),      # connectivity, dnf lock, disk space, lock the host
    # Before anything changes on the machine: on apt, a pin rule installs
    # the pinned version (a downgrade, possibly) in `excludes`.
    ("snapshot", "controller"),  # Proxmox snapshot of the guest VM
    ("excludes", "agent"),       # apply skip/pin rules via dnf versionlock + excludes
    ("patch", "agent"),          # dnf update
    ("reboot", "agent"),         # reboot if needed, wait for host to come back
    ("containers", "agent"),     # pull + recreate selected compose services
    ("healthcheck", "agent"),    # basic service/uptime check post-patch
    ("soak", "controller"),      # a short wait before the run counts as done
]

# What a run is allowed to touch. A host's OS packages and the containers
# running on it are independent surfaces: patching the guest leaves a
# two-year-old image running, and updating an image does nothing for the
# kernel underneath. They are also on different cadences in practice, so
# a run picks one or both rather than always doing everything.
SCOPE_OS = "os"
SCOPE_CONTAINERS = "containers"
SCOPE_BOTH = "both"
RUN_SCOPES = [SCOPE_OS, SCOPE_CONTAINERS, SCOPE_BOTH]

# Stages that only make sense when the OS itself is being patched.
_OS_ONLY_STAGES = {"excludes", "patch", "reboot"}


def stages_for(scope: str):
    """
    The stage list for one run's scope, as (name, executor) pairs.

    'containers' drops the package-manager stages entirely rather than
    running them as no-ops: a skipped stage in the UI reads as something
    that went wrong, and `reboot` in particular must not be offered when
    nothing was installed that could require one.

    The containers stage sits after `reboot` on purpose. Container
    lifecycle is independent of the guest's, so updating images before a
    reboot would just have them restarted again moments later; running
    afterwards leaves them started against the host's final state, and
    keeps `healthcheck` as the last thing that judges the result.

    Note this is the template for a NEW job. A job's actual stages live
    in its own JobStage rows from creation onward, so changing this list
    never rewrites a run already in flight.
    """
    if scope == SCOPE_CONTAINERS:
        return [(name, ex) for name, ex in STAGE_SEQUENCE if name not in _OS_ONLY_STAGES]
    if scope == SCOPE_BOTH:
        return list(STAGE_SEQUENCE)
    return [(name, ex) for name, ex in STAGE_SEQUENCE if name != "containers"]

# Stages where the actual command is package-manager-specific — these are the
# ones an OS-specific script can override. 'healthcheck' (systemctl --failed)
# is systemd-generic across every target OS so far and stays built into the
# agent; revisit if that stops being true. 'reboot' is deliberately excluded
# even though it's package-manager-specific too — the built-in handler writes
# state to disk *before* rebooting so the agent can resume and report back
# after the host comes back up (see agent.py's resume_pending_reboot). A
# custom script has no way to hook into that; it would just die mid-reboot
# with the job stuck at 'running' forever. Revisit once there's a real
# mechanism for scripts to signal "I'm about to reboot, remember this job".
SCRIPTABLE_STAGES = ["preflight", "excludes", "patch"]
STAGE_LABELS = {"preflight": "Pre-flight & lock", "excludes": "Exclude / pin list", "patch": "Patch"}


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True)
    hostname = Column(String, unique=True, nullable=False)
    role = Column(String, default="")
    team = Column(String, default="")
    os_version = Column(String, default="")       # raw string, e.g. "Rocky Linux release 8.10 (Green Obsidian)"
    os_family = Column(String, default="")         # normalized key matching an OS-scripts folder, e.g. "rocky8"
    smbios_uuid = Column(String, default="")        # from /sys/class/dmi/id/product_uuid — used to auto-resolve proxmox_vmid
    poll_interval_seconds = Column(Integer, default=900)  # this host's actual configured baseline interval — self-reported on every poll, used to calibrate offline detection correctly per-host
    proxmox_vmid = Column(Integer, nullable=True)  # Proxmox VM ID, needed for the proxmox rollback backend
    # Which Proxmox node this VM actually runs on -- optional. Blank/None
    # means "resolve it live at snapshot time via the cluster's own view"
    # (app/proxmox.py's resolve_vm_node, ), which is deliberately
    # NOT cached here by default: a VM that gets live-migrated between
    # nodes would otherwise go stale. Set this explicitly only to skip
    # that lookup call (e.g. a restricted API token that can't read
    # /cluster/resources) or to pin a VM that never migrates.
    proxmox_node = Column(String, nullable=True)
    # Which Proxmox connection proxmox_vmid belongs to. VM ids are only
    # unique within one cluster or standalone host, so with several
    # connections a vmid alone is ambiguous. None = the only connection
    # (installs that predate multiple connections, or have just one).
    proxmox_connection_id = Column(Integer, ForeignKey("proxmox_connections.id"), nullable=True)
    rollback_backend = Column(String, nullable=True)  # 'proxmox' | 'dnf_history' | 'none' | None (= use the global default, see app/rollback/)
    agent_secret_hash = Column(String, nullable=True)
    agent_version = Column(String, default="")  # self-reported on every poll -- see app/routers/agent.py, app/notifications self-update
    # Set from the console to update just this host's agent; wins over the
    # fleet-wide agent_target_version setting. Cleared once it gets there.
    agent_update_to = Column(String, nullable=True)
    # The machine groups it's in (MachineGroup): for scripts and update rules
    groups = relationship("MachineGroup", secondary="machine_group_members", back_populates="hosts",
                          lazy="selectin", order_by="MachineGroup.name")

    @property
    def group_ids(self) -> list:
        return [g.id for g in self.groups]
    # 'docker' | 'podman' | 'nerdctl', or '' when the host has none.
    # Self-reported alongside the container inventory; blank also covers
    # hosts on an agent build that predates inventory reporting.
    container_runtime = Column(String, default="")
    # Fingerprint of the installed-software list last stored for this host
    # (HostSoftware), so agents only resend the list when it changed.
    software_hash = Column(String, nullable=True)
    software_reported_at = Column(DateTime, nullable=True)
    # When software was last matched against vulnerability data; None = never
    vulns_matched_at = Column(DateTime, nullable=True)
    # Whether the host's last update assessment succeeded, and when.
    # False is not "nothing pending" -- one unreachable repository fails
    # the whole query, and showing such a host as fully patched would be
    # actively misleading.
    updates_assessed_ok = Column(Boolean, default=None, nullable=True)
    updates_assessed_at = Column(DateTime, nullable=True)
    updates_error = Column(String, default="")
    # Network facts, self-reported with the inventory. None
    # = never reported (older agent, or the Windows agent, which doesn't
    # collect them yet); False = the agent tried and could not tell. The
    # interfaces and ports themselves are HostInterface/HostListeningPort.
    network_ok = Column(Boolean, nullable=True)
    network_error = Column(String, default="")
    network_reported_at = Column(DateTime, nullable=True)
    default_gateway = Column(String, default="")
    last_seen = Column(DateTime, nullable=True)
    last_patched = Column(DateTime, nullable=True)
    status = Column(String, default="unknown")     # healthy / due / overdue / unknown / locked
    enrolled_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    id = Column(Integer, primary_key=True)
    token = Column(String, unique=True, nullable=False)
    hostname = Column(String, nullable=False)
    team = Column(String, default="")
    role = Column(String, default="")
    used = Column(Boolean, default=False)
    created_by = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)


class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True)
    ticket_id = Column(String, unique=True, nullable=False)  # e.g. "CHG-4821"
    status = Column(String, default="Pending approval")
    description = Column(String, default="")
    window_start = Column(Integer, default=0)   # hour, 0-23, local
    window_end = Column(Integer, default=23)
    requester = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class MachineGroup(Base):
    """
    A named set of machines an admin puts together -- "db-servers",
    "pilot", "lab" -- of any OS and any size; a machine can be in several.
    Groups carry stage scripts (OsScript rows under the group's name; see
    app/groups.py) and are what update rules can apply to, besides OS
    families and single machines. A group exists on its own: empty,
    without scripts, until it's deleted.
    """
    __tablename__ = "machine_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    hosts = relationship("Host", secondary="machine_group_members", back_populates="groups", order_by="Host.hostname")


class MachineGroupMember(Base):
    __tablename__ = "machine_group_members"

    group_id = Column(Integer, ForeignKey("machine_groups.id"), primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), primary_key=True, index=True)


class PatchDef(Base):
    __tablename__ = "patch_defs"

    id = Column(Integer, primary_key=True)
    pkg_pattern = Column(String, nullable=False)
    mode = Column(String, nullable=False)   # 'skip' | 'pin'
    version = Column(String, default="")    # only meaningful when mode == 'pin'
    reason = Column(String, default="")
    reviewed = Column(String, default="not yet reviewed")
    # The OS family a rule was limited to before rules had `targets`
    # (migration 0023 copied it there). No longer read; kept for a downgrade.
    os_family = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    targets = relationship("PatchDefTarget", lazy="selectin", cascade="all, delete-orphan")


# What an update rule applies to. A rule with no targets applies to every
# machine; otherwise to each machine any target matches.
TARGET_KINDS = ("os", "group", "host")


class PatchDefTarget(Base):
    __tablename__ = "patch_def_targets"

    id = Column(Integer, primary_key=True)
    def_id = Column(Integer, ForeignKey("patch_defs.id"), nullable=False, index=True)
    kind = Column(String, nullable=False)     # os (value: an os_family) | group (a MachineGroup id) | host (a Host id)
    value = Column(String, nullable=False)


class DefHistory(Base):
    __tablename__ = "def_history"

    id = Column(Integer, primary_key=True)
    def_id = Column(Integer, ForeignKey("patch_defs.id"), nullable=True, index=True)
    pkg_pattern = Column(String)
    change = Column(String)
    by = Column(String)
    at = Column(DateTime, default=datetime.utcnow)


BATCH_ONE_AT_A_TIME = "one_at_a_time"
BATCH_PARALLEL = "parallel"
BATCH_ROLLOUTS = (BATCH_ONE_AT_A_TIME, BATCH_PARALLEL)


class Batch(Base):
    """
    Several machines patched together from one wizard (app/batches.py).
    Each machine still gets its own Job; this holds what they share and
    how they roll out:

      one_at_a_time -- the next machine's run starts when the previous one
                       finishes cleanly; a failed or stopped run pauses the
                       batch until someone continues or stops it.
      parallel      -- every machine's run starts at once.

    The run settings are kept here because, one at a time, later runs are
    created long after the wizard closed.
    """
    __tablename__ = "batches"

    id = Column(Integer, primary_key=True)
    rollout = Column(String, nullable=False)
    status = Column(String, default="running")   # running | paused | stopped | done
    paused_reason = Column(String, default="")
    host_ids = Column(Text, default="[]")        # JSON list, in rollout order
    next_index = Column(Integer, default=0)      # one at a time: the next host_ids entry to start
    skipped = Column(Text, default="{}")         # JSON {host_id: why it was skipped}
    settings = Column(Text, default="{}")        # JSON: ticket, scope, severity, checklist (see routers/runs.py)
    operator = Column(String, default="")
    operator_role = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)


class Job(Base):
    __tablename__ = "jobs"
    # At most one queued/running run per host (migration 0026): two
    # requests passing the "already active?" check at once can't both insert.
    __table_args__ = (Index("uq_jobs_one_active_per_host", "host_id", unique=True,
                            sqlite_where=text("status IN ('queued', 'running')")),)

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    # Snapshot of host.hostname at job creation, same "frozen, not
    # re-resolved live" reasoning as rollback_backend below. Exists
    # because DELETE /hosts/{id} only blocks deletion for an *active*
    # job -- a host with finished/cancelled job history deletes cleanly
    # (see that endpoint's docstring), which would otherwise leave this
    # job with only a host_id pointing at a row that no longer exists
    # (SQLite has foreign_keys off by default, no app-level cascade).
    # Nullable because jobs created before this column existed have no
    # value here -- see runs.py/schemas.py for the fallback used when
    # displaying those.
    hostname = Column(String, nullable=True)
    ticket_id = Column(String, nullable=False)
    operator = Column(String, default="")
    operator_role = Column(String, default="")
    status = Column(String, default="queued")   # queued / running / done / failed
    current_stage_index = Column(Integer, default=0)
    window_override_reason = Column(String, nullable=True)
    # 'os' | 'containers' | 'both' -- see RUN_SCOPES. Frozen at creation
    # like rollback_backend, since it determines the stage rows that were
    # already written for this job.
    scope = Column(String, default=SCOPE_OS)
    # 'update' (pull newer images) or 'rollback' (put the captured images
    # back). Only meaningful when the scope includes containers.
    container_action = Column(String, default="update")
    # '' / 'all' = every available update. 'security' = advisories only.
    # Anything else is a comma-separated severity list, e.g.
    # 'critical,important'. Frozen at creation like the other run
    # decisions.
    severity_filter = Column(String, default="")
    # Newline-separated container names this run may update. Empty means
    # "every updatable container on the host", resolved at creation so a
    # container appearing mid-run is not silently swept in.
    container_selection = Column(Text, default="")
    # Resolved once at job creation (host override, else the global default —
    # see app/rollback/) and frozen here rather than re-resolved live at
    # execution time, so a mid-run Settings change can't leave a job's
    # already-fixed stage executor (see STAGE_SEQUENCE / runs.py create_run)
    # pointing at a different backend than what actually runs.
    rollback_backend = Column(String, nullable=True)
    # Marked Keep on the machine page: snapshot cleanup never removes this
    # run's Proxmox snapshot (app/snapshot_retention.py).
    snapshot_keep = Column(Boolean, default=False)
    # Set when this run is one machine of a batch (several machines patched
    # together, see app/batches.py).
    batch_id = Column(Integer, ForeignKey("batches.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    host = relationship("Host")
    stages = relationship("JobStage", back_populates="job", order_by="JobStage.stage_index")


class JobStage(Base):
    __tablename__ = "job_stages"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, index=True)
    stage_index = Column(Integer, nullable=False)
    name = Column(String, nullable=False)
    executor = Column(String, nullable=False)   # 'agent' | 'controller'
    status = Column(String, default="pending")  # pending / running / done / failed
    output = Column(Text, default="")
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    job = relationship("Job", back_populates="stages")


class ChecklistConfirmation(Base):
    __tablename__ = "checklist_confirmations"

    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, index=True)
    item_index = Column(Integer, nullable=False)
    item_text = Column(String, nullable=False)
    confirmed_by = Column(String, nullable=False)
    confirmed_at = Column(DateTime, default=datetime.utcnow)


class ChecklistItem(Base):
    """
    The admin-editable template of checklist items shown on every new run
    (this used to be 4 strings hardcoded in the frontend). No
    reordering support yet — order is insertion order (by id); delete and
    re-add to reorder, a real gap worth closing if this list grows past a
    handful of items. bootstrap.py seeds the original 4 items on first
    startup so an upgrade doesn't silently start every run with an empty,
    always-already-satisfied checklist.
    """
    __tablename__ = "checklist_items"

    id = Column(Integer, primary_key=True)
    text = Column(String, nullable=False)
    created_by = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]  # index == Schedule.day_of_week


class Schedule(Base):
    """
    Recurring patch runs — "patch Tuesday, automatically."
    Weekly only for now (day_of_week + hour, UTC) — a specific "Nth
    weekday of the month" rule (real Patch Tuesday) is a real gap, not
    implemented yet. See app/scheduler.py for how this actually fires.

    No human is present to click checklist boxes when this fires, so a
    scheduled run auto-confirms the current ChecklistItem template with
    confirmed_by='system (scheduled)' — visibly not a human confirmation,
    on purpose, never disguised as one. Ticket gating is NOT bypassed:
    if require_ticket is on, ticket_id must point at a ticket that's
    still Approved at fire time, checked fresh every time (not just when
    the schedule was created) — see scheduler.py.
    """
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    team = Column(String, default="")  # '' = every host regardless of team
    day_of_week = Column(Integer, nullable=False)  # 0=Monday .. 6=Sunday
    hour = Column(Integer, nullable=False)         # 0-23, UTC
    enabled = Column(Boolean, default=True)
    ticket_id = Column(String, nullable=True)
    # Same meaning as on Job, applied to every run this schedule starts.
    scope = Column(String, default=SCOPE_OS)
    container_selection = Column(Text, default="")
    severity_filter = Column(String, default="")
    created_by = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_fired_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.utcnow, index=True)
    actor = Column(String, nullable=False)
    role = Column(String, default="")
    action = Column(String, nullable=False)
    detail = Column(String, default="")
    tone = Column(String, default="neutral")  # success / warning / danger / neutral


class OsScript(Base):
    """
    The currently-active script for one (os_family, stage) pair — e.g.
    ('rocky8', 'patch'). Uploading a new one for the same pair REPLACES
    this row (old content moves to OsScriptHistory first) rather than
    creating a second row — deliberately enforced (see the unique
    constraint) so there's never more than one live script per OS per
    stage fighting for control of the same host.
    """
    __tablename__ = "os_scripts"

    id = Column(Integer, primary_key=True)
    os_family = Column(String, nullable=False)
    stage_name = Column(String, nullable=False)
    filename = Column(String, default="script.sh")
    content = Column(Text, nullable=False)
    tested = Column(Boolean, default=False)  # cleared on every upload, set True on first successful run
    uploaded_by = Column(String, default="")
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("os_family", "stage_name", name="uq_os_family_stage"),)


class OsScriptHistory(Base):
    __tablename__ = "os_script_history"

    id = Column(Integer, primary_key=True)
    os_family = Column(String, nullable=False)
    stage_name = Column(String, nullable=False)
    filename = Column(String, default="script.sh")
    content = Column(Text, nullable=False)
    uploaded_by = Column(String, default="")
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    note = Column(String, default="")  # e.g. "replaced" or "deleted"


class User(Base):
    """
    Real accounts, replacing what used to be a client-side-only role
    switcher. The role names (operator/lead/admin) are unchanged — same
    permission tiers as before, just actually enforced server-side now
    instead of only shaping what the browser shows.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)  # PBKDF2-HMAC-SHA256, see security.py; a fixed sentinel for auth_source='ldap' (never matches verify_password, see app/ldap_auth.py)
    role = Column(String, nullable=False, default="operator")  # operator | lead | admin
    display_name = Column(String, default="")
    # 'local' (password_hash is real, kite owns it) | 'ldap'
    # -- just-in-time provisioned on first successful LDAP bind, see
    # app/ldap_auth.py and auth_router.py's login(); every subsequent
    # login re-verifies against the directory, never against a cached
    # local password).
    auth_source = Column(String, nullable=False, default="local")
    # Set when someone else chose this password -- an admin's reset, a new
    # account, the first-run admin. Until the user picks their own, every
    # request but signing out and changing the password is refused (see
    # auth.get_current_user).
    must_change_password = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Session(Base):
    """
    Server-side session, referenced by an HttpOnly cookie — deliberately
    not a JWT the frontend has to manage. Sessions are looked up on every
    request, so revoking one (logout, or an admin force-clearing a
    compromised session later) takes effect immediately, unlike a stateless
    token that's valid until it expires no matter what.
    """
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    token = Column(String, unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User")


# What an API token may do. Read-only is the only scope for now: a token
# lives in a config file on some workstation (an MCP client, a script),
# which is a much weaker home than a browser session, so it can look but
# never act. A future 'run' scope would be a new value here, gated
# separately -- see app/auth.py's _token_user for where scope is enforced.
API_TOKEN_SCOPE_READ = "read"
API_TOKEN_SCOPES = [API_TOKEN_SCOPE_READ]


class ApiToken(Base):
    """
    A long-lived bearer credential for non-browser clients — the local MCP
    server (tools/kite_mcp.py), scripts, CI.

    A token authenticates as its owner, so it never sees more than its
    owner could, and a role change or account deletion applies to it at
    once. On top of that its scope caps it: a 'read' token is refused on
    every non-GET request regardless of the owner's role.

    Only the SHA-256 of the token is stored (same reasoning as agent
    secrets in security.py: full-entropy random, so no stretching needed).
    `prefix` is the first few characters, kept so a list of tokens can be
    told apart without ever showing one again.

    Expiry is mandatory. A token keeps working without consulting LDAP, so
    an account disabled in the directory would otherwise keep a working
    credential here indefinitely.
    """
    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    token_hash = Column(String, unique=True, nullable=False)
    prefix = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scope = Column(String, nullable=False, default=API_TOKEN_SCOPE_READ)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_used_at = Column(DateTime, nullable=True)

    user = relationship("User")


class HostInterface(Base):
    """
    A network interface as the host's own agent last reported it.
    Inventory, replaced wholesale on each good report. The MAC is what
    joins it to a ProxmoxGuestNic, and so to a bridge and VLAN.
    """
    __tablename__ = "host_interfaces"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    mac = Column(String, default="")
    kind = Column(String, default="")        # '' for a plain NIC; 'bridge', 'vlan', 'bond', ...
    is_up = Column(Boolean, default=True)
    addresses = Column(Text, default="")     # newline-separated CIDR forms, e.g. "10.0.20.5/24"
    reported_at = Column(DateTime, default=datetime.utcnow)

    @property
    def address_list(self):
        return [a for a in (self.addresses or "").split("\n") if a]


SOFTWARE_KINDS = ("rpm", "deb", "snap", "flatpak", "app", "kb", "os")


class HostSoftware(Base):
    """
    Everything installed on a host, as its agent last reported it: the
    ground truth vulnerability matching works from (app/vulnerabilities).
    The agent sends the whole list only when it changed (Host.software_hash);
    each full report replaces the host's rows.

    kind: rpm / deb (the OS package manager), snap / flatpak, app (a
    Windows installed program), kb (an installed Windows update), os (the
    OS itself and its build). source_name/source_version are the source
    package a binary package was built from -- what Debian/Ubuntu and
    RHEL-family advisories are written against.
    """
    __tablename__ = "host_software"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    kind = Column(String, nullable=False)
    name = Column(String, nullable=False)
    version = Column(String, default="")
    arch = Column(String, default="")
    source_name = Column(String, default="")
    source_version = Column(String, default="")
    publisher = Column(String, default="")


class VulnFeed(Base):
    """
    One download unit of vulnerability data (app/vulnerabilities.py): an
    OSV ecosystem such as "Rocky Linux", or one release of a big one such
    as "Ubuntu:24.04:LTS". `ecosystems` is what was kept from it (the OS
    releases the fleet runs), `cursor` the newest change already applied.
    """
    __tablename__ = "vuln_feeds"

    name = Column(String, primary_key=True)
    ecosystems = Column(Text, default="")        # newline-separated
    cursor = Column(String, default="")          # OSV modified timestamp
    records = Column(Integer, default=0)
    loaded_at = Column(DateTime, nullable=True)  # last full download
    refreshed_at = Column(DateTime, nullable=True)
    attempted_at = Column(DateTime, nullable=True)
    error = Column(Text, default="")


class VulnRecord(Base):
    """An advisory (RLSA-, USN-, DSA-, ...) or per-CVE record, kept only if it names a fix."""
    __tablename__ = "vuln_records"
    __table_args__ = (UniqueConstraint("feed", "osv_id"),)

    id = Column(Integer, primary_key=True)
    feed = Column(String, nullable=False, index=True)
    osv_id = Column(String, nullable=False)
    cves = Column(Text, default="")              # space-separated CVE ids
    severity = Column(String, default="unknown")  # see SEVERITY_RANK
    score = Column(String, default="")          # highest CVSS v3 base score, "" if none
    summary = Column(Text, default="")
    url = Column(String, default="")
    modified = Column(String, default="")


class VulnPackage(Base):
    """A package version range a VulnRecord affects: introduced <= installed < fixed."""
    __tablename__ = "vuln_packages"
    __table_args__ = (Index("ix_vuln_packages_ecosystem_name", "ecosystem", "name"),)

    id = Column(Integer, primary_key=True)
    record_id = Column(Integer, ForeignKey("vuln_records.id"), nullable=False, index=True)
    ecosystem = Column(String, nullable=False)   # "Rocky Linux:9", "Ubuntu:24.04:LTS", "Red Hat:enterprise_linux:9"
    name = Column(String, nullable=False)
    introduced = Column(String, default="0")
    fixed = Column(String, nullable=False)
    # NVD only: the platforms the CVE is limited to ("windows", "linux", ...); "" = any.
    # NVD rows also carry bounds with operators -- see app/third_party.in_range.
    platforms = Column(String, default="")
    # Windows (app/windows_os) only: the update that brings the fixed build ("KB5034441")
    kb = Column(String, default="")


class HostVuln(Base):
    """
    A CVE an installed package is exposed to, from the last match of the
    host's software against the feeds. One row per (CVE, package).
    """
    __tablename__ = "host_vulns"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    cve = Column(String, nullable=False, index=True)   # or the advisory id when it names no CVE
    advisories = Column(Text, default="")              # space-separated
    severity = Column(String, default="unknown")
    score = Column(String, default="")
    package = Column(String, nullable=False)
    installed = Column(String, default="")
    fixed = Column(String, default="")
    summary = Column(Text, default="")
    url = Column(String, default="")
    source = Column(String, default="distro")   # distro | go (OSV Go advisories) | nvd | msrc (Windows itself)


class HostListeningPort(Base):
    """
    A socket the host listens on, as its agent reports it. Kept across
    reports rather than replaced, so first_seen survives -- that is what
    lets the controller say "port 3306 opened on db-01 today" by itself.
    A port missing from a good report is deleted: it closed.

    Listening is not the same as reachable: a firewall can still block
    it. The console says "listening", never "exposed".
    """
    __tablename__ = "host_listening_ports"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    proto = Column(String, nullable=False)   # 'tcp' | 'udp'
    address = Column(String, nullable=False) # bound address; 0.0.0.0 / :: = every interface
    port = Column(Integer, nullable=False)
    process = Column(String, default="")
    loopback = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class ProxmoxConnection(Base):
    """
    One Proxmox API endpoint kite reads from: a cluster (any node's
    address reaches all of it) or a standalone host. Each has its own
    API token, created on that host. The secret is stored encrypted; when
    blank, the connection uses PROXMOX_TOKEN_SECRET from the environment
    (an install configured through .env keeps the secret out of the DB).
    """
    __tablename__ = "proxmox_connections"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    host = Column(String, nullable=False)
    node = Column(String, default="")             # optional pin, as the old single setting
    token_id = Column(String, nullable=False)
    token_secret_enc = Column(String, default="")
    verify_ssl = Column(Boolean, default=False)
    created_by = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class ProxmoxBridge(Base):
    """
    A Linux bridge on a Proxmox node, refreshed from the node's network
    config by app/network_inventory.py. On a non-VLAN-aware setup each
    VLAN is its own bridge over an `ethX.N` interface; vlan_id is that N,
    or None for a bridge on an untagged port.
    """
    __tablename__ = "proxmox_bridges"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, nullable=True)  # None = the only (legacy) connection
    node = Column(String, nullable=False)
    name = Column(String, nullable=False)
    vlan_id = Column(Integer, nullable=True)
    vlan_aware = Column(Boolean, default=False)
    ports = Column(String, default="")       # bridge_ports as Proxmox reports them
    cidr = Column(String, default="")        # the node's own address on this bridge, if any
    comments = Column(String, default="")
    refreshed_at = Column(DateTime, default=datetime.utcnow)


class ProxmoxGuestNic(Base):
    """
    One NIC of a Proxmox guest (netN in its config): which bridge it's
    plugged into, its MAC, and its VLAN tag if the bridge is VLAN-aware.
    Known for every guest, enrolled or not -- the agent is not needed to
    say which network a VM sits on.
    """
    __tablename__ = "proxmox_guest_nics"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, nullable=True)  # None = the only (legacy) connection
    vmid = Column(Integer, nullable=False)
    node = Column(String, default="")
    guest_type = Column(String, default="qemu")   # 'qemu' | 'lxc'
    iface = Column(String, default="")            # 'net0'
    mac = Column(String, default="")
    bridge = Column(String, default="")
    vlan_tag = Column(Integer, nullable=True)
    firewall = Column(Boolean, default=False)     # Proxmox's own per-NIC firewall flag
    config_ip = Column(String, default="")        # LXC static ip= from the config; blank for DHCP/QEMU
    refreshed_at = Column(DateTime, default=datetime.utcnow)


class ProxmoxIgnoredGuest(Base):
    """
    A Proxmox guest deliberately left out of kite -- a firewall
    appliance, a Windows desktop, a scratch VM. Without this, the coverage
    view's "no agent" list fills with things nobody intends to enroll,
    and a list that is always non-empty stops being read. Recorded with a
    reason and who decided it, so "ignored" is a visible decision rather
    than a silent gap. Keyed by vmid, which Proxmox keeps unique across a
    cluster.
    """
    __tablename__ = "proxmox_ignored_guests"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, nullable=True)  # vmids repeat across connections
    vmid = Column(Integer, nullable=False)
    reason = Column(String, default="")
    created_by = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("connection_id", "vmid", name="uq_ignored_conn_vmid"),)


class ProxmoxGuestFlag(Base):
    """
    A person's decision about one Proxmox guest's place in the topology:
    gateway=True promotes it to the gateway (router/firewall) above the
    zones it routes; gateway=False dismisses the "looks like a gateway"
    suggestion. No row = automatic. A `kite-gateway` tag on the VM in
    Proxmox always means gateway, whatever is stored here -- the tag is
    the portable way, this is the one-click way.
    """
    __tablename__ = "proxmox_guest_flags"

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, nullable=True)  # vmids repeat across connections
    vmid = Column(Integer, nullable=False)
    gateway = Column(Boolean, nullable=False)
    set_by = Column(String, default="")
    set_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("connection_id", "vmid", name="uq_guest_flag_conn_vmid"),)


class Container(Base):
    """
    One container observed on a host, as last reported by its agent.

    Inventory, not history: an agent reports its full current set on each
    idle poll and the controller replaces that host's rows wholesale, so
    a container that has been removed disappears rather than lingering as
    a phantom. There is deliberately no per-container audit trail —
    containers come and go far too often for that to be signal.

    kite only observes these. Updating a container means recreating
    it, which is safe only when something records how it was created
    (a compose file), and is the orchestrator's job entirely when one is
    involved — hence managed_by, which decides what may ever be offered.
    """
    __tablename__ = "containers"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    container_id = Column(String, default="")   # short runtime id, for operator cross-reference
    name = Column(String, nullable=False)
    image = Column(String, nullable=False)      # the reference as written, tag or digest
    image_digest = Column(String, default="")   # repo digest the local image was pulled at
    state = Column(String, default="")          # running / exited / created / ...
    # 'compose' | 'standalone' | 'kubernetes' | 'swarm' | 'nomad'
    managed_by = Column(String, default="standalone")
    compose_project = Column(String, default="")
    # Recorded by compose itself. The working directory is what makes a
    # compose update precise rather than reconstructed: it is where the
    # project's own file lives, so `compose pull && up -d` run there
    # reproduces exactly the deployment that is already present.
    compose_service = Column(String, default="")
    compose_working_dir = Column(String, default="")
    # Whether a pre-update capture of this service's image exists on the
    # host, and when the run that took it finished. Self-reported by the
    # agent on each inventory pass, so a capture removed out of band
    # (`docker image prune`, a manual rmi) stops being offered.
    rollback_available = Column(Boolean, default=False)
    rollback_captured_at = Column(DateTime, nullable=True)

    @property
    def updatable(self) -> bool:
        """
        Whether kite could update this container at all. Compose
        records where the project lives, which is what makes recreation
        reproduce the existing deployment rather than guess at it;
        without that there is no safe action.
        """
        return bool(self.managed_by == "compose" and self.compose_working_dir and self.compose_service)
    # True when the image is digest-pinned, which means it cannot drift
    # and must never be offered as updatable.
    pinned = Column(Boolean, default=False)
    # True/False once a registry comparison has been made; NULL means not
    # determined -- an unreachable or private registry, or a locally built
    # image. NULL must never be read as "up to date".
    update_available = Column(Boolean, nullable=True)
    reported_at = Column(DateTime, default=datetime.utcnow)

    host = relationship("Host")


class PendingUpdate(Base):
    """
    One package with an update available on a host, as the host's own
    package manager reports it.

    Severity comes from repository errata metadata, so it is only as good
    as what the distribution publishes:

      - dnf carries real advisory severities (critical/important/
        moderate/low) and an advisory id.
      - apt publishes no per-advisory severity. A security update is
        identifiable by its origin suite and is recorded as 'unknown'
        severity, which is not the same as 'low' and must not be
        displayed as though it were.

    Inventory, not history: replaced wholesale on each report, so a
    package that has since been patched stops being listed.
    """
    __tablename__ = "pending_updates"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False, index=True)
    package = Column(String, nullable=False)
    new_version = Column(String, default="")
    advisory = Column(String, default="")       # advisory id (dnf) or origin suite (apt)
    severity = Column(String, default="none")   # see SEVERITY_RANK
    is_security = Column(Boolean, default=False)
    # Where this finding came from: 'os' (dnf/apt/Windows Update), or a
    # third-party manager -- 'winget', 'flatpak', 'snap'. An OS package
    # manager only sees what it installed; third-party apps like Chrome
    # or Notepad++ are reported by their own manager and labelled here so
    # the two never get conflated. Defaults to 'os' so every pre-existing
    # row, and any agent too old to send a source, keeps its old meaning.
    source = Column(String, default="os")
    # The version installed now, where the source can report it. The OS
    # package managers report only the target version (new_version), so
    # this is blank for them; winget/flatpak/snap report both, which is
    # what lets the console show "116.0 -> 117.0" rather than just a
    # target nobody can compare against.
    current_version = Column(String, default="")
    reported_at = Column(DateTime, default=datetime.utcnow)

    host = relationship("Host")


# Highest first, which is the order an operator works the list in.
SEVERITY_RANK = ["critical", "important", "moderate", "low", "unknown", "none"]

# What a run is allowed to install. 'all' and 'security' map straight onto
# dnf's own flags; anything else is a severity list.
SEVERITY_ALL = "all"
SEVERITY_SECURITY = "security"


class Setting(Base):
    """Small generic key/value store for admin-toggleable behavior (e.g. require_ticket)."""
    __tablename__ = "settings"

    key = Column(String, primary_key=True)
    value = Column(String, default="")
