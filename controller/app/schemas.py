import re
from datetime import datetime
from typing import Annotated, Optional, List

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator


# ---------- Identity-field validation ----------
# hostname / team / os_family / role are set by an enrolling agent — which
# means an untrusted (or compromised) host controls them — and are later
# rendered in the operator console. The console escapes them, but these
# values have no legitimate need for quotes, angle brackets or control
# characters, so we also reject those at the source: defense in depth
# against a rendering context that forgets to escape (e.g. a value used
# inside an inline event handler), and cheap input hygiene besides.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")   # hostname, os_family: a bare key
_LABEL_RE = re.compile(r"^[A-Za-z0-9 ._-]*$")                  # team, role: may be blank, may have spaces


def _v_identifier(v: Optional[str]) -> Optional[str]:
    if v is None or v == "":
        return v
    v = v.strip()
    if len(v) > 253 or not _IDENTIFIER_RE.match(v):
        raise ValueError("must contain only letters, digits, dot, hyphen and underscore")
    return v


def _v_label(v: Optional[str]) -> Optional[str]:
    if v is None:
        return v
    v = v.strip()
    if len(v) > 64 or not _LABEL_RE.match(v):
        raise ValueError("must contain only letters, digits, spaces, dot, hyphen and underscore")
    return v


def _v_hostname(v: str) -> str:
    v = (v or "").strip()
    if not v or len(v) > 253 or not _IDENTIFIER_RE.match(v):
        raise ValueError("hostname must be 1-253 chars of letters, digits, dot, hyphen, underscore")
    return v


# An update rule's package pattern: a package name with dnf-style
# wildcards on Linux, a KB number or update-title pattern on Windows
# (titles have spaces and brackets). It reaches dnf/apt/Windows Update as
# one argument, never through a shell -- refused are what would still go
# wrong there: a leading '-' (an option to dnf and apt-mark), quotes,
# shell and control characters, and a pattern that is only wildcards,
# which would hold back every update on every machine it applies to.
_PKG_PATTERN_RE = re.compile(r"^[A-Za-z0-9._+*?:~()\[\] /-]+$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9._+*:~-]*$")


def _v_pkg_pattern(v: str) -> str:
    v = (v or "").strip()
    if not v or len(v) > 200 or not _PKG_PATTERN_RE.match(v):
        raise ValueError("must be a package name or pattern: letters, digits and . _ + - : ~ * ? ( ) [ ] / "
                         "or spaces, up to 200 characters")
    if v.startswith("-"):
        raise ValueError("can't start with '-' (dnf and apt would read it as an option)")
    if not any(c.isalnum() for c in v):
        raise ValueError("is only wildcards: it would hold back every update; name the package")
    return v


def _v_version(v: str) -> str:
    v = (v or "").strip()
    if len(v) > 120 or not _VERSION_RE.match(v) or v.startswith("-"):
        raise ValueError("must be a version: letters, digits and . _ + - : ~ *, up to 120 characters")
    return v


PkgPattern = Annotated[str, AfterValidator(_v_pkg_pattern)]
PkgVersion = Annotated[str, AfterValidator(_v_version)]
Hostname = Annotated[str, AfterValidator(_v_hostname)]     # required, non-empty
Identifier = Annotated[str, AfterValidator(_v_identifier)]  # optional key, may be blank
Label = Annotated[str, AfterValidator(_v_label)]


# ---------- Enrollment ----------
class EnrollTokenCreate(BaseModel):
    hostname: Hostname
    team: Label = ""
    role: Label = ""


class EnrollTokenOut(BaseModel):
    token: str
    hostname: str
    expires_at: Optional[datetime]


class AgentEnrollRequest(BaseModel):
    token: str
    os_version: str
    os_family: Optional[Identifier] = ""  # e.g. "rocky8" — normalized key matching an OS-scripts folder
    smbios_uuid: Optional[str] = ""  # from /sys/class/dmi/id/product_uuid — used to auto-resolve proxmox_vmid
    poll_interval_seconds: Optional[int] = None
    proxmox_vmid: Optional[int] = None


class AgentEnrollResponse(BaseModel):
    host_id: int
    agent_secret: str  # shown once — agent must store this locally


class AgentSelfEnrollRequest(BaseModel):
    secret: str  # shared enrollment secret — see KITE_ENROLL_SECRET
    hostname: Hostname
    team: Label = ""
    role: Label = ""
    os_version: str
    os_family: Optional[Identifier] = ""
    smbios_uuid: Optional[str] = ""
    poll_interval_seconds: Optional[int] = None
    proxmox_vmid: Optional[int] = None


# ---------- Hosts ----------
class HostOut(BaseModel):
    id: int
    hostname: str
    role: str
    team: str
    os_version: str
    os_family: str
    smbios_uuid: str
    poll_interval_seconds: int
    proxmox_vmid: Optional[int]
    proxmox_connection_id: Optional[int] = None
    proxmox_node: Optional[str] = None
    rollback_backend: Optional[str] = None
    agent_version: Optional[str] = ""
    agent_update_to: Optional[str] = None
    group_ids: List[int] = []
    # Attached by routers/hosts.py: snapshot | package_history | none (app/rollback.safety_net)
    safety_net: str = "none"
    container_runtime: Optional[str] = ""
    updates_assessed_ok: Optional[bool] = None
    # Why the assessment failed, as the agent reported it. The controller
    # has stored this since risk assessment landed but never returned it,
    # so the console could say a host's pending count was unknown without
    # ever saying why — sending someone to read a host's log for a reason
    # already sitting in the database.
    updates_error: Optional[str] = ""
    # Attached by the fleet/host queries, not columns — see
    # routers/hosts.py's _attach_update_counts.
    pending_updates: int = 0
    max_severity: str = "none"
    last_seen: Optional[datetime]
    last_patched: Optional[datetime]
    status: str
    active_job_id: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


# ---------- Tickets ----------
class TicketCreate(BaseModel):
    ticket_id: str
    status: str = "Pending approval"
    description: str = ""
    window_start: int = 0
    window_end: int = 23
    requester: str = ""


class TicketOut(BaseModel):
    ticket_id: str
    status: str
    description: str
    window_start: int
    window_end: int
    requester: str

    model_config = ConfigDict(from_attributes=True)


# ---------- Patch definitions ----------
class DefTarget(BaseModel):
    kind: str    # os | group | host -- see models.TARGET_KINDS
    value: str   # an os_family, a group id, a host id

    model_config = ConfigDict(from_attributes=True)


class DefCreate(BaseModel):
    pkg_pattern: PkgPattern
    mode: str  # 'skip' | 'pin'
    version: PkgVersion = ""
    reason: str
    # What it applies to; none = every machine. `os_family` is the older
    # way to give one OS family, still accepted.
    targets: List[DefTarget] = []
    os_family: str = ""


class DefTargetsSet(BaseModel):
    targets: List[DefTarget] = []


class DefOut(BaseModel):
    id: int
    pkg_pattern: str
    mode: str
    version: str
    reason: str
    reviewed: str
    targets: List[DefTarget] = []

    model_config = ConfigDict(from_attributes=True)


# ---------- Runs / Jobs ----------
class ChecklistItemIn(BaseModel):
    item_index: int
    item_text: str


class RunCreate(BaseModel):
    host_id: int
    ticket_id: Optional[str] = None  # optional — see /settings "require_ticket"
    checklist: List[ChecklistItemIn]
    window_override_reason: Optional[str] = None
    # 'os' (default, and what every run did before scopes existed),
    # 'containers', or 'both'. See models.RUN_SCOPES.
    scope: str = "os"
    # Container names to update. Empty means every updatable container on
    # the host. Ignored when the scope doesn't include containers.
    containers: List[str] = []
    # 'update' or 'rollback'. A rollback puts each selected service back
    # on the image captured before its last update.
    container_action: str = "update"
    # '' / 'all' = everything. 'security' = advisories only. Anything
    # else is a severity list, e.g. 'critical,important'.
    severity_filter: str = ""


class StageOut(BaseModel):
    name: str
    executor: str
    status: str
    output: str

    model_config = ConfigDict(from_attributes=True)


class JobOut(BaseModel):
    id: int
    host_id: int
    scope: Optional[str] = "os"
    container_action: Optional[str] = "update"
    severity_filter: Optional[str] = ""
    # Snapshotted at job creation (see models.py's Job.hostname) so a
    # job's identity stays readable even if its host is later deleted.
    # None for jobs created before this field existed -- nothing to
    # backfill that with reliably, so it's left honestly absent rather
    # than guessed.
    hostname: Optional[str] = None
    ticket_id: str
    operator: str
    status: str
    current_stage_index: int
    rollback_backend: Optional[str] = None
    stages: List[StageOut]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ---------- Agent-facing ----------
class AgentJobStageInstruction(BaseModel):
    job_id: int
    stage_name: str
    excludes: List[dict]   # resolved patch_defs for the agent to apply
    hostname: str
    custom_script: Optional[str] = None  # if set, agent runs this instead of its built-in handler
    # Both only populated for the 'containers' stage: the compose
    # services this run selected, with the project details needed to act
    # on them, and whether to update them or restore their captures.
    containers: List[dict] = []
    container_action: str = "update"
    # Narrows the patch stage: '' = everything, 'security' = advisories
    # only, otherwise a severity list.
    severity_filter: str = ""
    # Patch stage only: install what can be installed and list the rest
    # (Settings -> Policy, "patch_skip_uninstallable").
    skip_uninstallable: bool = False


class AgentStageReport(BaseModel):
    status: str  # 'done' | 'failed'
    output: str = ""


class AgentContainer(BaseModel):
    """One container as an agent observed it. Every field is
    agent-reported and therefore untrusted display data — nothing here
    is used for an authorization decision."""
    container_id: str = ""
    name: str
    image: str
    image_digest: str = ""
    state: str = ""
    managed_by: str = "standalone"
    compose_project: str = ""
    compose_service: str = ""
    # Where compose recorded the project. Without it there is no safe
    # update, so a container missing this is reported but never actioned.
    compose_working_dir: str = ""
    # Whether the host still holds a pre-update capture of this image.
    rollback_available: bool = False
    pinned: bool = False
    # None = not determined (private registry, no network, locally built
    # image). Deliberately tri-state: it must not collapse into "false".
    update_available: Optional[bool] = None


class AgentPendingUpdate(BaseModel):
    package: str
    new_version: str = ""
    advisory: str = ""
    severity: str = "none"
    is_security: bool = False
    # Which manager reported this. 'os' (the default, and what every
    # agent before third-party support sent) or 'winget' / 'flatpak' /
    # 'snap'. See models.PendingUpdate.source.
    source: str = "os"
    # Installed version, where the source knows it. Blank for the OS
    # package managers, which report only the target.
    current_version: str = ""


class AgentUpdateSource(BaseModel):
    """
    One assessed source's result. The agent attempts each manager the
    host actually has and says, per manager, whether the query succeeded.

    This is what keeps 'we could not tell' honest once there is more than
    one source: winget failing must not blank the OS updates, and a
    working OS query must not imply winget was checked. The controller
    replaces a source's rows only when that source reported ok, and
    leaves the last known list in place for one that did not.
    """
    name: str
    ok: bool
    error: str = ""


# ---------- Agent-reported network facts ----------
# All of this is controlled by the host, so every field is shape-checked
# here: an interface name or process name lands in the console, and an
# address is parsed by ipaddress later -- junk is dropped, not stored.
_IFNAME_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_PROCESS_RE = re.compile(r"^[A-Za-z0-9_.:/+@ -]{0,64}$")


def _valid_cidr(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_interface(value)
        return "/" in value
    except ValueError:
        return False


def _valid_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class AgentInterface(BaseModel):
    name: str
    mac: str = ""
    kind: str = ""
    up: bool = True
    addresses: List[str] = []

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        if not _IFNAME_RE.match(v or ""):
            raise ValueError("bad interface name")
        return v

    @field_validator("mac")
    @classmethod
    def _mac(cls, v):
        v = (v or "").lower()
        return v if _MAC_RE.match(v) else ""

    @field_validator("kind")
    @classmethod
    def _kind(cls, v):
        return v if re.match(r"^[a-z0-9_-]{0,24}$", v or "") else ""

    @field_validator("addresses")
    @classmethod
    def _addresses(cls, v):
        return [a for a in (v or [])[:32] if isinstance(a, str) and _valid_cidr(a)]


class AgentListening(BaseModel):
    proto: str
    address: str
    port: int
    process: str = ""
    loopback: bool = False

    @field_validator("proto")
    @classmethod
    def _proto(cls, v):
        if v not in ("tcp", "udp"):
            raise ValueError("proto must be tcp or udp")
        return v

    @field_validator("address")
    @classmethod
    def _address(cls, v):
        if not _valid_ip(v):
            raise ValueError("bad address")
        return v

    @field_validator("port")
    @classmethod
    def _port(cls, v):
        if not 0 < v < 65536:
            raise ValueError("bad port")
        return v

    @field_validator("process")
    @classmethod
    def _process(cls, v):
        return v if _PROCESS_RE.match(v or "") else ""


def _keep_valid(model, value, limit):
    """
    Validate a list item by item, dropping the ones that fail. A null
    counts as empty, as elsewhere in the agent schemas. One odd interface
    or socket must not get the whole inventory report -- which also
    carries the pending updates -- rejected.
    """
    from pydantic import ValidationError
    out = []
    for item in (value or [])[:limit]:
        try:
            out.append(model.model_validate(item))
        except ValidationError:
            continue
    return out


class AgentNetwork(BaseModel):
    ok: bool = True
    error: str = ""
    interfaces: List[AgentInterface] = []
    default_gateway: str = ""
    listening: List[AgentListening] = []

    @field_validator("interfaces", mode="before")
    @classmethod
    def _interfaces(cls, value):
        return _keep_valid(AgentInterface, value, 128)

    @field_validator("listening", mode="before")
    @classmethod
    def _listening(cls, value):
        return _keep_valid(AgentListening, value, 1000)

    @field_validator("default_gateway")
    @classmethod
    def _gw(cls, v):
        return v if v and _valid_ip(v) else ""

    @field_validator("error")
    @classmethod
    def _error(cls, v):
        return (v or "")[:500]


class AgentSoftwareItem(BaseModel):
    kind: str
    name: Annotated[str, Field(min_length=1, max_length=200)]
    version: Annotated[str, Field(max_length=120)] = ""
    arch: Annotated[str, Field(max_length=32)] = ""
    source_name: Annotated[str, Field(max_length=200)] = ""
    source_version: Annotated[str, Field(max_length=120)] = ""
    publisher: Annotated[str, Field(max_length=200)] = ""

    @field_validator("kind")
    @classmethod
    def _kind(cls, v):
        from .models import SOFTWARE_KINDS
        if v not in SOFTWARE_KINDS:
            raise ValueError(f"kind must be one of {SOFTWARE_KINDS}")
        return v


class AgentSoftware(BaseModel):
    """
    Installed software. `items` is the full list, sent only when it changed;
    otherwise just `hash`, and the controller asks for the list again
    (software_resend in the reply) if the hash isn't the one it stored.
    """
    hash: Annotated[str, Field(pattern=r"^[0-9a-f]{16,64}$")]
    items: Optional[List[AgentSoftwareItem]] = None

    @field_validator("items", mode="before")
    @classmethod
    def _items(cls, value):
        return None if value is None else _keep_valid(AgentSoftwareItem, value, 30000)


class AgentInventory(BaseModel):
    runtime: str = ""                      # 'docker' | 'podman' | 'nerdctl' | '' if none installed
    containers: List[AgentContainer] = []
    updates: List[AgentPendingUpdate] = []
    # Whether the assessment ran at all. False with an empty list means
    # "could not tell", which is not "nothing pending" -- see
    # models.PendingUpdate.
    updates_ok: Optional[bool] = None
    updates_error: str = ""
    # Per-source assessment results. Empty from agents that predate
    # third-party support -- the controller then treats the report as a
    # single 'os' source gated by updates_ok, exactly as before.
    update_sources: List[AgentUpdateSource] = []
    # None = this agent doesn't report network facts at
    # all, which leaves whatever the host last reported untouched.
    network: Optional[AgentNetwork] = None
    # None = not reported; the last stored list stays.
    software: Optional[AgentSoftware] = None
    # The machine's SMBIOS UUID. Recorded only for a host
    # with none on record (enrolled before its agent sent one), binding it
    # to this hardware from then on (routers/enroll.py).
    smbios_uuid: Annotated[str, Field(max_length=64)] = ""

    @field_validator("containers", "updates", "update_sources", mode="before")
    @classmethod
    def _empty_for_null(cls, value):
        """
        Accept a JSON null for either list.

        Sending null for an empty list is ordinary client behaviour --
        Go marshals a nil slice that way, and so do several other
        languages. Rejecting the whole report over it would be worse
        than pedantic here: the report that carries an empty list is
        usually the one carrying updates_ok=false, so strictness would
        discard exactly the "I could not tell" signal the controller
        most needs to hear.
        """
        return [] if value is None else value


class PendingUpdateOut(BaseModel):
    package: str
    new_version: str
    advisory: str
    severity: str
    is_security: bool
    source: str = "os"
    current_version: str = ""

    model_config = ConfigDict(from_attributes=True)


class ContainerOut(BaseModel):
    id: int
    name: str
    image: str
    state: str
    managed_by: str
    compose_project: str
    compose_service: str = ""
    # Whether kite could actually update this container. Only
    # compose-managed ones qualify — see app/routers/agent.py's
    # _selected_containers for why.
    updatable: bool = False
    rollback_available: bool = False
    rollback_captured_at: Optional[datetime] = None
    pinned: bool
    update_available: Optional[bool] = None
    reported_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AgentHeartbeat(BaseModel):
    status: str = "healthy"


# ---------- OS scripts ----------
class OsScriptOut(BaseModel):
    os_family: str
    stage_name: str
    filename: str
    tested: bool
    uploaded_by: str
    uploaded_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OsScriptHistoryOut(BaseModel):
    filename: str
    uploaded_by: str
    uploaded_at: datetime
    note: str

    model_config = ConfigDict(from_attributes=True)


# ---------- Audit ----------
class AuditOut(BaseModel):
    ts: datetime
    actor: str
    role: str
    action: str
    detail: str
    tone: str

    model_config = ConfigDict(from_attributes=True)


# ---------- Auth ----------
class LoginRequest(BaseModel):
    username: str
    password: str


class MeOut(BaseModel):
    username: str
    role: str
    display_name: str
    must_change_password: bool = False   # the console shows only "choose your password" until it's done


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UserCreate(BaseModel):
    username: str
    password: str
    role: str  # operator | lead | admin
    display_name: str = ""
    # The admin chose this password, so by default the user replaces it at
    # first sign-in. Off for accounts whose password is handed over by
    # other means (a vault, a service account).
    must_change_password: bool = True


class PasswordResetIn(BaseModel):
    # Typed by the admin, or blank to have one generated. Either way it
    # only gets the user signed in once: they choose their own next.
    temporary_password: str = ""


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    display_name: str
    auth_source: str = "local"  # 'local' | 'ldap' — see app/ldap_auth.py
    must_change_password: bool = False

    model_config = ConfigDict(from_attributes=True)


class UserPatch(BaseModel):
    role: Optional[str] = None
    display_name: Optional[str] = None


class PasswordResetOut(BaseModel):
    username: str
    new_password: str  # the temporary password, shown exactly once; the user must replace it at sign-in
    must_change_password: bool = True


# ---------- Checklist template ----------
class ChecklistItemCreate(BaseModel):
    text: str


class ChecklistItemOut(BaseModel):
    id: int
    text: str
    created_by: str

    model_config = ConfigDict(from_attributes=True)


# ---------- Schedules ----------
class ScheduleCreate(BaseModel):
    name: str
    team: str = ""
    day_of_week: int  # 0=Monday .. 6=Sunday
    hour: int          # 0-23, UTC
    ticket_id: Optional[str] = None
    scope: str = "os"
    containers: List[str] = []
    severity_filter: str = ""


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    team: Optional[str] = None
    day_of_week: Optional[int] = None
    hour: Optional[int] = None
    ticket_id: Optional[str] = None
    enabled: Optional[bool] = None
    scope: Optional[str] = None
    containers: Optional[List[str]] = None
    severity_filter: Optional[str] = None


class ScheduleOut(BaseModel):
    id: int
    name: str
    team: str
    scope: Optional[str] = "os"
    severity_filter: Optional[str] = ""
    day_of_week: int
    hour: int
    enabled: bool
    ticket_id: Optional[str] = None
    created_by: str
    last_fired_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ---------- Settings ----------
class SettingOut(BaseModel):
    key: str
    value: str


class SettingUpdate(BaseModel):
    value: str


# ---------- API tokens ----------
# Longest a token may live. Expiry is mandatory (see models.ApiToken), and
# a year is the outer bound of "rotate it when you renew the cert".
API_TOKEN_MAX_DAYS = 365


def _v_token_name(v: str) -> str:
    v = (v or "").strip()
    if not v or len(v) > 64 or not _LABEL_RE.match(v):
        raise ValueError("name must be 1-64 chars of letters, digits, spaces, dot, hyphen and underscore")
    return v


class ApiTokenCreate(BaseModel):
    name: Annotated[str, AfterValidator(_v_token_name)]
    expires_in_days: int = 90
    scope: str = "read"

    @field_validator("expires_in_days")
    @classmethod
    def _days_in_range(cls, v: int) -> int:
        if not 1 <= v <= API_TOKEN_MAX_DAYS:
            raise ValueError(f"expires_in_days must be between 1 and {API_TOKEN_MAX_DAYS}")
        return v


class ApiTokenOut(BaseModel):
    id: int
    name: str
    prefix: str
    scope: str
    username: str
    created_at: Optional[datetime]
    expires_at: datetime
    last_used_at: Optional[datetime]
    expired: bool


class ApiTokenCreated(ApiTokenOut):
    # The full token. Returned by the create call only, never again.
    token: str


# ---------- Proxmox connections ----------
_PVE_HOST_RE = re.compile(r"^[A-Za-z0-9.:\[\]-]{1,253}$")
_PVE_TOKEN_ID_RE = re.compile(r"^[^@\s!]+@[^@\s!]+![^@\s!]+$")


def _v_pve_host(v: str) -> str:
    v = (v or "").strip()
    if not _PVE_HOST_RE.match(v):
        raise ValueError("address must be a hostname or IP, without https:// or a port")
    return v


def _v_pve_token_id(v: str) -> str:
    v = (v or "").strip()
    if not _PVE_TOKEN_ID_RE.match(v):
        raise ValueError("token ID must look like user@realm!tokenname")
    return v


class ProxmoxConnectionIn(BaseModel):
    name: Annotated[str, AfterValidator(_v_token_name)]
    host: Annotated[str, AfterValidator(_v_pve_host)]
    token_id: Annotated[str, AfterValidator(_v_pve_token_id)]
    token_secret: str = ""          # required on create; blank on update keeps the saved one
    node: Identifier = ""
    verify_ssl: bool = False


class ProxmoxConnectionPatch(BaseModel):
    name: Optional[Annotated[str, AfterValidator(_v_token_name)]] = None
    host: Optional[Annotated[str, AfterValidator(_v_pve_host)]] = None
    token_id: Optional[Annotated[str, AfterValidator(_v_pve_token_id)]] = None
    token_secret: Optional[str] = None
    node: Optional[Identifier] = None
    verify_ssl: Optional[bool] = None


class ProxmoxConnectionOut(BaseModel):
    id: int
    name: str
    host: str
    node: str
    token_id: str
    verify_ssl: bool
    secret_set: bool
    secret_from_env: bool
    guests: int          # VMs/containers seen on it (as of the last network discovery pass)
    linked_hosts: int    # enrolled machines linked to a VM on it
    created_by: str
    created_at: Optional[datetime]


class ProxmoxTest(BaseModel):
    """Unsaved form values to try. Any field left out (or blank) falls
    back to the saved connection named by connection_id, so "test what I
    just typed" works without re-entering the write-only secret."""
    connection_id: Optional[int] = None
    host: Optional[str] = None
    token_id: Optional[str] = None
    token_secret: Optional[str] = None
    verify_ssl: Optional[bool] = None


# ---------- Proxmox coverage ----------
_REASON_FORBIDDEN_RE = re.compile(r"[<>\x00-\x1f\x7f]")


def _v_reason(v: str) -> str:
    # Free prose ("Appliance, vendor-updated"), so wider than Label -- but
    # still no markup or control characters, same hygiene as other
    # operator-entered text that lands in the console and the audit log.
    v = (v or "").strip()
    if not v or len(v) > 200 or _REASON_FORBIDDEN_RE.search(v):
        raise ValueError("reason is required: 1-200 characters, no angle brackets or control characters")
    return v


class IgnoreGuestCreate(BaseModel):
    vmid: int
    connection_id: Optional[int] = None   # which connection the vmid is on; None = the only one
    reason: Annotated[str, AfterValidator(_v_reason)]


class GatewayFlagSet(BaseModel):
    vmid: int
    connection_id: Optional[int] = None
    gateway: bool   # True = draw it as a gateway; False = it isn't one, stop suggesting it
