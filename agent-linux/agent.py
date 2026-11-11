"""
kite agent — runs on each Linux host as a root systemd service.
Supports both RHEL-family (dnf) and Debian-family (apt) hosts from this
one codebase — see detect_package_manager() and the per-stage dnf/apt
handler pairs below. Same poll/execute/report contract, same OS-scripts
override mechanism, regardless of which package manager is underneath.

Runs as root deliberately: dnf/apt, package holds, and reboot all require
it, and this is now a per-host, scoped credential rather than one shared
central SSH key with root over the whole fleet. Compromising this agent
gets you this host — which kite already grants root patching rights
on — not the rest of the fleet.

Loop: poll the controller for a pending stage on this host, execute it,
report back. The controller drives the pipeline forward; this agent has
no opinion about what stage comes next, only how to execute the one
it's handed.

Reboot handling is the one genuinely tricky part: the agent triggering
a reboot is a process about to disappear mid-job. Before rebooting, it
writes STATE_PATH with the job id. On the next start (systemd restarts
it after boot), resume_pending_reboot() sees that file, reports the
'reboot' stage done, and deletes it. This is the only stage that can't
just synchronously return a result.
"""
import argparse
import hashlib
import io
import json
import logging
import os
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone

import requests

# Bump alongside packaging/kite-agent.spec's %{version} on every
# release — this is the single source of truth the controller compares
# against Settings -> agent_target_version to decide whether this agent
# should self-update. Sent on every poll; never trusted by
# the controller for anything security-sensitive, purely informational
# plus this one opt-in comparison.
AGENT_VERSION = "1.0.0"

CONFIG_PATH = os.environ.get("KITE_AGENT_CONFIG", "/etc/kite/agent.conf")
STATE_PATH = os.environ.get("KITE_AGENT_STATE", "/var/lib/kite/pending_reboot.json")
TRIGGER_PATH = os.environ.get("KITE_AGENT_TRIGGER", "/var/lib/kite/trigger")
# The package holds kite itself put in place (versionlock pins, apt
# holds), so they can be released when the rule asking for them goes.
HOLDS_PATH = os.environ.get("KITE_AGENT_HOLDS", "/var/lib/kite/holds.json")
# The agent's own dnf repo on the controller, and the key it is signed with
# (see ensure_signed_repo).
REPO_FILE = os.environ.get("KITE_REPO_FILE", "/etc/yum.repos.d/kite.repo")
REPO_KEY_PATH = os.environ.get("KITE_REPO_KEY", "/etc/pki/rpm-gpg/RPM-GPG-KEY-kite")
# The controller's root CA, once pinned (enroll.py --ca-fingerprint, or
# pin_controller_ca below): every call to the controller is checked
# against it, and only it.
CA_PATH = os.environ.get("KITE_CA_CERT_PATH", "/etc/kite/controller-ca.crt")

# A plain, quick poll request — no held-open connection (see agent README
# for why that got dropped). This just needs to comfortably cover a normal
# round trip, not survive a long hold.
POLL_CLIENT_TIMEOUT = 15

# How often (seconds) the sleep-with-trigger-check loop wakes up just to
# check whether TRIGGER_PATH exists, while otherwise sleeping toward the
# next scheduled poll. Small enough that touching the trigger file feels
# instant, large enough not to matter for CPU/wakeups.
TRIGGER_CHECK_INTERVAL = 2

log = logging.getLogger("kite-agent")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def detect_package_manager():
    """
    'dnf' or 'apt', checked via which() at runtime rather than parsed out of
    os_family — os_family is a display/OS-scripts-matching key (see
    enroll.py), this is about which binary actually exists on this host, and
    the two shouldn't be coupled: a host with a wrong/missing os_family
    override should still patch correctly as long as its package manager is
    detectable. None means neither is present — every stage that needs a
    package manager fails clearly instead of guessing.
    """
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("apt-get"):
        return "apt"
    return None


# How often to ask a registry whether a mutable tag has moved. Local
# enumeration is cheap and runs on every poll; a registry round trip per
# distinct image is not, so it is throttled independently.
DRIFT_CHECK_INTERVAL = int(os.environ.get("KITE_DRIFT_INTERVAL", "21600"))  # 6h

# Container labels that mean something else already owns this container's
# lifecycle. kite reports these and never acts on them: an orchestrator
# will either revert an out-of-band change or have it bypass the rollout
# safety the orchestrator exists to provide.
_ORCHESTRATOR_LABELS = {
    "io.kubernetes.pod.name": "kubernetes",
    "com.docker.swarm.service.id": "swarm",
    "com.hashicorp.nomad.alloc_id": "nomad",
}
_COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
_COMPOSE_SERVICE_LABEL = "com.docker.compose.service"
# Compose records where the project lives. This is what makes updating a
# compose container precise rather than reconstructed: running
# `compose pull && up -d` there reproduces the deployment already
# present, instead of guessing at flags from `inspect` output.
_COMPOSE_WORKDIR_LABEL = "com.docker.compose.project.working_dir"
# ...and how it was brought up: `-f` files (comma-separated, absolute) and
# `--env-file`s. A project started with its own -p name or -f files is a
# different project to compose without them.
_COMPOSE_FILES_LABEL = "com.docker.compose.project.config_files"
_COMPOSE_ENV_FILES_LABEL = "com.docker.compose.project.environment_file"


def detect_container_runtime():
    """
    'docker', 'podman', 'nerdctl', or None. Checked by which() at runtime
    for the same reason as detect_package_manager: what matters is which
    binary this host actually has, not what its OS family implies.

    Order is preference, not capability — a host with both docker and
    podman is far more likely to be using docker for the containers that
    matter, since podman ships by default on RHEL-family whether anyone
    uses it or not.
    """
    for binary in ("docker", "podman", "nerdctl"):
        if shutil.which(binary):
            return binary
    return None


def _classify_management(labels):
    """
    Who owns this container's lifecycle. Determines what kite is
    allowed to do with it later, so it is deliberately conservative:
    anything carrying an orchestrator's label is that orchestrator's.
    """
    for label, owner in _ORCHESTRATOR_LABELS.items():
        if label in labels:
            return owner
    if labels.get(_COMPOSE_PROJECT_LABEL):
        return "compose"
    return "standalone"


# Where a pre-update capture is kept. One tag per compose service, so a
# new capture replaces the previous one by construction: re-tagging moves
# the name onto the new image id and the old one becomes untagged, which
# means disk never grows past one retained image per service.
_ROLLBACK_REPO = "kite-rollback"


def rollback_tag(project, service):
    return f"{_ROLLBACK_REPO}/{project or 'none'}_{service}:previous"


def _is_pinned(image_ref):
    """
    A digest-pinned reference (name@sha256:...) is frozen on purpose.
    It can never drift, and should never be offered as updatable.
    """
    return "@sha256:" in (image_ref or "")


# Severity vocabulary, lowest to highest. dnf reports these directly from
# repo errata metadata; apt has no equivalent, so an apt security update
# is 'unknown' rather than being assigned a level nobody published.
SEVERITY_ORDER = ["none", "unknown", "low", "moderate", "important", "critical"]


def _normalise_severity(raw):
    value = (raw or "").strip().lower().rstrip(".")
    if value.endswith("/sec"):
        value = value[:-4]
    return value if value in SEVERITY_ORDER else "none"


def assess_updates(pkg_manager, timeout=180):
    """
    Pending updates on this host, with severity where the package manager
    publishes it.

    Read-only: nothing is installed, and no repository state is changed
    beyond the metadata refresh a query needs anyway.

    The two package managers differ in what they can answer, and the
    difference is reported rather than smoothed over:

      - dnf carries errata metadata, so each update has an advisory id and
        a real severity (Critical/Important/Moderate/Low).
      - apt has no per-CVE severity. What it does have is the origin, so a
        security update is identifiable but its severity is 'unknown'.
        Assigning one would be inventing a number nobody published.

    Returns {"ok": bool, "error": str, "updates": [...]}. The ok flag is
    load-bearing: a query that failed is not a host with nothing pending.
    A single unreachable repository fails the whole dnf query, and
    reporting that as zero would show a host as fully patched when it has
    dozens of outstanding advisories.
    """
    if pkg_manager == "dnf":
        return _assess_dnf(timeout=timeout)
    if pkg_manager == "apt":
        return _assess_apt(timeout=timeout)
    return {"ok": False, "error": f"no supported package manager (got {pkg_manager!r})", "updates": []}


def _assess_dnf(timeout=180):
    """
    Parses `dnf updateinfo list --available`, whose lines look like:

        RLSA-2026:58572 Moderate/Sec.  NetworkManager-1:1.54.3-5.el9.x86_64
        RLBA-2026:39332 bugfix         kernel-tools-5.14.0-687.el9.x86_64

    The middle column is `<Severity>/Sec.` for a security advisory and a
    plain type word otherwise. Advisory ids vary by repo (EPEL's are like
    FEDORA-EPEL-2026-1a2b3c4d), so a line is recognised by its package
    column, not its id.

    Repositories that publish no errata (many vendor and third-party
    ones) have updates updateinfo knows nothing about; `dnf check-update`
    lists every available update, and those missing from the advisories
    are added with no advisory and no severity -- pending, not invisible.
    """
    rc, out = run_cmd(["dnf", "updateinfo", "list", "--available", "-q"], timeout=timeout)
    if rc != 0:
        log.warning("update assessment failed: %s", out[:200])
        return {"ok": False, "error": out.strip()[-500:], "updates": []}

    updates = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or not _NEVRA.match(parts[2]):
            continue
        advisory, kind, nevra = parts[0], parts[1], parts[2]
        is_security = kind.lower().endswith("/sec.") or kind.lower().endswith("/sec")
        updates.append({
            "package": _package_name_from_nevra(nevra),
            "new_version": nevra,
            "advisory": advisory,
            "severity": _normalise_severity(kind.split("/")[0]) if is_security else "none",
            "is_security": is_security,
        })
    known = {u["package"] for u in updates}
    rc, out = run_cmd(["dnf", "check-update", "-q"], timeout=timeout)
    if rc == 100:   # 100: updates available; 0: none; anything else: leave what updateinfo said
        for line in out.splitlines():
            parts = line.split()
            if len(parts) != 3 or "." not in parts[0] or line.startswith(" "):
                continue
            name, _, arch = parts[0].rpartition(".")
            if name in known or not name:
                continue
            known.add(name)
            updates.append({"package": name, "new_version": f"{name}-{parts[1]}.{arch}", "advisory": "",
                            "severity": "none", "is_security": False})
    return {"ok": True, "error": "", "updates": updates}


# name-[epoch:]version-release.arch, as dnf prints a package
_NEVRA = re.compile(r"^\S+-(\d+:)?[^-\s]+-[^-\s]+\.[A-Za-z0-9_]+$")


def _package_name_from_nevra(nevra):
    """`NetworkManager-1:1.54.3-5.el9_8.x86_64` -> `NetworkManager`."""
    stem = nevra.rsplit(".", 1)[0]                 # drop arch
    for _ in range(2):                              # drop release, then version
        if "-" in stem:
            stem = stem.rsplit("-", 1)[0]
    return stem


def _assess_apt(timeout=180):
    """
    Parses `apt list --upgradable`, whose lines look like:

        libpcre2-8-0/oldstable-security 10.42-1+deb12u1 amd64 [upgradable from: 10.42-1]

    The suite after the slash is what identifies a security update on both
    Debian (`*-security`) and Ubuntu (`*-security`). There is no severity
    to read, so security updates are reported as 'unknown' severity.
    """
    rc, out = run_cmd(["apt", "list", "--upgradable"], timeout=timeout)
    if rc != 0:
        log.warning("update assessment failed: %s", out[:200])
        return {"ok": False, "error": out.strip()[-500:], "updates": []}

    updates = []
    for line in out.splitlines():
        if "/" not in line or line.startswith("Listing"):
            continue
        head, _, rest = line.partition(" ")
        package, _, suite = head.partition("/")
        fields = rest.split()
        if not package or not fields:
            continue
        is_security = "-security" in suite.lower()
        updates.append({
            "package": package,
            "new_version": fields[0],
            "advisory": suite,
            "severity": "unknown" if is_security else "none",
            "is_security": is_security,
        })
    return {"ok": True, "error": "", "updates": updates}


def assess_flatpak(timeout=120):
    """
    Flatpak apps with an update available.

    Flatpak is where a lot of desktop software lives that the OS package
    manager never sees. Read-only: `remote-ls --updates` queries the
    remotes, it installs nothing.

    Returns the same {ok, error, updates} shape as the OS assessment,
    with each update carrying the installed version as current_version
    and the available one as new_version. A remote that cannot be reached
    is ok=false -- "we could not check flatpak", not "flatpak has nothing".
    """
    installed = {}
    rc, out = run_cmd(["flatpak", "list", "--app", "--columns=application,version"], timeout=timeout)
    if rc == 0:
        for line in out.splitlines():
            parts = line.split("\t") if "\t" in line else line.split()
            if len(parts) >= 2:
                installed[parts[0]] = parts[1]

    rc, out = run_cmd(["flatpak", "remote-ls", "--updates", "--columns=application,version"], timeout=timeout)
    if rc != 0:
        return {"ok": False, "error": out.strip()[-500:], "updates": []}

    updates = []
    for line in out.splitlines():
        parts = line.split("\t") if "\t" in line else line.split()
        if not parts:
            continue
        app = parts[0]
        available = parts[1] if len(parts) >= 2 else ""
        if not app or app.lower() == "application":
            continue
        updates.append({
            "package": app,
            "new_version": available,
            "current_version": installed.get(app, ""),
            # flatpak has no advisory ids or severities; leaving them
            # neutral is honest rather than inventing one.
            "advisory": "",
            "severity": "none",
            "is_security": False,
        })
    return {"ok": True, "error": "", "updates": updates}


def assess_snap(timeout=120):
    """
    Snap packages with a refresh available.

    `snap refresh --list` is read-only -- it lists what a refresh would
    update without doing it. Its Version column is the AVAILABLE version;
    the installed one comes from `snap list`. Snap names and versions
    contain no spaces, so the table splits cleanly on whitespace.

    Same {ok, error, updates} contract and the same "could not tell is not
    nothing" rule as every other source.
    """
    installed = {}
    rc, out = run_cmd(["snap", "list"], timeout=timeout)
    if rc == 0:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                installed[parts[0]] = parts[1]

    rc, out = run_cmd(["snap", "refresh", "--list"], timeout=timeout)
    if rc != 0:
        return {"ok": False, "error": out.strip()[-500:], "updates": []}

    updates = []
    for line in out.splitlines():
        low = line.strip().lower()
        # "All snaps up to date." is the clean-empty case, and the header
        # row starts with "Name".
        if not line.strip() or low.startswith(("all snaps", "name ")):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name, available = parts[0], parts[1]
        updates.append({
            "package": name,
            "new_version": available,
            "current_version": installed.get(name, ""),
            "advisory": "",
            "severity": "none",
            "is_security": False,
        })
    return {"ok": True, "error": "", "updates": updates}


def assess_all_sources(pkg_manager):
    """
    Every update source this host has, merged, with a per-source status.

    Returns (updates, sources): each update tagged with the source that
    found it, and sources a list of {name, ok, error} so the controller
    can refresh one source without blanking another it could not check.
    The OS package manager is always a source; flatpak and snap are added
    only where their tool exists.
    """
    updates = []
    sources = []

    os_result = assess_updates(pkg_manager)
    for u in os_result["updates"]:
        u["source"] = "os"
        u.setdefault("current_version", "")
    updates.extend(os_result["updates"])
    sources.append({"name": "os", "ok": os_result["ok"], "error": os_result["error"]})

    # Third-party sources beyond the OS package manager, each guarded by
    # whether its tool is actually installed. A host with no flatpak is not
    # a host where flatpak assessment failed -- it is simply not a source
    # there, and a phantom failing source would alarm forever. The list is
    # built here, at call time, so the assessors resolve to the current
    # module functions rather than references frozen at import.
    third_party = [("flatpak", assess_flatpak), ("snap", assess_snap)]
    for name, assess in third_party:
        if not shutil.which(name):
            continue
        result = assess()
        for u in result["updates"]:
            u["source"] = name
            u.setdefault("current_version", "")
        updates.extend(result["updates"])
        sources.append({"name": name, "ok": result["ok"], "error": result["error"]})

    return updates, sources


# dnf's dependency problems, e.g.
#   Problem: cannot install the best update candidate for package log-shipper-1.2.0-1.el8.x86_64
#    - nothing provides libc.so.6(GLIBC_2.34)(64bit) needed by log-shipper-9.0.1-1.x86_64 from vendor
#    - package foo-2.0-1.x86_64 from vendor requires libbar >= 3, but none of the providers can be installed
# and, with --skip-broken, the "Skipping packages with broken dependencies:"
# table. Keyed by the candidate update; values are what it needs.
_DNF_NOTHING_PROVIDES = re.compile(r"nothing provides (.+?) needed by (\S+) from (\S+)")
_DNF_REQUIRES = re.compile(r"package (\S+) from (\S+) requires (.+?), but none of the providers can be installed")
_DNF_SKIP_HEAD = re.compile(r"^Skipping packages with (broken dependencies|conflicts):")


def _split_nevra(nevra):
    """'log-shipper-9.0.1-1.x86_64' -> ('log-shipper', '9.0.1-1'); best effort."""
    base = nevra.rsplit(".", 1)[0] if re.search(r"\.(x86_64|aarch64|noarch|i686|ppc64le|s390x)$", nevra) else nevra
    parts = base.rsplit("-", 2)
    if len(parts) == 3:
        return parts[0], f"{parts[1]}-{parts[2]}"
    return base, ""


def parse_dnf_problems(output):
    """{(name, version, repo): [needs...]} from dnf's problem report, in order seen."""
    found = {}
    for line in (output or "").splitlines():
        m = _DNF_NOTHING_PROVIDES.search(line)
        if m:
            name, ver = _split_nevra(m.group(2))
            found.setdefault((name, ver, m.group(3)), [])
            if m.group(1) not in found[(name, ver, m.group(3))]:
                found[(name, ver, m.group(3))].append(m.group(1))
            continue
        m = _DNF_REQUIRES.search(line)
        if m:
            name, ver = _split_nevra(m.group(1))
            found.setdefault((name, ver, m.group(2)), [])
            if m.group(3) not in found[(name, ver, m.group(2))]:
                found[(name, ver, m.group(2))].append(m.group(3))
    # The skip table: " name  arch  version  repo  size" rows until a blank line.
    in_table = False
    for line in (output or "").splitlines():
        if _DNF_SKIP_HEAD.match(line.strip()):
            in_table = True
            continue
        if in_table:
            cols = line.split()
            if len(cols) < 4 or line.strip().endswith(":"):
                in_table = False
                continue
            name, ver, repo = cols[0], cols[2], cols[3]
            if not any(k[0] == name for k in found):
                found[(name, ver, repo)] = []
    return found


def format_dnf_problems(problems):
    out = []
    for (name, ver, repo), needs in problems.items():
        line = f"{name} {ver} (from {repo})".replace("  ", " ")
        if needs:
            line += f" needs {', '.join(needs)}, which this system doesn't provide"
        out.append(line)
    return out


def _with_summary(head, out, limit=4000):
    summary = "\n".join(head)
    room = max(0, limit - len(summary) - 2)
    return summary + "\n\n" + (out[-room:] if room else "")


def _write_atomically(path, data, mode):
    """Write next to the target and rename over it, so a crash never leaves half a file."""
    tmp = f"{path}.new"
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# apt's own report of what an upgrade left out, e.g.
#   The following packages have been kept back:
#     linux-generic linux-headers-generic
#   The following upgrades have been deferred due to phasing:
#     ubuntu-release-upgrader-core
# Package names follow on indented lines, wrapped, until the next unindented line.
_APT_HELD_HEADS = {
    "The following packages have been kept back:": "kept-back",
    "The following upgrades have been deferred due to phasing:": "phased",
}


def parse_apt_held_back(output):
    """{'kept-back': [...], 'phased': [...]} from apt-get's output, in order seen, no duplicates."""
    found = {"kept-back": [], "phased": []}
    current = None
    for line in (output or "").splitlines():
        stripped = line.strip()
        if stripped in _APT_HELD_HEADS:
            current = _APT_HELD_HEADS[stripped]
            continue
        if current and line.startswith(" ") and stripped:
            for name in stripped.split():
                if name not in found[current]:
                    found[current].append(name)
            continue
        current = None
    return found


def apt_held_back_summary(found):
    """Lines that lead the patch stage output when apt left updates out."""
    if not found["kept-back"] and not found["phased"]:
        return []
    lines = ["Installed what apt would install. Not installed this run:"]
    lines += [f"[kept-back] {n} needs a package added or removed, which `apt-get upgrade` never does"
              for n in found["kept-back"]]
    lines += [f"[phased] {n} is being rolled out gradually by the distribution and will install on a later run"
              for n in found["phased"]]
    return lines


# After a command's timeout: how long it gets to stop on SIGTERM (dnf and
# apt finish or roll back the step they're on) before SIGKILL.
STOP_GRACE_SECONDS = 60


def _smbios_uuid():
    """This machine's hardware id (as enroll.py sends it), or '' when it can't be read."""
    try:
        with open("/sys/class/dmi/id/product_uuid") as f:
            return f.read().strip().lower()
    except OSError:
        return ""


def _set_repo_options(text, options, drop):
    """
    The repo file with `drop` keys removed from, and `options` lines put
    into, its [kite] section (the first section if none is called
    that). Other sections are left exactly as they are.
    """
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip().startswith("[")]
    if not starts:
        return "\n".join(options + lines) + "\n"
    begin = next((i for i in starts if lines[i].strip() == "[kite]"), starts[0])
    end = next((i for i in starts if i > begin), len(lines))
    body = [line for line in lines[begin + 1:end] if not re.match(r"^\s*(%s)\s*=" % "|".join(drop), line)]
    return "\n".join(lines[:begin + 1] + options + body + lines[end:]) + "\n"


def _boot_id():
    """Changes on every boot: how a reboot is told apart from an agent restart."""
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return ""


def run_cmd(cmd, dry_run=False, timeout=1800, env=None):
    """
    Run a command; (returncode, stdout+stderr). It runs in its own process
    group, so on a timeout everything it started is stopped with it:
    SIGTERM first, so a package manager can finish the step it's on
    rather than being killed mid-transaction, then SIGKILL. And a child
    left holding the output pipe can't keep this waiting forever (Python
    3.6's subprocess.run did exactly that after a kill).
    """
    log.info("exec: %s", " ".join(cmd))
    if dry_run:
        return 0, f"[dry-run] would run: {' '.join(cmd)}"
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,  # 'text=' kwarg needs Python 3.7+; Rocky 8's default python3 is 3.6
            env=env,
            start_new_session=True,
        )
    except FileNotFoundError as e:
        return 1, f"command not found: {e}"
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, ((out or "") + (err or "")).strip()
    except subprocess.TimeoutExpired:
        pass
    note = f"command timed out after {timeout}s and was stopped: {' '.join(cmd)}"
    for sig, wait in ((signal.SIGTERM, STOP_GRACE_SECONDS), (signal.SIGKILL, 10)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        try:
            out, err = proc.communicate(timeout=wait)
            return 1, (note + "\n" + (out or "") + (err or "")).strip()
        except subprocess.TimeoutExpired:
            continue
    return 1, note


# Bounds on what one inventory report carries about the network, so a
# host with thousands of veth pairs or listening sockets can't turn the
# report into a megabyte. Generous for any real server.
MAX_INTERFACES = 128
MAX_LISTENING = 1000
# Interface kinds that are plumbing rather than networks: per-container
# veth pairs and tunnel endpoints. Skipped unless they carry a global
# address, which would make them worth knowing about after all.
_PLUMBING_KINDS = {"veth", "tun", "tap", "dummy", "ifb", "nlmon"}


def _ss_endpoint(text):
    """
    Split an ss local-address column into (address, port).

    ss prints '0.0.0.0:22', '[::]:22', '*:22', and scoped forms like
    '127.0.0.53%lo:53' or '[fe80::1]%eth0:546'. The port is always after
    the last colon; the address may itself contain colons (IPv6).
    """
    addr, _, port = text.rpartition(":")
    addr = addr.split("%", 1)[0].strip("[]")
    if addr == "*":
        addr = "0.0.0.0"
    return addr, port


def _is_loopback(addr):
    return addr.startswith("127.") or addr == "::1"


def parse_ss_listening(output):
    """
    Listening TCP and bound UDP sockets from `ss -H -tulnp`, as
    [{proto, address, port, process, loopback}]. Lines that don't parse
    are skipped rather than failing the whole report.
    """
    found, seen = [], set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] == "Netid":
            continue
        proto, state, local = fields[0], fields[1], fields[4]
        if proto not in ("tcp", "udp") or state not in ("LISTEN", "UNCONN"):
            continue
        addr, port = _ss_endpoint(local)
        if not port.isdigit():
            continue
        process = ""
        rest = " ".join(fields[6:])
        if 'users:(("' in rest:
            process = rest.split('users:(("', 1)[1].split('"', 1)[0]
        key = (proto, addr, int(port))
        if key in seen:
            continue
        seen.add(key)
        found.append({"proto": proto, "address": addr, "port": int(port),
                      "process": process, "loopback": _is_loopback(addr)})
    return found[:MAX_LISTENING]


def parse_ip_addr(data):
    """
    Interfaces from `ip -d -j addr show`, as [{name, mac, kind, up,
    addresses}]. Loopback is skipped, and so is container plumbing
    with no global address -- see _PLUMBING_KINDS.
    """
    out = []
    for link in data or []:
        if link.get("link_type") == "loopback":
            continue
        kind = ((link.get("linkinfo") or {}).get("info_kind")) or ""
        addresses = [
            "%s/%s" % (a["local"], a["prefixlen"])
            for a in link.get("addr_info") or []
            if a.get("scope") == "global" and a.get("local") and a.get("prefixlen") is not None
        ]
        if kind in _PLUMBING_KINDS and not addresses:
            continue
        out.append({
            "name": link.get("ifname", ""),
            "mac": (link.get("address") or "").lower(),
            "kind": kind,
            "up": "UP" in (link.get("flags") or []),
            "addresses": addresses,
        })
    return out[:MAX_INTERFACES]


# ---------- installed software ----------
#
# Everything installed, for the controller to match against vulnerability
# data. Read-only: the package database, snap and flatpak. Sent in full
# only when it changed (see Agent._software_payload).

# rpm and dpkg-query expand \t and \n in their format strings themselves.
_RPM_QF = r"%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\n"
_DPKG_FMT = r"${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"


def parse_rpm_qa(out):
    """`rpm -qa --qf _RPM_QF` -> items. The source RPM is what RHEL-family advisories name."""
    items = []
    for line in (out or "").splitlines():
        f = line.split("\t")
        if len(f) < 7 or f[0] in ("gpg-pubkey", "gpg-pubkey-release"):
            continue
        name, epoch, ver, rel, arch, srpm, vendor = f[:7]
        version = f"{ver}-{rel}" if epoch in ("", "0", "(none)") else f"{epoch}:{ver}-{rel}"
        src_name = src_version = ""
        if srpm.endswith(".src.rpm"):
            parts = srpm[: -len(".src.rpm")].rsplit("-", 2)
            if len(parts) == 3:
                src_name, src_version = parts[0], f"{parts[1]}-{parts[2]}"
        items.append({"kind": "rpm", "name": name, "version": version, "arch": arch,
                      "source_name": src_name, "source_version": src_version,
                      "publisher": "" if vendor == "(none)" else vendor})
    return items


def parse_dpkg_query(out):
    """`dpkg-query -W -f _DPKG_FMT` -> installed packages only ('ii'). Debian/Ubuntu advisories name the source."""
    items = []
    for line in (out or "").splitlines():
        f = line.split("\t")
        if len(f) < 6 or not f[5].startswith("ii"):
            continue
        name, ver, arch, src, src_ver = f[:5]
        items.append({"kind": "deb", "name": name, "version": ver, "arch": arch,
                      "source_name": (src or name).split(" ")[0], "source_version": src_ver or ver})
    return items


def parse_snap_list(out):
    items = []
    for line in (out or "").splitlines()[1:]:   # header: Name Version Rev Tracking Publisher Notes
        cols = line.split()
        if len(cols) >= 2:
            items.append({"kind": "snap", "name": cols[0], "version": cols[1],
                          "publisher": cols[4].rstrip("*✓") if len(cols) > 4 else ""})
    return items


def parse_flatpak_list(out):
    items = []
    for line in (out or "").splitlines():
        cols = line.split("\t")
        if cols and cols[0].strip():
            items.append({"kind": "flatpak", "name": cols[0].strip(), "version": cols[1].strip() if len(cols) > 1 else ""})
    return items


def os_release():
    try:
        with open("/etc/os-release") as f:
            pairs = (line.rstrip("\n").split("=", 1) for line in f if "=" in line)
            return {k: v.strip('"') for k, v in pairs}
    except OSError:
        return {}


def collect_software(pkg_manager, timeout=120):
    """
    (items, error). items is sorted, so the same system always hashes the
    same; error is set when the package database couldn't be read, and
    then nothing is sent rather than an empty list that would read as
    "nothing installed".
    """
    if pkg_manager == "dnf":
        rc, out = run_cmd(["rpm", "-qa", "--qf", _RPM_QF], timeout=timeout)
        if rc != 0:
            return None, "rpm -qa failed: %s" % out[:200]
        items = parse_rpm_qa(out)
    elif pkg_manager == "apt":
        rc, out = run_cmd(["dpkg-query", "-W", "-f", _DPKG_FMT], timeout=timeout)
        if rc != 0:
            return None, "dpkg-query failed: %s" % out[:200]
        items = parse_dpkg_query(out)
    else:
        return None, "no supported package manager"
    if shutil.which("snap"):
        rc, out = run_cmd(["snap", "list"], timeout=60)
        if rc == 0:
            items += parse_snap_list(out)
    if shutil.which("flatpak"):
        rc, out = run_cmd(["flatpak", "list", "--app", "--columns=application,version"], timeout=60)
        if rc == 0:
            items += parse_flatpak_list(out)
    rel = os_release()
    if rel.get("ID"):
        items.append({"kind": "os", "name": rel["ID"], "version": rel.get("VERSION_ID", ""),
                      "publisher": rel.get("PRETTY_NAME", "")[:200]})
    items.sort(key=lambda i: (i["kind"], i["name"], i.get("arch", ""), i.get("version", "")))
    return items, ""


def software_hash(items):
    return hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()


def discover_network(timeout=15):
    """
    What this host looks like on the network: its interfaces and
    addresses, default gateway, and the sockets it listens on. Read-only,
    from iproute2 (`ip`, `ss`), which every supported distro ships.

    Returns {"ok", "error", "interfaces", "default_gateway", "listening"}.
    ok=False means "could not tell", which the controller keeps distinct
    from "no ports open" -- the same rule as a failed update assessment.
    """
    result = {"ok": True, "error": "", "interfaces": [], "default_gateway": "", "listening": []}
    rc, out = run_cmd(["ip", "-d", "-j", "addr", "show"], timeout=timeout)
    if rc != 0:
        return dict(result, ok=False, error="ip addr failed: %s" % out[:300])
    try:
        result["interfaces"] = parse_ip_addr(json.loads(out))
    except ValueError as e:
        return dict(result, ok=False, error="could not parse ip -j output: %s" % e)
    rc, out = run_cmd(["ip", "-j", "route", "show", "default"], timeout=timeout)
    if rc == 0:
        try:
            routes = json.loads(out or "[]")
            result["default_gateway"] = next((r.get("gateway", "") for r in routes if r.get("gateway")), "")
        except ValueError:
            pass  # the gateway is a nicety; interfaces and ports still stand
    rc, out = run_cmd(["ss", "-H", "-tulnp"], timeout=timeout)
    if rc != 0:
        return dict(result, ok=False, error="ss failed: %s" % out[:300])
    result["listening"] = parse_ss_listening(out)
    return result


def discover_containers(runtime, timeout=30):
    """
    Enumerate this host's containers and what each one is running.

    Read-only by design. Nothing here starts, stops, pulls or recreates
    anything: the point is to answer "is this host running something
    stale" without taking any action whose blast radius depends on how
    the container was created.

    Returns a list of dicts, or [] when no runtime is installed. A
    runtime that is present but unusable (daemon down, permission
    denied) also yields [] rather than raising — container inventory is
    supplementary, and must never be able to fail a patch run.
    """
    if not runtime:
        return []

    # One record per line, tab-separated, so a container name containing
    # spaces can't shift the fields. Labels are emitted as the runtime's
    # own comma-separated k=v list.
    fmt = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Labels}}"
    rc, out = run_cmd([runtime, "ps", "--all", "--no-trunc", "--format", fmt], timeout=timeout)
    if rc != 0:
        log.warning("container discovery skipped: %s ps failed: %s", runtime, out[:200])
        return []

    # One listing of the capture repository, rather than an inspect per
    # container: a host with fifty services should cost one call.
    captured = set()
    rc_tags, tags_out = run_cmd([runtime, "images", "--format", "{{.Repository}}:{{.Tag}}",
                                  _ROLLBACK_REPO + "/*"], timeout=timeout)
    if rc_tags == 0:
        captured = {line.strip() for line in tags_out.splitlines() if line.strip()}

    containers = []
    for line in out.splitlines():
        fields = line.split("\t")
        if len(fields) < 4:
            continue
        container_id, names, image, state = fields[:4]
        raw_labels = fields[4] if len(fields) > 4 else ""
        labels = {}
        for pair in raw_labels.split(","):
            if "=" in pair:
                key, _, value = pair.partition("=")
                labels[key.strip()] = value.strip()
        containers.append({
            "container_id": container_id[:12],
            "name": (names.split(",")[0] if names else container_id[:12]),
            "image": image,
            "state": state.lower(),
            "managed_by": _classify_management(labels),
            "compose_project": labels.get(_COMPOSE_PROJECT_LABEL, ""),
            "compose_service": labels.get(_COMPOSE_SERVICE_LABEL, ""),
            "compose_working_dir": labels.get(_COMPOSE_WORKDIR_LABEL, ""),
            "pinned": _is_pinned(image),
            "image_digest": "",
            "update_available": None,   # None = not determined; see check_image_drift
            "rollback_available": rollback_tag(
                labels.get(_COMPOSE_PROJECT_LABEL, ""),
                labels.get(_COMPOSE_SERVICE_LABEL, ""),
            ) in captured,
        })
    return containers


def _local_image_identity(runtime, image, timeout=20):
    """
    (config_digest, platform) for the locally stored image, or ('', '').

    The config digest is what identifies image *content*. The repo digest
    is not usable for this comparison: for a multi-arch image it is the
    digest of the manifest LIST, while a registry query returns
    per-platform manifests, so the two never match and every container
    would look outdated.
    """
    # `index . "Variant"` rather than `.Variant`: the field is absent from
    # the inspect output on some runtime versions, and referring to it
    # directly fails the whole template ("map has no entry for key").
    rc, out = run_cmd([runtime, "image", "inspect", image, "--format",
                        '{{.Id}}|{{.Architecture}}|{{.Os}}|{{index . "Variant"}}'], timeout=timeout)
    if rc != 0 or "|" not in out:
        return "", ""
    parts = out.strip().split("|")
    if len(parts) < 3:
        return "", ""
    config_digest, arch, os_name = parts[0], parts[1], parts[2]
    variant = parts[3] if len(parts) > 3 else ""
    if variant in ("<no value>", "<nil>"):
        variant = ""
    return config_digest, "/".join(x for x in (os_name, arch, variant) if x)


def _manifest_platform(descriptor):
    platform = descriptor.get("platform") or {}
    return "/".join(
        x for x in (platform.get("os"), platform.get("architecture"), platform.get("variant")) if x
    )


def _registry_config_digest(runtime, image, platform, timeout=30):
    """
    The config digest the tag currently resolves to upstream for
    `platform`, or '' when it can't be determined — an unauthenticated
    private registry, no network, or a runtime without a manifest
    subcommand. '' means unknown and must not be read as "up to date".

    A multi-arch tag returns one entry per platform, so the right entry
    has to be selected rather than taking the first: comparing against
    another architecture's manifest reports drift that isn't there.
    """
    rc, out = run_cmd([runtime, "manifest", "inspect", "--verbose", image], timeout=timeout)
    if rc != 0:
        return ""
    try:
        payload = json.loads(out)
    except ValueError:
        return ""

    entries = payload if isinstance(payload, list) else [payload]

    def config_digest(entry):
        # OCI and Docker schema-2 registries name this differently.
        manifest = entry.get("OCIManifest") or entry.get("SchemaV2Manifest") or {}
        return (manifest.get("config") or {}).get("digest") or ""

    # A single-manifest image carries no platform to choose between.
    if len(entries) == 1:
        return config_digest(entries[0])

    # Exact platform first; then os/arch ignoring variant, since a
    # runtime that omits Variant locally would otherwise never match a
    # registry entry that reports one (linux/arm64 vs linux/arm64/v8).
    base = "/".join(platform.split("/")[:2])
    fallback = ""
    for entry in entries:
        entry_platform = _manifest_platform(entry.get("Descriptor") or {})
        if entry_platform == platform:
            return config_digest(entry)
        if not fallback and "/".join(entry_platform.split("/")[:2]) == base:
            fallback = config_digest(entry)
    return fallback


def check_image_drift(runtime, containers, timeout=30):
    """
    Fill in update_available by comparing the config digest of each
    mutable tag's local image against the one the registry currently
    serves for the same platform.

    Only mutable tags are checked. A digest-pinned image is frozen on
    purpose and is left as not-updatable rather than being reported as
    drifted. An image whose upstream digest can't be read stays None —
    "unknown", which the console shows as unknown rather than folding
    into either answer.

    Costs one registry round trip per distinct image, which is why this
    is throttled by DRIFT_CHECK_INTERVAL rather than run every poll.
    """
    resolved = {}
    for container in containers:
        image = container["image"]
        if container["pinned"]:
            container["update_available"] = False
            continue
        if image not in resolved:
            local, platform = _local_image_identity(runtime, image)
            remote = _registry_config_digest(runtime, image, platform, timeout=timeout) if local else ""
            resolved[image] = (local, remote)
        local, remote = resolved[image]
        container["image_digest"] = local
        if local and remote:
            container["update_available"] = local != remote
        else:
            container["update_available"] = None
    return containers


class Agent:
    def __init__(self, config, dry_run=False):
        self.base = config["controller_url"].rstrip("/")
        self.host_id = config["host_id"]
        self.secret = config["agent_secret"]
        # Baseline check-in cadence when idle — this is deliberately long
        # (default 15 min; can be set to hours). The local trigger file
        # (see _sleep_with_trigger_check) is what gives instant response
        # for on-demand work without needing a short interval here.
        self.poll_interval = config.get("poll_interval", 900)
        # Short backoff after a genuinely FAILED request (network down,
        # controller unreachable) — distinct from poll_interval, since you
        # don't want to wait the full 15 minutes to retry after a blip,
        # but you also don't want a tight error-retry loop.
        self.error_backoff = config.get("error_backoff", 20)
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {self.secret}"
        # False when enroll.py was run with --insecure (self-signed
        # controller cert) — set on the session so it applies to every
        # request this agent ever makes, not just the first one.
        self.session.verify = config.get("verify_tls", True)
        if config.get("ca_cert") and os.path.exists(config["ca_cert"]):
            self.session.verify = config["ca_cert"]
        if not self.session.verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log.warning(
                "TLS certificate verification is DISABLED for controller calls "
                "(verify_tls: false in agent.conf) -- traffic to the controller has "
                "no protection against interception or tampering. Re-enroll against "
                "a trusted certificate to fix this."
            )
        self.pkg_manager = detect_package_manager()
        log.info("detected package manager: %s", self.pkg_manager or "NONE (dnf/apt-get not found)")
        self.container_runtime = detect_container_runtime()
        if self.container_runtime:
            log.info("detected container runtime: %s", self.container_runtime)
        # Monotonic timestamp of the last registry drift check, so the
        # expensive half of discovery is throttled independently of the
        # cheap local enumeration. 0 = never checked, so the first pass
        # does a full check.
        self._last_drift_check = 0.0
        # Set from the instruction just before the containers stage runs;
        # 'update' unless the controller asked for a rollback.
        self._container_action = "update"
        # Set from the instruction just before the patch stage runs;
        # '' means every available update, which is what a run that
        # doesn't ask for a narrower scope gets.
        self._severity_filter = ""
        self._skip_uninstallable = False
        self._self_update_tried = {}   # target version -> monotonic time of the last attempt
        # (job_id, stage, status, output) of the last stage run here: see run_stage
        self._last_result = None
        self._software_sent = None      # hash of the software list the controller last accepted
        self.install_dir = os.path.dirname(os.path.abspath(__file__))   # where agent.py/enroll.py live

    def _url(self, path):
        return f"{self.base}/agent/{self.host_id}{path}"

    def heartbeat(self, status="healthy"):
        """Kept for explicit/manual use — the main loop no longer calls this,
        since /jobs/next updates last_seen on every poll attempt now."""
        try:
            self.session.post(self._url("/heartbeat"), json={"status": status}, timeout=10)
            log.info("heartbeat ok (status=%s)", status)
        except requests.RequestException as e:
            log.warning("heartbeat failed: %s", e)

    def poll_next(self):
        """
        Plain quick poll — no held-open connection. Returns
        (instruction_or_None, ok, self_update_target_or_None) so the
        caller can distinguish "no work" from "the request itself
        failed", and separately learn whether the controller wants this
        agent to self-update (see SELF_UPDATE_HEADER on the
        controller side; a header, not a body field, so it rides along
        without changing this response's existing JSON shape). Sends this
        agent's own poll_interval and version so the controller can
        calibrate offline-detection thresholds and self-update decisions
        correctly for this specific host.
        """
        try:
            r = self.session.get(self._url("/jobs/next"),
                                  params={"interval": self.poll_interval, "agent_version": AGENT_VERSION},
                                  timeout=POLL_CLIENT_TIMEOUT)
            r.raise_for_status()
            self_update_target = r.headers.get("X-Kite-Self-Update") or None
            return r.json(), True, self_update_target
        except requests.RequestException as e:
            log.warning("poll failed: %s", e)
            return None, False, None

    def _sleep_with_trigger_check(self, duration):
        """
        Sleep up to `duration` seconds, but wake immediately — and consume
        the trigger — if TRIGGER_PATH appears during the sleep. This is
        the local on-demand mechanism: no network push, no held-open
        connection, just a file that anything with local access (SSH,
        Ansible, cron, a person at the console) can touch to make the
        agent check in right now instead of waiting for the next
        scheduled poll. Same pattern Qualys uses for its own on-demand
        trigger (a local registry key / shell script the agent watches).
        """
        elapsed = 0.0
        while elapsed < duration:
            if os.path.exists(TRIGGER_PATH):
                log.info("local trigger detected at %s — waking early", TRIGGER_PATH)
                try:
                    os.remove(TRIGGER_PATH)
                except FileNotFoundError:
                    pass
                return
            step = min(TRIGGER_CHECK_INTERVAL, duration - elapsed)
            time.sleep(step)
            elapsed += step

    def self_update(self, target_version):
        """
        Runs 'dnf upgrade kite-agent-<version>' (with a fresh package
        list) to pick up the version the controller is targeting, then
        restarts the systemd unit so the new agent.py actually takes
        effect. Only ever called from an idle poll (see loop() below) —
        never while a job stage is in flight.

        dnf-only for now: there's no .deb/apt repo for this agent yet
        (same stated gap as Debian/Ubuntu packaging), so an
        apt-based host just logs and skips rather than silently doing
        nothing forever unexplained.

        The RPM's own %post already runs 'systemctl try-restart' on
        upgrade (see packaging/kite-agent.spec) — the explicit
        restart here is belt-and-suspenders for the case where dnf's own
        post-scriptlet restart doesn't land (e.g. a manual --once test
        run outside systemd), not a duplicate of it in the normal path.
        A process restarting the systemd unit it runs under is a
        well-trodden pattern — dnf-automatic and yum-cron restart other
        services on upgrade the same way. systemd handles the handover;
        the replacement process is started from the new binary after
        this one exits.

        Returns True only when an update was installed and the service
        restart asked for; otherwise (skipped, not due yet, failed) the
        caller carries on with an ordinary idle poll. An attempt, failed
        or not, is made at most hourly per version: the controller asks
        again on every poll until the agent reports the new version.
        """
        if self.pkg_manager not in ("dnf", "apt"):
            log.warning("self-update to %s requested but no supported package manager was detected — skipping",
                        target_version)
            return False
        if not re.fullmatch(r"\d+(\.\d+)*", target_version or ""):
            log.warning("self-update: ignoring malformed target version %r", target_version)
            return False
        tried_at = self._self_update_tried.get(target_version)
        if tried_at and time.monotonic() - tried_at < 3600:
            return False
        self._self_update_tried[target_version] = time.monotonic()
        if self.pkg_manager == "apt":
            if self.dry_run:
                log.info("[dry-run] would install the controller's agent bundle %s", target_version)
                return False
            ok, note = self._self_update_from_bundle(target_version)
            if not ok:
                log.error("self-update failed: %s", note)
                return False
            log.info("self-update: %s; restarting service", note)
            run_cmd(["systemctl", "try-restart", "kite-agent"], timeout=30)
            return True
        log.info("self-update requested: %s -> %s", AGENT_VERSION, target_version)
        # --refresh: the repo's cached package list can be up to two days
        # old (dnf's default expiry), and a version published since then
        # would read as "nothing to do". Naming the version installs
        # exactly what the controller asked for.
        cmd = ["dnf", "-y", "--refresh", "upgrade", f"kite-agent-{target_version}"]
        if self.dry_run:
            log.info("[dry-run] would run: %s", " ".join(cmd))
            return False
        rc, out = run_cmd(cmd, timeout=300)
        if rc != 0:
            log.error("self-update failed (rc=%s): %s", rc, out)
            return False
        # dnf exits 0 for "nothing to do" too. Restarting into the same
        # version would only bring the request straight back (and forget
        # the hourly limit above), so restart only into the version asked for.
        rc, installed = run_cmd(["rpm", "-q", "--qf", "%{VERSION}", "kite-agent"], timeout=30)
        if rc != 0 or installed.strip() != target_version:
            log.error("self-update: dnf finished but kite-agent is %s, not %s; not restarting",
                      installed.strip() or "not installed", target_version)
            return False
        log.info("self-update: kite-agent %s installed, restarting service", target_version)
        run_cmd(["systemctl", "try-restart", "kite-agent"], timeout=30)
        return True

    # The files the Debian/Ubuntu install (install-debian.sh) puts in place.
    _BUNDLE_FILES = (("agent-linux/agent.py", "agent.py"), ("agent-linux/enroll.py", "enroll.py"))
    _BUNDLE_UNIT = "agent-linux/kite-agent.service"
    UNIT_PATH = "/etc/systemd/system/kite-agent.service"

    def _self_update_from_bundle(self, target_version):
        """
        Debian/Ubuntu: there's no apt repo for the agent, so update from the
        same bundle install-debian.sh installed from -- the controller's
        /download/agent-linux. Checks the download against the checksum the
        controller sends with it and that it really is target_version, then
        replaces agent.py and enroll.py beside this one (keeping the old
        agent.py as agent.py.prev) and the unit file if it changed.
        Returns (ok, note).
        """
        try:
            r = self.session.get(f"{self.base}/download/agent-linux", timeout=60)
            r.raise_for_status()
        except requests.RequestException as e:
            return False, f"could not download the agent bundle: {e}"
        want_sum = (r.headers.get("X-Kite-Sha256") or "").lower()
        if not want_sum:
            # Required, as the Windows agent requires it: without one
            # there is nothing to check the download against, and this
            # replaces the code that runs as root on this host.
            return False, "the controller didn't send a checksum with the bundle (controller too old?)"
        if hashlib.sha256(r.content).hexdigest() != want_sum:
            return False, "the downloaded bundle doesn't match its checksum"
        try:
            with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
                files = {}
                for member in [m for m, _ in self._BUNDLE_FILES] + [self._BUNDLE_UNIT]:
                    m = tar.getmember(member)
                    if not m.isfile():
                        return False, f"{member} in the bundle isn't a regular file"
                    files[member] = tar.extractfile(m).read()
        except (tarfile.TarError, KeyError, OSError) as e:
            return False, f"the agent bundle is unreadable: {e}"
        found = re.search(rb'^AGENT_VERSION = "([^"]+)"', files["agent-linux/agent.py"], re.MULTILINE)
        if not found or found.group(1).decode() != target_version:
            have = found.group(1).decode() if found else "unknown"
            return False, f"the controller's bundle is version {have}, not {target_version}"

        install_dir = self.install_dir
        try:
            agent_path = os.path.join(install_dir, "agent.py")
            if os.path.exists(agent_path):
                shutil.copy2(agent_path, agent_path + ".prev")
            for member, name in self._BUNDLE_FILES:
                _write_atomically(os.path.join(install_dir, name), files[member], 0o644)
            unit = files[self._BUNDLE_UNIT]
            try:
                with open(self.UNIT_PATH, "rb") as f:
                    unit_changed = f.read() != unit
            except OSError:
                unit_changed = True
            if unit_changed:
                _write_atomically(self.UNIT_PATH, unit, 0o644)
                run_cmd(["systemctl", "daemon-reload"], timeout=30)
        except OSError as e:
            return False, f"could not install the new agent files: {e}"
        return True, f"installed agent {target_version} from the controller's bundle"

    def report(self, job_id, stage_name, status, output):
        """Send a stage's result. True when the controller has it."""
        try:
            r = self.session.post(
                self._url(f"/jobs/{job_id}/stages/{stage_name}/report"),
                json={"status": status, "output": (output or "")[:8000]},
                timeout=15,
            )
            r.raise_for_status()
            log.info("reported job %s stage %s -> %s", job_id, stage_name, status)
            return True
        except requests.RequestException as e:
            log.error("report failed for job %s stage %s: %s", job_id, stage_name, e)
            return False

    def report_containers(self):
        """
        Send this host's container inventory to the controller.

        Best-effort throughout: a host with no container runtime sends an
        empty list (which correctly clears any previously reported
        containers), and any failure here is logged and dropped. Patch
        runs must not depend on, or be broken by, inventory reporting.
        """
        if self.dry_run:
            return
        try:
            containers = discover_containers(self.container_runtime)
            now = time.monotonic()
            if containers and (now - self._last_drift_check) >= DRIFT_CHECK_INTERVAL:
                check_image_drift(self.container_runtime, containers)
                self._last_drift_check = now
            updates, sources = assess_all_sources(self.pkg_manager)
            try:
                network = discover_network()
            except Exception as e:  # noqa: BLE001 — network facts must never block the rest of the report
                network = {"ok": False, "error": "network discovery failed: %s" % e,
                           "interfaces": [], "default_gateway": "", "listening": []}
            # The host-level flags track the OS source specifically -- that
            # is what "is this host patched" has always meant. Third-party
            # sources are shown per-source rather than folded into one.
            os_source = next((s for s in sources if s["name"] == "os"),
                             {"ok": True, "error": ""})
            software = self._software_payload()
            r = self.session.post(
                self._url("/inventory"),
                json={
                    "runtime": self.container_runtime or "",
                    "containers": containers,
                    "updates": updates,
                    "update_sources": sources,
                    "updates_ok": os_source["ok"],
                    "updates_error": os_source["error"],
                    "network": network,
                    "smbios_uuid": _smbios_uuid(),
                    **({"software": software} if software else {}),
                },
                timeout=POLL_CLIENT_TIMEOUT,
            )
            self._software_accepted(software, r)
            log.info("reported %s container(s), %s pending update(s) across %s source(s), "
                     "%s interface(s), %s listening socket(s)",
                     len(containers), len(updates), len(sources),
                     len(network["interfaces"]), len(network["listening"]))
        except requests.RequestException as e:
            log.warning("container inventory report failed: %s", e)
        except Exception as e:  # noqa: BLE001 — inventory must never break the agent
            log.warning("container discovery failed: %s", e)

    def _software_payload(self):
        """{hash, items} when the list changed since the controller last took it, {hash} otherwise; None if unreadable."""
        try:
            items, error = collect_software(self.pkg_manager)
        except Exception as e:  # noqa: BLE001 — never let this break the report
            items, error = None, str(e)
        if items is None:
            log.warning("software inventory skipped: %s", error)
            return None
        h = software_hash(items)
        return {"hash": h} if h == self._software_sent else {"hash": h, "items": items}

    def _software_accepted(self, software, response):
        """Remember what the controller now holds, or forget it when it asks for the list again."""
        if not software:
            return
        try:
            ok = response.status_code == 200
            resend = ok and bool(response.json().get("software_resend"))
        except (ValueError, AttributeError):
            ok, resend = False, False
        if resend or not ok:
            self._software_sent = None
        elif "items" in software:
            self._software_sent = software["hash"]

    def resume_pending_reboot(self):
        """
        If a run's reboot stage asked for a reboot and the host has since
        rebooted, report that stage done. Checked on start and before every
        poll, so a report that didn't get through is sent again rather
        than lost.

        "Has rebooted" is the kernel's boot id changing, not the agent
        starting: an agent restarted for another reason (a self-update)
        while the reboot is still pending mustn't report one. A state
        file that can't be read is set aside (it would otherwise stop the
        agent at every start); the controller then shows the stage as
        still running, which someone can stop.
        """
        if not os.path.exists(STATE_PATH):
            return
        try:
            with open(STATE_PATH) as f:
                state = json.load(f)
            job_id = int(state["job_id"])
        except (OSError, ValueError, TypeError, KeyError) as e:
            log.error("the pending-reboot file %s is unreadable (%s); setting it aside", STATE_PATH, e)
            try:
                os.replace(STATE_PATH, STATE_PATH + ".bad")
            except OSError:
                pass
            return
        if state.get("boot_id") and state["boot_id"] == _boot_id():
            return   # the reboot hasn't happened yet
        uptime_s = self._uptime_seconds()
        output = f"host rebooted and back online, uptime {uptime_s:.0f}s"
        log.info("resuming after reboot: job %s", job_id)
        if self.report(job_id, "reboot", "done", output):
            os.remove(STATE_PATH)

    def reboot_pending(self):
        """A reboot this agent asked for that hasn't happened yet."""
        try:
            with open(STATE_PATH) as f:
                state = json.load(f)
        except (OSError, ValueError):
            return False
        return bool(state.get("boot_id")) and state["boot_id"] == _boot_id()

    @staticmethod
    def _uptime_seconds():
        try:
            with open("/proc/uptime") as f:
                return float(f.read().split()[0])
        except Exception:
            return -1.0

    # ---------- stage handlers ----------
    # Each returns (status, output) where status is 'done' | 'failed', except
    # stage_reboot, which can return ('deferred', '') when it actually reboots —
    # in that case nothing is reported now; resume_pending_reboot() finishes it
    # after the next boot.

    def run_stage(self, instruction):
        job_id = instruction["job_id"]
        stage = instruction["stage_name"]
        excludes = instruction["excludes"]
        custom_script = instruction.get("custom_script")

        # The controller hands out a stage until its report arrives. Given
        # the stage just run here again, the report was lost on the way:
        # send it again rather than run the stage twice. A second run is
        # not harmless -- the containers stage would take the images it
        # just pulled as the rollback point, losing the real one.
        if self._last_result and self._last_result[:2] == (job_id, stage):
            log.warning("job %s stage %s already ran here and its report didn't arrive; sending it again",
                        job_id, stage)
            self.report(*self._last_result)
            return

        # Set for both paths: a custom script is told the run's severity scope
        # through KITE_SEVERITY, so it can honour "security only" /
        # "Critical,Important" instead of silently patching everything the
        # operator did not ask for.
        self._severity_filter = instruction.get("severity_filter") or ""
        self._skip_uninstallable = bool(instruction.get("skip_uninstallable"))

        try:
            if custom_script:
                status, output = self.run_custom_script(job_id, stage, custom_script, excludes)
            else:
                handler = getattr(self, f"stage_{stage}", None)
                if not handler:
                    self.report(job_id, stage, "failed", f"agent has no handler for stage '{stage}'")
                    return
                # Every stage but this one acts on package rules; the
                # containers stage acts on the container list the run
                # selected, so it takes that instead of `excludes`.
                if stage == "containers":
                    # Stage-specific payload: this stage acts on the run's
                    # container selection, every other one on package rules.
                    self._container_action = instruction.get("container_action") or "update"
                    payload = instruction.get("containers") or []
                else:
                    payload = excludes
                status, output = handler(job_id, payload)
        except Exception as e:  # noqa: BLE001 — never let an exception hang a job silently
            status, output = "failed", f"unhandled agent error: {e}"

        if status == "deferred":
            return
        self._last_result = (job_id, stage, status, output)
        self.report(job_id, stage, status, output)

    def run_custom_script(self, job_id, stage_name, script_text, excludes):
        """
        Execute a controller-supplied script instead of the built-in handler
        for this stage. Written to a temp file rather than piped inline, so
        the script's own shebang/quoting behaves normally. The script's
        contract: exit 0 = done, any other exit code = failed; stdout+stderr
        (combined) is reported back as the stage output.

        Data is passed via environment variables rather than templated into
        the script text, so the same uploaded script keeps working as the
        exclude/pin list changes over time:
          KITE_JOB_ID, KITE_HOSTNAME, KITE_STAGE
          KITE_EXCLUDES  — space-separated skip-mode package patterns
          KITE_PINS      — space-separated "pattern=version" for pin-mode
          KITE_SEVERITY  — the run's severity scope: '' / 'all' (every
                               update), 'security', or a comma-separated
                               severity list such as 'Critical,Important'.
                               Without this a custom patch script has no way
                               to know what the operator actually asked for.
        """
        script_dir = "/var/lib/kite/stage_scripts"
        os.makedirs(script_dir, exist_ok=True)
        # stage_name is controller-supplied — os.path.join happily accepts
        # "../../etc/cron.d/pwned" (writes outside script_dir) or an
        # absolute path (silently discards script_dir entirely, per
        # os.path.join's own semantics) with no error. basename() plus a
        # containment check closes both: a traversal/absolute stage_name
        # is rejected outright rather than silently writing wherever it
        # points.
        safe_stage_name = os.path.basename(stage_name)
        script_path = os.path.join(script_dir, f"{safe_stage_name}.sh")
        if (not safe_stage_name or safe_stage_name in (".", "..")
                or os.path.dirname(os.path.abspath(script_path)) != os.path.abspath(script_dir)):
            return "failed", f"refusing custom script: unsafe stage name {stage_name!r}"
        with open(script_path, "w") as f:
            f.write(script_text)
        os.chmod(script_path, 0o700)

        skip_patterns = " ".join(r["pkg_pattern"] for r in excludes if r["mode"] == "skip")
        pins = " ".join(f"{r['pkg_pattern']}={r['version']}" for r in excludes if r["mode"] == "pin")

        env = os.environ.copy()
        env.update({
            "KITE_JOB_ID": str(job_id),
            "KITE_HOSTNAME": self._hostname(),
            "KITE_STAGE": stage_name,
            "KITE_EXCLUDES": skip_patterns,
            "KITE_PINS": pins,
            "KITE_SEVERITY": self._severity_filter or "",
        })

        log.info("exec custom script: %s (stage=%s)", script_path, stage_name)
        if self.dry_run:
            return "done", f"[dry-run] would run custom script for '{stage_name}' ({len(script_text)} bytes)"
        try:
            proc = subprocess.run(
                ["/bin/bash", script_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, env=env, timeout=3600,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode != 0:
                return "failed", output[-4000:] or f"custom script exited {proc.returncode} with no output"
            return "done", output[-4000:]
        except subprocess.TimeoutExpired:
            return "failed", f"custom script for '{stage_name}' timed out after 3600s"

    @staticmethod
    def _hostname():
        try:
            with open("/etc/hostname") as f:
                return f.read().strip()
        except Exception:
            return ""

    @staticmethod
    def _apt_env():
        """DEBIAN_FRONTEND=noninteractive stops dpkg config-file prompts from
        hanging an unattended run; NEEDRESTART_MODE=a tells Ubuntu's
        needrestart to restart affected services automatically instead of
        prompting — both are exactly what unattended-upgrades itself sets."""
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        env["NEEDRESTART_MODE"] = "a"
        return env

    # dpkg options that make an upgrade/install non-interactive on a config
    # file conflict — keep the existing (or default) config rather than
    # stopping to ask, same default unattended-upgrades ships with.
    # Wait up to 5 minutes for another apt (unattended-upgrades, someone's
    # shell) to finish, instead of failing on its lock straight away.
    _APT_LOCK_OPTS = ["-o", "DPkg::Lock::Timeout=300"]
    _APT_DPKG_OPTS = ["-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
                      *_APT_LOCK_OPTS]

    def stage_preflight(self, job_id, excludes):
        checks = [f"package manager: {self.pkg_manager or 'NONE DETECTED'}"]
        if self.pkg_manager == "dnf":
            rc, out = run_cmd(["dnf", "-C", "check-update"], dry_run=self.dry_run, timeout=60)
            # 100: updates are available; 0: none. 1 is an error -- except
            # an empty cache (-C reads only the cache), which the patch
            # stage fills anyway.
            if rc not in (0, 100) and not self.dry_run and "cache" not in out.lower():
                return "failed", "dnf can't read its repositories:\n" + out[-3000:]
            checks.append(f"dnf reachable (rc={rc})")
        elif self.pkg_manager == "apt":
            rc, out = run_cmd(["apt-get", *self._APT_LOCK_OPTS, "update"], dry_run=self.dry_run, timeout=300,
                              env=self._apt_env())
            if rc != 0 and not self.dry_run:
                return "failed", "apt-get update failed:\n" + out[-3000:]
            checks.append(f"apt-get update (rc={rc})")
        else:
            return "failed", "no supported package manager found (dnf or apt-get) — cannot patch this host"

        rc, out = run_cmd(["df", "-h", "/"], dry_run=self.dry_run)
        checks.append(out.replace("\n", " | "))

        return "done", "; ".join(checks)

    def stage_excludes(self, job_id, excludes):
        if self.pkg_manager == "dnf":
            return self._excludes_dnf(excludes)
        elif self.pkg_manager == "apt":
            return self._excludes_apt(excludes)
        return "failed", "no supported package manager found (dnf or apt-get)"

    @staticmethod
    def _load_holds():
        try:
            with open(HOLDS_PATH) as f:
                held = json.load(f)
            return set(h for h in held if isinstance(h, str))
        except (OSError, ValueError, TypeError):
            return set()

    def _save_holds(self, held):
        if self.dry_run:
            return
        try:
            os.makedirs(os.path.dirname(HOLDS_PATH), exist_ok=True)
            _write_atomically(HOLDS_PATH, json.dumps(sorted(held)).encode(), 0o600)
        except OSError as e:
            log.warning("could not record the package holds kite placed: %s", e)

    def _release_holds(self, held, wanted, kind, cmd, results):
        """
        Release the holds of `kind` kite placed that no rule asks for
        any more -- a rule removed or changed since the last run. Only
        kite's own: a hold someone placed by hand isn't in `held`.
        """
        for entry in sorted(h for h in held if h.startswith(kind + ":") and h not in wanted):
            target = entry.split(":", 1)[1]
            rc, out = run_cmd(cmd + [target], dry_run=self.dry_run)
            if rc == 0 or self.dry_run:
                held.discard(entry)
                results.append(f"released {target} (no rule asks for it any more)")
            else:
                results.append(f"could not release {target} (rc={rc}): {out.strip()[-200:]}")

    def _excludes_dnf(self, excludes):
        results = []
        held = self._load_holds()
        wanted = {"versionlock:" + f"{r['pkg_pattern'].rstrip('*')}-{r['version']}*"
                  for r in excludes if r["mode"] == "pin"}
        self._release_holds(held, wanted, "versionlock", ["dnf", "versionlock", "delete"], results)
        try:
            for rule in excludes:
                pattern = rule["pkg_pattern"]
                base = pattern.rstrip("*")
                if rule["mode"] == "pin":
                    lock_spec = f"{base}-{rule['version']}*"
                    rc, out = run_cmd(["dnf", "versionlock", "add", lock_spec], dry_run=self.dry_run)
                    results.append(f"pin {lock_spec} (rc={rc})")
                    if rc != 0 and not self.dry_run:
                        return "failed", "; ".join(results) + f" — {out}"
                    held.add("versionlock:" + lock_spec)
                else:
                    results.append(f"skip {pattern} (applied via --exclude at patch time)")
        finally:
            self._save_holds(held)
        return "done", "; ".join(results) if results else "no exclude rules to apply"

    def _excludes_apt(self, excludes):
        """
        apt has no --exclude-at-patch-time equivalent to dnf, so exclusion
        happens here instead, via `apt-mark hold` — stage_patch's `apt-get
        upgrade` naturally skips whatever's held, no per-invocation flag
        needed. Also no glob support: apt-mark operates on exact installed
        package names, unlike dnf's --exclude/versionlock which accept
        wildcards — a pattern with a '*' from a shared cross-platform patch
        definition simply won't match anything here, reported as such
        rather than silently doing nothing.
        """
        results = []
        held = self._load_holds()
        names = [r["pkg_pattern"] for r in excludes if "*" not in r["pkg_pattern"]]
        self._release_holds(held, {"hold:" + n for n in names}, "hold", ["apt-mark", "unhold"], results)
        # A package already held by someone else stays theirs: not recorded,
        # so it's never released here.
        theirs = set()
        if names:
            rc, out = run_cmd(["apt-mark", "showhold"], dry_run=self.dry_run)
            if rc == 0:
                theirs = set(out.split()) - {h.split(":", 1)[1] for h in held if h.startswith("hold:")}
        try:
            for rule in excludes:
                pattern = rule["pkg_pattern"]
                if "*" in pattern:
                    results.append(f"'{pattern}' skipped — apt-mark needs an exact package name, not a wildcard")
                    continue
                if rule["mode"] == "pin":
                    spec = f"{pattern}={rule['version']}"
                    rc, out = run_cmd(["apt-get", "install", "-y", "--allow-downgrades", *self._APT_DPKG_OPTS, spec],
                                       dry_run=self.dry_run, timeout=300, env=self._apt_env())
                    if rc != 0 and not self.dry_run:
                        return "failed", "; ".join(results) + f" — install {spec} failed: {out}"
                    rc, out = run_cmd(["apt-mark", "hold", pattern], dry_run=self.dry_run)
                    results.append(f"pin {spec}, held (rc={rc})")
                else:
                    rc, out = run_cmd(["apt-mark", "hold", pattern], dry_run=self.dry_run)
                    results.append(f"hold {pattern} (rc={rc})")
                    if rc != 0 and not self.dry_run:
                        return "failed", "; ".join(results) + f" — {out}"
                if rc == 0 and pattern not in theirs:
                    held.add("hold:" + pattern)
        finally:
            self._save_holds(held)
        return "done", "; ".join(results) if results else "no exclude rules to apply"

    def stage_snapshot(self, job_id, excludes):
        """
        Only ever dispatched here when the controller resolved this
        host's rollback backend to 'dnf_history' (see the controller's
        app/rollback/) — every other backend runs controller-side and
        never reaches the agent at all. No hypervisor needed: this just
        records the current dnf transaction id as a rollback reference
        point before patch runs, so 'dnf history undo <id>' is available
        afterward if needed. Not an automatic restore — a human decides
        that, same as the Proxmox backend only ever creates a snapshot,
        never restores one on its own.
        """
        if self.pkg_manager != "dnf":
            return "failed", (
                f"the dnf-history rollback backend requires dnf; this host's package manager "
                f"is '{self.pkg_manager or 'none detected'}' — pick a different rollback "
                "backend for this host in the controller's Settings."
            )
        if self.dry_run:
            return "done", "[dry-run] would capture the current dnf transaction id as the rollback reference point"
        rc, out = run_cmd(["dnf", "history", "list"], timeout=30)
        if rc != 0:
            return "failed", f"'dnf history list' failed (rc={rc}): {out}"
        last_id = self._parse_last_dnf_transaction_id(out)
        return "done", (
            f"dnf-history rollback reference captured: last transaction before this run is #{last_id}. "
            + (f"If this run needs reverting, run 'dnf history rollback {last_id}' on this host: it undoes "
               "every transaction after that one" if last_id else
               "This host had no dnf history, so this run's will be #1: 'dnf history undo 1' reverts it")
            + " (not automatic — a human decides)."
        )

    @staticmethod
    def _parse_last_dnf_transaction_id(output):
        """
        Parses `dnf history list`'s table -- header row, a '---' rule,
        then newest-first data rows like ' 12 | update -y | 2026-08-20
        10:00 | Update | 5'. Returns 0 (not an error) for a fresh system
        with no transaction history yet -- 'dnf history undo 1' is then
        the right first-ever id.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("ID") or set(line) <= {"-", " "}:
                continue
            first_field = line.split("|", 1)[0].strip()
            if first_field.isdigit():
                return int(first_field)
        return 0

    def stage_patch(self, job_id, excludes):
        """
        `self._severity_filter` narrows what gets installed:

          ''/'all'   every available update (the default)
          'security' security advisories only
          'Critical,Important' (any severity list) those levels only

        dnf enforces all three natively. apt has no severity metadata, so
        a severity list there degrades to security-only and the stage
        output says it did — silently patching more than was asked for
        would be worse, and silently patching less than "Critical" implies
        is not something to hide.
        """
        if self.pkg_manager == "dnf":
            return self._patch_dnf(excludes)
        elif self.pkg_manager == "apt":
            return self._patch_apt(excludes)
        return "failed", "no supported package manager found (dnf or apt-get)"

    def _severity_levels(self):
        """The requested severity list, or [] for 'all'/'security'."""
        raw = (self._severity_filter or "").strip()
        if raw.lower() in ("", "all", "security"):
            return []
        return [level.strip() for level in raw.split(",") if level.strip()]

    def _patch_dnf(self, excludes):
        # The agent itself is updated only by self-update, to the version
        # Settings asks for -- never as a side effect of patching the host.
        cmd = ["dnf", "update", "-y", "--exclude=kite-agent"]
        levels = self._severity_levels()
        if levels:
            # --security scopes to advisories; --sec-severity then narrows
            # to the levels asked for. Without --security, --sec-severity
            # is ignored by dnf.
            cmd.append("--security")
            for level in levels:
                cmd.append(f"--sec-severity={level}")
        elif (self._severity_filter or "").lower() == "security":
            cmd.append("--security")
        for rule in excludes:
            if rule["mode"] == "skip":
                cmd.append(f"--exclude={rule['pkg_pattern']}")
        if self._skip_uninstallable:
            # Install everything that can be installed and leave the rest
            # (an update built for a newer OS, a vendor repo missing a
            # dependency) at its current version -- listed, not hidden.
            cmd += ["--nobest", "--skip-broken"]
        rc, out = run_cmd(cmd, dry_run=self.dry_run, timeout=3600)
        problems = parse_dnf_problems(out)
        if rc != 0 and not self.dry_run:
            if problems:
                head = ["dnf stopped before installing anything: these updates can't be installed on this system."]
                head += [f"[uninstallable] {p}" for p in format_dnf_problems(problems)]
                head.append("Fix: add a 'skip' update rule for each package, fix the repository, or turn on "
                            "'Skip updates that can't be installed' (Settings -> Policy).")
                return "failed", _with_summary(head, out)
            return "failed", out[-4000:]
        if problems and self._skip_uninstallable:
            head = ["Installed what could be installed. Skipped, left at the current version:"]
            head += [f"[skipped] {p}" for p in format_dnf_problems(problems)]
            return "done", _with_summary(head, out)
        return "done", out[-4000:]

    def _patch_apt(self, excludes):
        # Excludes were already applied as holds in stage_excludes — no
        # --exclude-equivalent flag needed here, apt-get upgrade skips held
        # packages on its own.
        rc, out = run_cmd(["apt-get", *self._APT_LOCK_OPTS, "update"], dry_run=self.dry_run, timeout=300,
                          env=self._apt_env())
        if rc != 0 and not self.dry_run:
            return "failed", "apt-get update failed, so nothing was upgraded:\n" + out[-3000:]
        notes = []
        wanted = (self._severity_filter or "").strip().lower()

        if wanted in ("", "all"):
            cmd = ["apt-get", "-y", *self._APT_DPKG_OPTS, "upgrade"]
        else:
            if self._severity_levels():
                notes.append(
                    "apt publishes no per-advisory severity, so this ran as security-only "
                    f"rather than restricted to {self._severity_filter}."
                )
            assessment = _assess_apt()
            if not assessment["ok"]:
                return "failed", f"could not determine which updates are security: {assessment['error']}"
            packages = sorted({u["package"] for u in assessment["updates"] if u["is_security"]})
            if not packages:
                return "done", "\n".join(notes + ["No security updates pending; nothing installed."])
            # --only-upgrade so a named package that isn't installed is not
            # pulled in as a new dependency of this run.
            cmd = ["apt-get", "-y", *self._APT_DPKG_OPTS, "install", "--only-upgrade", *packages]

        rc2, out2 = run_cmd(cmd, dry_run=self.dry_run, timeout=3600, env=self._apt_env())
        combined = "\n".join(notes + [out, out2]).strip()
        if rc2 != 0 and not self.dry_run:
            return "failed", combined[-4000:]
        held = apt_held_back_summary(parse_apt_held_back(out2))
        if held:
            return "done", _with_summary(held, combined)
        return "done", combined[-4000:]

    def stage_reboot(self, job_id, excludes):
        if self.pkg_manager == "dnf":
            rc, out = run_cmd(["needs-restarting", "-r"], dry_run=self.dry_run, timeout=30)
            reboot_needed = rc != 0
        elif self.pkg_manager == "apt":
            # Standard Debian/Ubuntu convention -- apt itself (and
            # unattended-upgrades) writes this file when an installed
            # package (typically a new kernel) needs a reboot to take
            # effect. A plain existence check, no subprocess needed.
            reboot_needed = os.path.exists("/var/run/reboot-required")
        else:
            return "failed", "no supported package manager found (dnf or apt-get)"

        if not reboot_needed:
            return "done", "no reboot required"

        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w") as f:
            json.dump({"job_id": job_id, "requested_at": datetime.now(timezone.utc).isoformat(),
                       "boot_id": _boot_id()}, f)

        if self.dry_run:
            log.info("[dry-run] would reboot now")
            os.remove(STATE_PATH)
            return "done", "[dry-run] reboot skipped"

        log.info("reboot required — rebooting now, agent will resume this stage on next start")
        rc, out = run_cmd(["systemctl", "reboot"], dry_run=False, timeout=60)
        if rc != 0:
            os.remove(STATE_PATH)
            return "failed", f"the reboot was refused (rc={rc}): {out}"
        return "deferred", ""

    def _capture_container_image(self, container):
        """
        Tag the image a container is running right now, so the update
        about to happen can be undone.

        Capturing the image is a complete rollback point for a compose
        service specifically: the compose file supplies ports, env,
        volumes and restart policy, and volumes persist across
        recreation, so the image is the only thing an update changes.

        `docker tag` copies nothing — it is a second name for an image
        already on disk. The cost is that the old image stops being
        garbage-collectable, which is the entire point, and is bounded to
        one image per service.

        NOT captured: anything a container wrote into a volume. If a new
        image migrates a schema on start, rolling the image back will not
        unmigrate it.
        """
        name = container.get("name")
        tag = rollback_tag(container.get("compose_project"), container.get("compose_service"))
        rc, image_id = self._runtime_cmd(["container", "inspect", name, "--format", "{{.Image}}"])
        if rc != 0 or not image_id.strip():
            return None, f"could not read the current image of {name}: {image_id}"
        rc, out = self._runtime_cmd(["tag", image_id.strip(), tag])
        if rc != 0:
            return None, f"could not capture {name}: {out}"
        return tag, f"captured {name} as {tag}"

    def _restore_container_image(self, container):
        """
        Point the compose file's own image reference back at the captured
        image, so the recreate that follows brings the previous version
        back.

        Re-tagging rather than editing the project: compose resolves the
        image by the name written in its file, so moving that name onto
        the captured id is what makes `up -d` see a changed image and
        recreate. The project on disk is never modified.
        """
        name = container.get("name")
        image_ref = container.get("image") or ""
        tag = rollback_tag(container.get("compose_project"), container.get("compose_service"))
        if not image_ref:
            return False, f"{name}: no image reference recorded, nothing to restore onto"
        if "@sha256:" in image_ref:
            # A digest names exact content, so there is no tag to move —
            # and a digest-pinned service was never updated to begin with.
            return False, f"{name}: cannot restore a digest-pinned reference ({image_ref})"
        rc, out = run_cmd([self.container_runtime, "image", "inspect", tag, "--format", "{{.Id}}"],
                          dry_run=self.dry_run, timeout=30)
        if rc != 0:
            return False, f"{name}: no capture to restore ({tag} not present)"
        rc, out = run_cmd([self.container_runtime, "tag", tag, image_ref],
                          dry_run=self.dry_run, timeout=30)
        if rc != 0:
            return False, f"{name}: could not restore {tag} onto {image_ref}: {out}"
        return True, f"restored {image_ref} from {tag}"

    # Just after a reboot the runtime is still starting, and restarting
    # every container with a restart policy; until it settles, even
    # `inspect` can block. Wait for it to answer before touching anything,
    # and give the read/tag calls a few slow attempts rather than one.
    RUNTIME_READY_WAIT = 300
    RUNTIME_CMD_TIMEOUT = 90
    RUNTIME_CMD_ATTEMPTS = 3

    def _wait_for_runtime(self):
        """(ready, seconds waited). Polls `<runtime> info` until it answers."""
        if self.dry_run:
            return True, 0
        start = time.monotonic()
        while True:
            rc, _ = run_cmd([self.container_runtime, "info", "--format", "{{.ServerVersion}}"], timeout=30)
            waited = int(time.monotonic() - start)
            if rc == 0:
                return True, waited
            if waited >= self.RUNTIME_READY_WAIT:
                return False, waited
            time.sleep(5)

    def _runtime_cmd(self, args):
        """A quick runtime call, retried while the runtime is slow to answer."""
        rc, out = 1, ""
        for attempt in range(self.RUNTIME_CMD_ATTEMPTS):
            rc, out = run_cmd([self.container_runtime] + args, dry_run=self.dry_run, timeout=self.RUNTIME_CMD_TIMEOUT)
            if rc == 0 or "timed out" not in out:
                return rc, out
            if attempt < self.RUNTIME_CMD_ATTEMPTS - 1:
                time.sleep(10)
        return rc, out

    def _compose_args(self, item):
        """
        The `compose` options that address this container's project the way
        it was brought up: its -p name, --project-directory, every -f file
        and --env-file, read from the container's own labels. `inspect`
        gives them as JSON; the label list in `ps` output is comma-joined,
        and the files label is itself a comma-separated list. Falls back
        to what the inventory reported when the container can't be
        inspected (gone, or the runtime slow).
        """
        labels = {}
        rc, out = run_cmd([self.container_runtime, "container", "inspect", item.get("name", ""),
                           "--format", "{{json .Config.Labels}}"], dry_run=self.dry_run, timeout=60)
        if rc == 0 and not self.dry_run:
            try:
                labels = json.loads(out.strip() or "{}") or {}
            except ValueError:
                labels = {}
        project = labels.get(_COMPOSE_PROJECT_LABEL) or item.get("compose_project") or ""
        workdir = labels.get(_COMPOSE_WORKDIR_LABEL) or item.get("compose_working_dir") or ""
        args = ["--project-directory", workdir]
        if project:
            args += ["-p", project]
        for path in filter(None, (labels.get(_COMPOSE_FILES_LABEL) or "").split(",")):
            args += ["-f", path]
        for path in filter(None, (labels.get(_COMPOSE_ENV_FILES_LABEL) or "").split(",")):
            args += ["--env-file", path]
        return tuple(args)

    def stage_containers(self, job_id, containers):
        """
        Update the containers this run selected.

        Only compose-managed ones. `docker pull` alone would change
        nothing — a running container keeps its old image until it is
        recreated — and recreating anything else cannot be done safely:
        a standalone container's `docker run` flags are not recorded
        anywhere, and an orchestrated one belongs to its orchestrator.
        The controller filters to compose before sending this list; this
        re-checks rather than trusting it, because acting on the wrong
        container here destroys a running service.

        Work is grouped by compose project, since `pull` and `up -d` act
        on a whole project at once — updating four services of the same
        project individually would recreate it four times.

        An update captures each service's current image first (see
        _capture_container_image) so it can be undone. A rollback puts
        that capture back and recreates. Both end in the same `up -d`,
        because recreating is what actually changes what is running.
        """
        if not self.container_runtime:
            return "failed", "no container runtime on this host (docker/podman/nerdctl not found)"

        # A dict payload carries its own action; a bare list is the
        # shape an older controller sends, and means an update.
        if isinstance(containers, dict):
            action = containers.get("action") or "update"
            containers = containers.get("containers") or []
        else:
            action = self._container_action

        skipped, wanted = [], []
        for item in containers or []:
            workdir = item.get("compose_working_dir") or ""
            service = item.get("compose_service") or ""
            if item.get("managed_by") != "compose" or not workdir or not service:
                skipped.append(item.get("name", "?"))
                continue
            wanted.append(item)

        if not wanted:
            detail = f"; not compose-managed: {', '.join(skipped)}" if skipped else ""
            return "failed", f"no updatable containers in this run's selection{detail}"

        eligible = [item for item in (containers or [])
                    if item.get("managed_by") == "compose"
                    and item.get("compose_working_dir") and item.get("compose_service")]

        lines = []
        ready, waited = self._wait_for_runtime()
        if not ready:
            return "failed", (f"{self.container_runtime} did not answer for {waited}s "
                              "(still starting after a reboot?); nothing was changed")
        if waited >= 5:
            lines.append(f"waited {waited}s for {self.container_runtime} to be ready")

        if action == "rollback":
            restored_any = False
            for item in eligible:
                ok, note = self._restore_container_image(item)
                lines.append(note)
                restored_any = restored_any or ok
            if not restored_any and not self.dry_run:
                return "failed", ("\n".join(lines))[-4000:]
        else:
            # Capture before changing anything. A failure here fails the
            # stage rather than proceeding: updating without a way back is
            # exactly what this stage exists to avoid.
            for item in eligible:
                tag, note = self._capture_container_image(item)
                lines.append(note)
                if tag is None and not self.dry_run:
                    return "failed", ("\n".join(lines))[-4000:]

        # Grouped by how each project was brought up (its labels).
        projects = {}
        for item in wanted:
            projects.setdefault(self._compose_args(item), []).append(item["compose_service"])
        for compose_args, services in sorted(projects.items()):
            services = sorted(set(services))
            base = [self.container_runtime, "compose", *compose_args]

            if action != "rollback":
                # --ignore-pull-failures because a pull is preparation, not
                # the operation. A project that mixes pulled images with
                # locally built ones is ordinary, and an image that exists
                # in no registry can never be pulled — without this, one
                # such service aborts the stage before `up` runs and
                # nothing is updated at all. Failures stay in the output
                # rather than being hidden.
                pull = base + ["pull", "--ignore-pull-failures"] + services
                _, out = run_cmd(pull, dry_run=self.dry_run, timeout=1800)
                lines.append(f"$ {' '.join(pull)}\n{out}".strip())

            # This is the step that actually changes what's running:
            # compose recreates a service whose image or config no longer
            # matches, and leaves the rest alone. Its failure is a real one.
            up = base + ["up", "-d", "--no-deps"] + services
            rc, out = run_cmd(up, dry_run=self.dry_run, timeout=1800)
            lines.append(f"$ {' '.join(up)}\n{out}".strip())
            if rc != 0 and not self.dry_run:
                return "failed", ("\n\n".join(lines))[-4000:]

        if skipped:
            lines.append(f"skipped (not compose-managed): {', '.join(skipped)}")
        return "done", ("\n\n".join(lines))[-4000:]

    def stage_healthcheck(self, job_id, excludes):
        """
        `systemctl --failed` exits 0 whether or not any units failed — it's
        a list command — so a non-zero rc means the CHECK didn't run, not
        that the host is unhealthy. Those are different outcomes and must
        not share a message.

        This used to ignore rc entirely and treat any non-empty output as
        failed units, which produced "failed systemd units present:
        command not found: ... 'systemctl'" on a host without systemd —
        a confident, wrong diagnosis. It also had the dangerous inverse:
        a systemctl that errored while printing nothing was reported as a
        clean healthcheck, marking the run healthy on the strength of a
        check that never happened.
        """
        rc, out = run_cmd(["systemctl", "--failed", "--no-legend"], dry_run=self.dry_run, timeout=30)
        if self.dry_run:
            return "done", out
        if rc != 0:
            return "failed", f"could not run the healthcheck (systemctl exited {rc}): {out}"
        if out.strip():
            return "failed", f"failed systemd units present: {out}"
        return "done", "no failed systemd units"

    # ---------- main loop ----------
    def ensure_signed_repo(self):
        """
        Once the controller signs the agent's dnf repo, have dnf check it:
        install the controller's public key and set gpgcheck=1 and
        repo_gpgcheck=1 in this host's kite.repo. Hosts enrolled
        before signing existed were set up with gpgcheck=0; this moves
        them over without anyone editing the file by hand.

        The key is taken from the controller once, the first time it's
        offered (the same trust as the enrolment itself), and never
        replaced afterwards: a different key later is refused and logged,
        since accepting it silently would undo the point of signing.
        Returns a note for the log, or "" when there was nothing to do.
        """
        if self.pkg_manager != "dnf" or not os.path.exists(REPO_FILE):
            return ""
        with open(REPO_FILE) as f:
            text = f.read()
        if re.search(r"^\s*gpgcheck\s*=\s*1\s*$", text, re.MULTILINE):
            return ""
        try:
            key = self.session.get(f"{self.base}/repo/RPM-GPG-KEY-kite", timeout=30)
            index_sig = self.session.get(f"{self.base}/repo/repodata/repomd.xml.asc", timeout=30)
        except requests.RequestException as e:
            return f"repo signing: controller not reachable ({e})"
        if key.status_code != 200 or index_sig.status_code != 200 or "BEGIN PGP PUBLIC KEY BLOCK" not in key.text:
            return ""   # the controller's repo isn't signed (yet): nothing to switch on
        if os.path.exists(REPO_KEY_PATH):
            with open(REPO_KEY_PATH) as f:
                if f.read().strip() != key.text.strip():
                    log.error("repo signing: the controller now offers a different signing key than the one "
                              "installed at %s; not switching. If the controller was reinstalled, remove "
                              "that file and restart the agent.", REPO_KEY_PATH)
                    return "repo signing: key mismatch, left as it was"
        if self.dry_run:
            return f"[dry-run] would install the repo key at {REPO_KEY_PATH} and set gpgcheck=1 in {REPO_FILE}"
        os.makedirs(os.path.dirname(REPO_KEY_PATH), exist_ok=True)
        with open(REPO_KEY_PATH, "w") as f:
            f.write(key.text)
        os.chmod(REPO_KEY_PATH, 0o644)
        rc, out = run_cmd(["rpm", "--import", REPO_KEY_PATH], timeout=60)
        if rc != 0:
            return f"repo signing: couldn't import the key: {out}"
        new_text = _set_repo_options(text, ["gpgcheck=1", "repo_gpgcheck=1", f"gpgkey=file://{REPO_KEY_PATH}"],
                                     ["gpgcheck", "repo_gpgcheck", "gpgkey"])
        tmp = REPO_FILE + ".kite-new"
        with open(tmp, "w") as f:
            f.write(new_text)
        os.replace(tmp, REPO_FILE)
        return f"repo signing: dnf now checks the agent repo's signatures (key at {REPO_KEY_PATH})"

    def pin_controller_ca(self):
        """
        An agent enrolled with --insecure (certificate checks off) starts
        checking the controller's certificate once it can:

          - when the controller publishes its own root CA (its default,
            self-signed setup), that root is taken once, over the
            connection this agent already trusts, and from then on every
            call is checked against it alone;
          - when it doesn't (a public certificate, Let's Encrypt), the
            system's own CAs are used.

        Only after a request checked that way has succeeded: a switch that
        locked the agent out of its controller would be worse than none.
        The dnf repo file gets the same check. Returns a note for the
        log, or "" when there was nothing to do.
        """
        if self.session.verify is not False:
            return self._check_repo_tls()
        try:
            resp = self.session.get(f"{self.base}/download/ca.crt", timeout=30)
        except requests.RequestException as e:
            return f"controller certificate: controller not reachable ({e})"
        pem, verify = "", True
        if resp.status_code == 200:
            pem = resp.text
            try:
                ssl.PEM_cert_to_DER_cert(pem)
            except ValueError:
                return "controller certificate: the controller's CA download isn't a certificate; checks stay off"
            tmp = CA_PATH + ".new"
            if not self.dry_run:
                os.makedirs(os.path.dirname(CA_PATH), exist_ok=True)
                with open(tmp, "w") as f:
                    f.write(pem)
                os.chmod(tmp, 0o644)
            verify = tmp
        if self.dry_run:
            return f"[dry-run] would check the controller's certificate against {'its CA' if pem else 'the system CAs'}"
        try:
            requests.get(f"{self.base}/health", timeout=30, verify=verify).raise_for_status()
        except requests.RequestException as e:
            if pem:
                os.remove(verify)
            return f"controller certificate: still not checked: a checked request failed ({e})"
        updates = {"verify_tls": True}
        if pem:
            os.replace(verify, CA_PATH)
            updates["ca_cert"] = verify = CA_PATH
        self._update_config(updates)
        self.session.verify = verify
        note = self._check_repo_tls()
        return ("controller certificate: now checked against " + ("its CA at " + CA_PATH if pem else "the system CAs")
                + (f"; {note}" if note else ""))

    def _update_config(self, updates):
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        config.update(updates)
        tmp = CONFIG_PATH + ".new"
        with open(tmp, "w") as f:
            json.dump(config, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_PATH)

    def _check_repo_tls(self):
        """Have dnf check the controller's certificate too, as this agent now does."""
        if self.pkg_manager != "dnf" or self.session.verify is False or not os.path.exists(REPO_FILE):
            return ""
        with open(REPO_FILE) as f:
            text = f.read()
        if not re.search(r"^\s*sslverify\s*=\s*0\s*$", text, re.MULTILINE):
            return ""
        lines = ["sslverify=1"] + ([f"sslcacert={self.session.verify}"] if isinstance(self.session.verify, str) else [])
        if self.dry_run:
            return f"[dry-run] would set {', '.join(lines)} in {REPO_FILE}"
        tmp = REPO_FILE + ".kite-new"
        with open(tmp, "w") as f:
            f.write(_set_repo_options(text, lines, ["sslverify", "sslcacert"]))
        os.replace(tmp, REPO_FILE)
        return f"dnf checks the repo's certificate too ({REPO_FILE})"

    # How long to wait for a reboot this agent asked for before asking again.
    REBOOT_WAIT_SECONDS = 600

    def loop(self):
        # Start-up housekeeping: a failure in any of these is logged and
        # the agent carries on -- it must never keep the agent from polling.
        for step in (self.resume_pending_reboot, self.pin_controller_ca, self.ensure_signed_repo):
            try:
                note = step()
            except Exception as e:  # noqa: BLE001
                log.error("%s failed: %s", step.__name__, e)
                continue
            if note:
                log.info("%s", note)
        log.info("entering poll loop: baseline interval=%ss, local trigger=%s", self.poll_interval, TRIGGER_PATH)
        while True:
            self.resume_pending_reboot()
            if self.reboot_pending():
                # The reboot stage asked for one. Polling now would be handed
                # that stage again and reboot a second time; wait for it.
                log.info("waiting for the reboot this agent asked for")
                time.sleep(self.REBOOT_WAIT_SECONDS)
                if self.reboot_pending():
                    log.warning("the host hasn't rebooted %ss after it was asked to; asking again",
                                self.REBOOT_WAIT_SECONDS)
                    try:
                        os.remove(STATE_PATH)
                    except OSError:
                        pass
                continue
            instruction, ok, self_update_target = self.poll_next()
            if not ok:
                # The request itself failed (network, controller down) —
                # short backoff so a broken connection doesn't turn into a
                # tight error loop, but still checks the trigger file while
                # waiting, in case someone's trying to force a check-in.
                self._sleep_with_trigger_check(self.error_backoff)
                continue
            if instruction:
                self.run_stage(instruction)
                continue  # just did work — check again right away instead of sleeping the full interval
            if self_update_target:
                # Only reaches here when the poll was otherwise idle (the
                # controller never sets this header alongside a real
                # instruction) — safe to act on immediately rather than
                # waiting out the full poll_interval. When nothing was
                # installed (failed, or tried within the hour) this is an
                # ordinary idle poll: going straight back to the
                # controller would ask it again in a tight loop.
                if self.self_update(self_update_target):
                    continue
            # Idle: nothing to execute, so this is the cheapest moment to
            # refresh inventory. Never runs alongside a job stage.
            self.report_containers()
            log.info("poll ok — no pending job stage, sleeping up to %ss (or until triggered)", self.poll_interval)
            self._sleep_with_trigger_check(self.poll_interval)


def main():
    parser = argparse.ArgumentParser(description="kite agent")
    parser.add_argument("--dry-run", action="store_true", help="log intended commands instead of executing them")
    parser.add_argument("--once", action="store_true", help="poll a single time and exit (for testing)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    config = load_config()
    agent = Agent(config, dry_run=args.dry_run)

    if args.once:
        agent.resume_pending_reboot()
        instruction, ok, self_update_target = agent.poll_next()
        if not ok:
            log.warning("poll request failed")
        elif instruction:
            agent.run_stage(instruction)
        elif self_update_target:
            agent.self_update(self_update_target)
        else:
            log.info("no pending job stage for this host")
            agent.report_containers()
        return

    agent.loop()


if __name__ == "__main__":
    main()
