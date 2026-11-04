"""
Which Linux agent builds this controller publishes, and which version a
host should be running.

The dnf repo under REPO_DIR is the source of truth: a version is
"published" when its RPM is there. Updating agents from the console sets
a target -- for the whole fleet (Settings' agent_target_version) or for
one host (Host.agent_update_to, which wins) -- and the agent upgrades
itself on its next idle poll (routers/agent.py's SELF_UPDATE_HEADER).
Only ever upward: a host already on a newer build is left alone, so a
stale target can't make agents reinstall or downgrade on every poll.

Three channels: RHEL-family agents upgrade from the dnf repo (REPO_DIR);
Debian/Ubuntu agents, which have no apt repo, reinstall from the
controller's agent bundle (DIST_DIR/kite-agent-linux.tar.gz); Windows
agents (0.5.0+) replace their exe with DIST_DIR/kite-agent.exe. For
the last two, "published" is the one version that file holds. Since 0.6.0
both agents share one version number (tests/test_agent_versions.py keeps
them in step); the fleet-wide target is "latest" -- each agent to the
newest build for its OS -- so a controller serving builds from different
releases still does the right thing.
"""
import hashlib
import os
import re
import shutil
import tarfile
from pathlib import Path

from sqlalchemy.orm import Session

from . import models
from .settings_store import get_setting

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# KITE_REPO_DIR is overridable so the Docker image can point it at a mounted
# volume instead of the (ephemeral, inside-the-image) default. `or`,
# not `.get(..., default)` -- .env.example ships this blank, and a blank
# *set* env var should fall through to the default too.
REPO_DIR = Path(os.environ.get("KITE_REPO_DIR") or (PROJECT_ROOT / "repo"))
# Same override shape, for the downloads (routers/downloads.py) and the bundle.
DIST_DIR = Path(os.environ.get("KITE_DIST_DIR") or (PROJECT_ROOT / "dist"))
LINUX_AGENT_BUNDLE = "kite-agent-linux.tar.gz"

_RPM = re.compile(r"^kite-agent-(\d+(?:\.\d+)*)-[^-]+\.noarch\.rpm$")
_BUNDLE_VERSION = re.compile(rb'^AGENT_VERSION = "(\d+(?:\.\d+)*)"', re.MULTILINE)
_APT_FAMILIES = ("debian", "ubuntu")
_bundle_cache = {}
_exe_cache = {}
WINDOWS_AGENT = "kite-agent.exe"
# The Docker image carries the agents it was built with here (see the
# Dockerfile); seed_agents() copies newer ones into the data volume.
SEED_DIR = os.environ.get("KITE_AGENT_SEED_DIR", "")
LATEST = "latest"
# Windows agents before this only log a self-update request.
_WINDOWS_SELF_UPDATE_FROM = (0, 5, 0)


def version_key(v: str):
    return tuple(int(p) for p in re.findall(r"\d+", v or ""))


def published(repo_dir: Path = None) -> list:
    """Versions with an RPM in the repo, newest first."""
    d = repo_dir or REPO_DIR
    try:
        names = os.listdir(d)
    except OSError:
        return []
    found = {m.group(1) for m in (_RPM.match(n) for n in names) if m}
    return sorted(found, key=version_key, reverse=True)


def bundle_info(dist_dir: Path = None) -> dict:
    """{version, sha256} of the Debian/Ubuntu agent bundle, or {} when there isn't one. Cached per file."""
    path = (dist_dir or DIST_DIR) / LINUX_AGENT_BUNDLE
    try:
        st = path.stat()
    except OSError:
        return {}
    key = (str(path), st.st_mtime, st.st_size)
    if key not in _bundle_cache:
        data = path.read_bytes()
        version = ""
        try:
            with tarfile.open(path, "r:gz") as tar:
                m = _BUNDLE_VERSION.search(tar.extractfile("agent-linux/agent.py").read())
                version = m.group(1).decode() if m else ""
        except (tarfile.TarError, KeyError, OSError, AttributeError):
            pass
        _bundle_cache.clear()
        _bundle_cache[key] = {"version": version, "sha256": hashlib.sha256(data).hexdigest()} if version else {}
    return _bundle_cache[key]


def windows_info(dist_dir: Path = None) -> dict:
    """{version, sha256} of the Windows agent exe, from its .version file (written by build.sh); {} without one."""
    d = dist_dir or DIST_DIR
    exe, ver = d / WINDOWS_AGENT, d / (WINDOWS_AGENT + ".version")
    try:
        st, version = exe.stat(), ver.read_text().strip()
    except OSError:
        return {}
    if not re.fullmatch(r"\d+(\.\d+)*", version):
        return {}
    key = (str(exe), st.st_mtime, st.st_size, version)
    if key not in _exe_cache:
        digest = hashlib.sha256()
        with exe.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        _exe_cache.clear()
        _exe_cache[key] = {"version": version, "sha256": digest.hexdigest()}
    return _exe_cache[key]


def _channel(host: models.Host) -> str:
    """'rpm', 'bundle' or 'exe' -- where this host's agent updates from."""
    fam = (host.os_family or "").lower()
    if fam.startswith("windows"):
        return "exe"
    return "bundle" if fam.startswith(_APT_FAMILIES) else "rpm"


def latest_for(host: models.Host) -> str:
    """The newest version this host's agent could update itself to."""
    ch = _channel(host)
    if ch == "bundle":
        return bundle_info().get("version", "")
    if ch == "exe":
        return windows_info().get("version", "")
    versions = published()
    return versions[0] if versions else ""


def can_self_update(host: models.Host) -> bool:
    """
    RHEL family: always (the dnf repo may be hosted elsewhere, so an empty
    local repo doesn't mean there's nothing to install). Debian/Ubuntu: when
    this controller has a bundle. Windows: no.
    """
    ch = _channel(host)
    if not host.agent_version:
        return False
    if ch == "rpm":
        return True
    if ch == "exe" and version_key(host.agent_version) < _WINDOWS_SELF_UPDATE_FROM:
        return False
    return bool(latest_for(host))


def target_for(db: Session, host: models.Host, fleet_target: str = None) -> str:
    """
    The version this host should move to, or '' when it's where it should be.
    `fleet_target`: the agent_target_version setting, when the caller already has it.
    """
    want = host.agent_update_to or (get_setting(db, "agent_target_version") if fleet_target is None else fleet_target)
    if not want or not host.agent_version or not can_self_update(host):
        return ""
    if want == LATEST:
        want = latest_for(host)
        if not want:
            return ""
    # The bundle and the exe hold exactly one version each: it's that or nothing.
    if _channel(host) in ("bundle", "exe") and want != latest_for(host):
        return ""
    return want if version_key(want) > version_key(host.agent_version) else ""


def fleet_status(db: Session) -> dict:
    """What the console needs: what's published, the fleet target, and who's behind."""
    versions = published()
    bundle = bundle_info().get("version", "")
    windows = windows_info().get("version", "")
    latest = max([v for v in (versions[:1] + [bundle]) if v], key=version_key, default="")   # Linux line
    hosts = db.query(models.Host).all()
    fleet_target = get_setting(db, "agent_target_version")
    rows = []
    for h in hosts:
        if not h.agent_version:
            continue
        mine = latest_for(h)
        behind = bool(mine) and version_key(h.agent_version) < version_key(mine)
        rows.append({
            "host_id": h.id, "hostname": h.hostname, "agent_version": h.agent_version,
            "latest": mine, "can_self_update": can_self_update(h), "behind": behind,
            "updating_to": target_for(db, h, fleet_target),
        })
    return {
        "published": versions,
        "bundle": bundle,
        "windows": windows,
        "latest": latest,
        "fleet_target": fleet_target,
        "hosts": rows,
    }


def seed_agents(seed_dir: Path, dist_dir: Path = None, repo_dir: Path = None) -> list:
    """
    Copy the agents an image was built with (seed_dir/dist, seed_dir/repo)
    into the served directories where they are newer than what is there:
    so a fresh Docker install can enroll machines straight away, and
    `docker compose up --build` after an upgrade hands out the new agents
    too. Never replaces a newer agent someone placed by hand. Returns what
    was copied.
    """
    dist, repo = dist_dir or DIST_DIR, repo_dir or REPO_DIR
    seed_dist, seed_repo = seed_dir / "dist", seed_dir / "repo"
    copied = []
    dist.mkdir(parents=True, exist_ok=True)
    repo.mkdir(parents=True, exist_ok=True)

    new = bundle_info(seed_dist).get("version", "")
    if new and version_key(new) > version_key(bundle_info(dist).get("version", "")):
        shutil.copy2(seed_dist / LINUX_AGENT_BUNDLE, dist / LINUX_AGENT_BUNDLE)
        copied.append(f"{LINUX_AGENT_BUNDLE} {new}")

    new = windows_info(seed_dist).get("version", "")
    if new and version_key(new) > version_key(windows_info(dist).get("version", "")):
        for f in sorted(seed_dist.glob("kite-agent*")):
            if f.name != LINUX_AGENT_BUNDLE:
                shutil.copy2(f, dist / f.name)
        copied.append(f"{WINDOWS_AGENT} {new}")

    added = [f for f in sorted(seed_repo.glob("*.rpm")) if not (repo / f.name).exists()]
    newest = published(seed_repo)
    if added and newest and version_key(newest[0]) > version_key((published(repo) or [""])[0]):
        for f in added:
            shutil.copy2(f, repo / f.name)
        # the image's metadata lists its own RPM, the newest; older ones stay on disk unlisted
        if (seed_repo / "repodata").is_dir():
            shutil.rmtree(repo / "repodata", ignore_errors=True)
            shutil.copytree(seed_repo / "repodata", repo / "repodata")
        for key in seed_repo.glob("RPM-GPG-KEY-*"):
            shutil.copy2(key, repo / key.name)
        copied.append(f"agent RPM {newest[0]}")
    return copied
