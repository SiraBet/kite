"""
Agent downloads.

The Windows agent is a single executable rather than a package in a repo:
Windows has no dnf, and telling an operator to unzip a folder and run a
script does not scale past a handful of hosts. So the controller hands
out the binary the same way Wazuh and Qualys do — you fetch the installer
from the console you already have open, run it on the host, and it enrols
itself.

Two endpoints, deliberately with different access:

- the manifest is session-authenticated, because it is console data and
  says what this particular controller can actually hand out;
- the binary itself is not, because the host downloading it has no
  session and cannot get one. It carries no secrets — enrolling still
  needs a token or the shared secret — and this is the same reasoning
  under the unauthenticated /repo mount that serves the RPM.
"""
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import agent_package, agent_releases, controller_ca, models, repo_signing
from ..auth import get_current_user
from ..db import get_db
from ..security import hash_secret

router = APIRouter(tags=["downloads"])

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DIST_DIR = agent_releases.DIST_DIR   # KITE_DIST_DIR, see app/agent_releases.py

BUILD_COMMAND = "agent-windows/build.sh"

# The Debian/Ubuntu agent has no compiled binary or installer — it is the
# same agent.py/enroll.py the RPM carries, just laid down by
# install-debian.sh. So the controller hands out a small source bundle
# instead, which the Debian enrol command fetches directly rather than
# cloning the (possibly private, and heavier) git repository onto every
# host. Staged into DIST_DIR by build-release.sh / controller-install.sh.
LINUX_AGENT_BUNDLE = agent_releases.LINUX_AGENT_BUNDLE
LINUX_BUNDLE_COMMAND = "build-release.sh (or copy agent-linux/ there)"


class AgentArtifact(BaseModel):
    """One downloadable build, and whether this controller has it."""
    platform: str
    label: str
    filename: str
    available: bool
    url: str
    # The installer alongside the bare agent. Absent when this install
    # has not built one.
    installer_filename: Optional[str] = None
    installer_available: bool = False
    installer_url: Optional[str] = None
    installer_size_bytes: Optional[int] = None
    installer_sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    sha256: Optional[str] = None
    built_at: Optional[datetime] = None
    # Populated only when the file is missing. A console that says "not
    # available" without saying why sends someone hunting; this says what
    # to run and on which machine.
    build_command: Optional[str] = None
    # The dnf repo only: whether hosts can check signatures (app/repo_signing.py).
    signed: Optional[bool] = None


# Two artifacts per platform. The installer is what an operator should
# download -- it registers the service, writes the Apps & features entry
# and enrols the host. The bare agent is kept downloadable for anyone
# placing it by hand or scripting around the installer entirely.
CATALOG = {
    "windows": {
        "label": "Windows Server / 10 / 11 (x86-64)",
        "filename": "kite-agent.exe",
        "installer": "kite-agent-setup.exe",
    },
}


def _describe(platform: str) -> AgentArtifact:
    entry = CATALOG[platform]
    artifact = AgentArtifact(
        platform=platform, label=entry["label"], filename=entry["filename"],
        available=False, url=f"/download/agent/{platform}",
        installer_filename=entry["installer"],
        installer_url=f"/download/installer/{platform}",
    )

    installer = DIST_DIR / entry["installer"]
    try:
        stat = installer.stat()
        artifact.installer_available = True
        artifact.installer_size_bytes = stat.st_size
        artifact.installer_sha256 = _checksum(installer)
    except OSError:
        pass

    try:
        stat = (DIST_DIR / entry["filename"]).stat()
    except OSError:
        artifact.build_command = BUILD_COMMAND
        return artifact
    artifact.available = True
    artifact.size_bytes = stat.st_size
    artifact.built_at = datetime.utcfromtimestamp(stat.st_mtime)
    artifact.sha256 = _checksum(DIST_DIR / entry["filename"])
    if not artifact.installer_available:
        artifact.build_command = BUILD_COMMAND
    return artifact


def _checksum(path: Path) -> Optional[str]:
    """
    Read from the .sha256 written at build time if it is there, and hash
    the file otherwise. Hashing 8MB on every manifest request would be
    wasteful, but a missing sidecar file must not blank out the checksum
    the console shows people to verify against.
    """
    sidecar = path.with_suffix(path.suffix + ".sha256")
    try:
        first = sidecar.read_text().split()[0]
        if len(first) == 64:
            return first
    except (OSError, IndexError):
        pass
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _describe_linux_bundle() -> AgentArtifact:
    """
    The Linux agent ships as a source bundle rather than a built binary, so
    it isn't in CATALOG. It is still something this controller either has or
    hasn't got, and the console needs to know which before offering a
    download link that would 404.
    """
    path = DIST_DIR / LINUX_AGENT_BUNDLE
    artifact = AgentArtifact(
        platform="linux", label="Ubuntu / Debian (source bundle)",
        filename=LINUX_AGENT_BUNDLE, available=False,
        url="/download/agent-linux",
    )
    if path.is_file():
        stat = path.stat()
        artifact.available = True
        artifact.size_bytes = stat.st_size
        artifact.sha256 = _checksum(path)
        artifact.built_at = datetime.utcfromtimestamp(stat.st_mtime)
    else:
        artifact.build_command = LINUX_BUNDLE_COMMAND
    return artifact


@router.get("/download/agents", response_model=List[AgentArtifact])
def list_agent_downloads(user: models.User = Depends(get_current_user)):
    """What this controller can hand out, and what it is missing."""
    # Windows first: existing callers index [0] for it.
    return [_describe(platform) for platform in CATALOG] + [_describe_linux_bundle(), _describe_rpm_repo()]


def _describe_rpm_repo() -> AgentArtifact:
    """The RHEL-family dnf repo: the newest RPM in it, and whether it's signed."""
    versions = agent_releases.published()
    rpms = sorted(agent_releases.REPO_DIR.glob(f"kite-agent-{versions[0]}-*.rpm")) if versions else []
    artifact = AgentArtifact(platform="rhel", label="RHEL / Rocky / AlmaLinux (dnf repo)",
                             filename=rpms[0].name if rpms else "", available=bool(rpms), url="/repo",
                             signed=repo_signing.repo_signed(agent_releases.REPO_DIR))
    if not rpms:
        artifact.build_command = "agent-linux/packaging/build.sh"
    return artifact


@router.get("/download/ca")
def controller_ca_info(user: models.User = Depends(get_current_user)):
    """For the enrol commands: whether there's a CA to pin, and its fingerprint."""
    return controller_ca.describe()


@router.get("/download/ca.crt")
def download_controller_ca():
    """
    The root agents check the controller's HTTPS against (app/controller_ca.py).
    Unauthenticated: it's a public certificate, and the enrol command
    checks its fingerprint before trusting it.
    """
    pem = controller_ca.current()
    if not pem:
        raise HTTPException(404, "This controller's certificate is from a public CA; agents check it the usual way")
    return Response(content=pem, media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="kite-controller-ca.crt"'})


@router.get("/download/agent/{platform}")
def download_agent(platform: str):
    """
    The binary. Unauthenticated on purpose — see the module docstring.
    """
    if platform not in CATALOG:
        raise HTTPException(404, f"No agent build for '{platform}'. Available: {', '.join(CATALOG)}")
    entry = CATALOG[platform]
    path = DIST_DIR / entry["filename"]
    if not path.is_file():
        # Not "there is no Windows agent" — there is one, this install
        # just has not built it. Saying which is the difference between a
        # two-minute fix and filing a bug.
        raise HTTPException(
            404,
            f"The {platform} agent has not been built into this install. "
            f"Run {BUILD_COMMAND} on the controller (it needs Go 1.23+, and cross-compiles "
            f"from Linux), or copy a {entry['filename']} built elsewhere into {DIST_DIR}.",
        )
    # What a Windows agent updating itself checks the download against.
    info = agent_releases.windows_info() if platform == "windows" else {}
    headers = {"X-Kite-Sha256": info["sha256"], "X-Kite-Agent-Version": info["version"]} if info else {}
    return FileResponse(path, media_type="application/octet-stream", filename=entry["filename"], headers=headers)


@router.get("/download/agent/{platform}/sha256")
def download_agent_checksum(platform: str):
    """
    The checksum on its own, so a host can verify the download without a
    session — `certutil -hashfile` on the host, compared against this.
    """
    if platform not in CATALOG:
        raise HTTPException(404, f"No agent build for '{platform}'")
    path = DIST_DIR / CATALOG[platform]["filename"]
    checksum = _checksum(path) if path.is_file() else None
    if not checksum:
        raise HTTPException(404, f"The {platform} agent has not been built into this install")
    return {"platform": platform, "filename": CATALOG[platform]["filename"], "sha256": checksum}


@router.get("/download/agent-linux")
def download_linux_agent():
    """
    The Debian/Ubuntu agent as a source bundle (agent.py, enroll.py, the
    unit file, install-debian.sh). Unauthenticated, same reasoning as the
    other agent artefacts: the host fetching it has no console session and
    the bundle carries no secrets. Lets a host install without cloning the
    repository — which matters while the repo is private, and is lighter
    besides.
    """
    path = DIST_DIR / LINUX_AGENT_BUNDLE
    if not path.is_file():
        raise HTTPException(
            404,
            f"The Linux agent bundle has not been staged into this install. "
            f"Run {LINUX_BUNDLE_COMMAND} on the controller, or (on a source checkout) "
            f"the git-clone path in the Ubuntu/Debian enrol command still works.",
        )
    # What a Debian/Ubuntu agent updating itself checks the download against.
    bundle = agent_releases.bundle_info()
    headers = {"X-Kite-Sha256": bundle["sha256"], "X-Kite-Agent-Version": bundle["version"]} if bundle else {}
    return FileResponse(path, media_type="application/gzip", filename=LINUX_AGENT_BUNDLE, headers=headers)


MCP_SERVER_SCRIPT = PROJECT_ROOT / "tools" / "kite_mcp.py"


@router.get("/download/mcp-server")
def download_mcp_server():
    """
    The local MCP server (tools/kite_mcp.py), so the command the
    console shows after creating an API token can fetch it from the
    controller the user is already looking at. Unauthenticated like the
    agent binaries: it is this project's own source, with no secret in
    it -- the token is what grants access, and that never travels here.
    """
    if not MCP_SERVER_SCRIPT.is_file():
        raise HTTPException(404, "tools/kite_mcp.py is missing from this install")
    return FileResponse(MCP_SERVER_SCRIPT, media_type="text/x-python", filename="kite_mcp.py")


@router.get("/download/installer/{platform}")
def download_installer(platform: str, request: Request, token: Optional[str] = None,
                        db: Session = Depends(get_db)):
    """
    The installer. With `token`, the copy handed back already knows this
    controller's address and carries that one-time token, so installing
    on the host is a double-click with nothing to type -- and nothing to
    mistype, which is where enrollment usually goes wrong.

    Unauthenticated, like the agent binary above: the host running this
    has no console session and cannot get one. Supplying a token grants
    nothing extra either, since whoever holds a token can already enroll
    with it directly.
    """
    if platform not in CATALOG:
        raise HTTPException(404, f"No installer for '{platform}'. Available: {', '.join(CATALOG)}")
    path = DIST_DIR / CATALOG[platform]["installer"]
    if not path.is_file():
        raise HTTPException(
            404,
            f"The {platform} installer has not been built into this install. "
            f"Run {BUILD_COMMAND} on the controller (it needs Go 1.23+, and cross-compiles "
            f"from Linux), or copy a {CATALOG[platform]['installer']} built elsewhere into {DIST_DIR}.",
        )
    if not token:
        return FileResponse(path, media_type="application/octet-stream",
                            filename=CATALOG[platform]["installer"])

    row = db.query(models.EnrollmentToken).filter(models.EnrollmentToken.token == hash_secret(token)).first()
    if not row:
        raise HTTPException(404, "Unknown enrollment token")
    if row.used:
        raise HTTPException(409, "That token has already been used — generate a new one")
    if row.expires_at and row.expires_at < datetime.utcnow():
        raise HTTPException(410, "That token has expired — generate a new one")

    # The address the console was reached on, so the installer points the
    # host at the same place the operator is looking at. Deriving it
    # rather than storing one means an install reached over a new name or
    # a new scheme keeps working without reconfiguration.
    base = str(request.base_url).rstrip("/")
    settings = {
        "controller_url": base,
        "token": token,   # the stored value is only its digest
        "hostname": row.hostname,
        "team": row.team,
        "role": row.role,
    }
    # The agent checks the controller's CA against this before enrolling,
    # and pins it (app/controller_ca.py).
    ca = controller_ca.describe()
    if ca["available"]:
        settings["ca_fingerprint"] = ca["sha256"]
    configured = agent_package.configure(path.read_bytes(), settings)
    safe_host = "".join(c for c in (row.hostname or "host") if c.isalnum() or c in "-_")
    return Response(
        content=configured,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="kite-agent-setup-{safe_host}.exe"'},
    )
