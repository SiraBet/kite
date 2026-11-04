"""
Signing the agent's dnf repository, so a RHEL-family host installs and
updates the agent only from packages this controller signed.

Hosts reach the repo over the controller's HTTPS with certificate checks
off (`sslverify=0`, for the default self-signed certificate), so the
signature is what stops a tampered package: the RPMs are signed
(`gpgcheck=1`) and so is the repo's index, repomd.xml (`repo_gpgcheck=1`).

The key is made once, here, on first start -- RSA 4096, which EL8's rpm
can verify -- and kept in STATE_DIR/signing, readable by the service
only. There's no passphrase: the controller signs unattended, and anyone
who could read the key could equally replace the packages it serves.
Every start (and `python -m app.repo_signing` after publishing an RPM by
hand) signs whatever isn't signed yet and re-signs the index.

Needs gpg, rpmsign (package rpm-sign) and createrepo_c; without them the
repo stays unsigned and the enrol command says so (gpgcheck=0).
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

from .config import STATE_DIR

KEY_DIR = Path(os.environ.get("KITE_SIGNING_DIR") or (STATE_DIR / "signing"))
PUBLIC_KEY = "RPM-GPG-KEY-kite"
TOOLS = ("gpg", "rpmsign", "createrepo_c")


def missing_tools() -> list:
    return [t for t in TOOLS if not shutil.which(t)]


def _run(args, **kw) -> str:
    env = dict(os.environ, GNUPGHOME=str(KEY_DIR))
    out = subprocess.run(args, env=env, capture_output=True, text=True, timeout=300, **kw)
    if out.returncode != 0:
        raise RuntimeError(f"{args[0]} failed: {(out.stderr or out.stdout).strip()[-500:]}")
    return out.stdout


def key_id() -> str:
    """The signing key's long id, or '' when there isn't one yet."""
    if not KEY_DIR.is_dir():
        return ""
    try:
        listing = _run(["gpg", "--batch", "--with-colons", "--list-secret-keys"])
    except RuntimeError:
        return ""
    m = re.search(r"^sec:[^:]*:[^:]*:[^:]*:([0-9A-F]{16}):", listing, re.M)
    return m.group(1) if m else ""


def ensure_key() -> str:
    """Make the key on first use. Returns its long id."""
    existing = key_id()
    if existing:
        return existing
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(KEY_DIR, 0o700)
    _run(["gpg", "--batch", "--gen-key"], input=(
        "%no-protection\nKey-Type: RSA\nKey-Length: 4096\n"
        "Name-Real: kite repo signing key\nName-Email: kite@localhost\nExpire-Date: 0\n%commit\n"))
    return key_id()


def _signed_by(rpm: Path, kid: str) -> bool:
    """Whether the RPM carries a signature from this key (rpm reports its short or long id)."""
    out = subprocess.run(["rpm", "-qp", "--nosignature", "--qf", "%{RSAHEADER:pgpsig}|%{SIGPGP:pgpsig}", str(rpm)],
                         capture_output=True, text=True, timeout=60).stdout.lower()
    return kid[-8:].lower() in out


def sign_repo(repo_dir: Path) -> dict:
    """
    Sign every RPM in the repo not yet signed with this controller's key,
    publish the public key beside them, and (re)sign the index. Returns
    {"key": id, "signed": [names]}; raises RuntimeError when a tool is
    missing or fails.
    """
    missing = missing_tools()
    if missing:
        raise RuntimeError(f"can't sign the agent repo: {', '.join(missing)} not installed "
                           f"(dnf install -y gnupg2 rpm-sign createrepo_c)")
    kid = ensure_key()
    repo_dir.mkdir(parents=True, exist_ok=True)
    public = _run(["gpg", "--batch", "--armor", "--export", kid])
    key_file = repo_dir / PUBLIC_KEY
    if not key_file.exists() or key_file.read_text() != public:
        key_file.write_text(public)
    signed = []
    for rpm in sorted(repo_dir.glob("*.rpm")):
        if not _signed_by(rpm, kid):
            _run(["rpmsign", "--define", f"_gpg_name {kid}", "--define", f"_gpg_path {KEY_DIR}", "--addsign", str(rpm)])
            signed.append(rpm.name)
    repomd = repo_dir / "repodata" / "repomd.xml"
    asc = repomd.with_name("repomd.xml.asc")
    if signed or not repomd.exists():
        _run(["createrepo_c", "--update", str(repo_dir)])
    if signed or not asc.exists() or asc.stat().st_mtime < repomd.stat().st_mtime:
        asc.unlink(missing_ok=True)
        _run(["gpg", "--batch", "--yes", "--armor", "--detach-sign", "-u", kid, "-o", str(asc), str(repomd)])
    return {"key": kid, "signed": signed}


def repo_signed(repo_dir: Path) -> bool:
    """Whether hosts can check signatures: the public key and a signed index are published."""
    return (repo_dir / PUBLIC_KEY).is_file() and (repo_dir / "repodata" / "repomd.xml.asc").is_file()


if __name__ == "__main__":   # after publishing an RPM by hand: python -m app.repo_signing
    from .agent_releases import REPO_DIR
    result = sign_repo(REPO_DIR)
    print(f"key {result['key']}; signed {', '.join(result['signed']) or 'nothing new'}; index signed")
