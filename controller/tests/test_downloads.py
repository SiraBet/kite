"""
Agent downloads — the path a Windows host takes to get its agent.

The distinction under most of these: "this controller has not built the
Windows agent" and "there is no Windows agent" are different answers, and
a console that renders the first as the second sends someone hunting for
a feature that is already there.
"""
import hashlib

import pytest

from app.routers import downloads


@pytest.fixture
def dist(tmp_path, monkeypatch):
    monkeypatch.setattr(downloads, "DIST_DIR", tmp_path)
    return tmp_path


def build_exe(dist, content=b"MZ fake windows binary", sidecar=True, name="kite-agent.exe"):
    path = dist / name
    path.write_bytes(content)
    if sidecar:
        (dist / f"{name}.sha256").write_text(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
    return path


def build_both(dist, agent=b"MZ agent", installer=b"MZ installer"):
    """What a controller looks like after agent-windows/build.sh has run."""
    build_exe(dist, agent, name="kite-agent.exe")
    build_exe(dist, installer, name="kite-agent-setup.exe")


def test_manifest_requires_a_session(client, dist):
    assert client.get("/download/agents").status_code == 401


def test_manifest_reports_a_built_agent(client, dist, logged_in):
    logged_in("operator")
    content = b"MZ fake windows binary"
    build_exe(dist, content)
    build_exe(dist, b"MZ installer", name="kite-agent-setup.exe")

    entry = client.get("/download/agents").json()[0]
    assert entry["platform"] == "windows"
    assert entry["available"] is True
    assert entry["size_bytes"] == len(content)
    assert entry["sha256"] == hashlib.sha256(content).hexdigest()
    assert entry["url"] == "/download/agent/windows"
    assert entry["built_at"]
    # Nothing to tell someone to run — it is already here.
    assert entry["build_command"] is None


def test_manifest_says_how_to_produce_a_missing_agent(client, dist, logged_in):
    logged_in("operator")
    entry = client.get("/download/agents").json()[0]
    assert entry["available"] is False
    assert entry["build_command"] == "agent-windows/build.sh"
    assert entry["sha256"] is None


def test_checksum_falls_back_to_hashing_the_file(client, dist, logged_in):
    """A missing sidecar must not blank out the checksum people verify against."""
    logged_in("operator")
    content = b"MZ another build"
    build_exe(dist, content, sidecar=False)
    entry = client.get("/download/agents").json()[0]
    assert entry["sha256"] == hashlib.sha256(content).hexdigest()


def test_checksum_ignores_a_corrupt_sidecar(client, dist, logged_in):
    logged_in("operator")
    content = b"MZ yet another build"
    build_exe(dist, content)
    (dist / "kite-agent.exe.sha256").write_text("not a checksum\n")
    entry = client.get("/download/agents").json()[0]
    assert entry["sha256"] == hashlib.sha256(content).hexdigest()


def test_binary_downloads_without_a_session(client, dist):
    """
    The host fetching this has no console session and cannot get one.
    The binary carries no secrets — enrolling still needs a token or the
    shared secret — which is why it is served like the RPM repo is.
    """
    content = b"MZ fake windows binary"
    build_exe(dist, content)
    resp = client.get("/download/agent/windows")
    assert resp.status_code == 200
    assert resp.content == content
    assert "kite-agent.exe" in resp.headers["content-disposition"]


def test_missing_binary_explains_itself(client, dist):
    resp = client.get("/download/agent/windows")
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "has not been built into this install" in detail
    assert "agent-windows/build.sh" in detail


def test_unknown_platform_lists_what_exists(client, dist):
    resp = client.get("/download/agent/solaris")
    assert resp.status_code == 404
    assert "windows" in resp.json()["detail"]


def test_checksum_endpoint_matches_the_binary(client, dist):
    content = b"MZ fake windows binary"
    build_exe(dist, content)
    body = client.get("/download/agent/windows/sha256").json()
    assert body["sha256"] == hashlib.sha256(content).hexdigest()
    assert body["filename"] == "kite-agent.exe"


def test_checksum_endpoint_404s_when_not_built(client, dist):
    assert client.get("/download/agent/windows/sha256").status_code == 404


# ---------- Installer ----------

def test_manifest_reports_the_installer(client, dist, logged_in):
    logged_in("operator")
    installer = b"MZ installer payload"
    build_both(dist, installer=installer)

    entry = client.get("/download/agents").json()[0]
    assert entry["installer_available"] is True
    assert entry["installer_filename"] == "kite-agent-setup.exe"
    assert entry["installer_url"] == "/download/installer/windows"
    assert entry["installer_sha256"] == hashlib.sha256(installer).hexdigest()


def test_manifest_flags_a_missing_installer_even_when_the_agent_exists(client, dist, logged_in):
    """
    The installer is what an operator should download. An install with
    only the bare agent is half-built, and saying nothing would leave the
    console offering the harder path without explaining why.
    """
    logged_in("operator")
    build_exe(dist)
    entry = client.get("/download/agents").json()[0]
    assert entry["available"] is True
    assert entry["installer_available"] is False
    assert entry["build_command"] == "agent-windows/build.sh"


def test_generic_installer_downloads_unconfigured(client, dist):
    body = b"MZ installer payload"
    build_both(dist, installer=body)
    resp = client.get("/download/installer/windows")
    assert resp.status_code == 200
    # No token asked for, so nothing appended: the installer will prompt.
    assert resp.content == body


def test_installer_with_a_token_carries_it(client, dist, db, logged_in):
    """
    The point of the whole footer mechanism: the download already knows
    the controller and the token, so nothing has to be typed on the host.
    """
    from app import agent_package
    logged_in("admin")
    build_both(dist, installer=b"MZ installer payload")

    token = client.post("/enroll/tokens", json={
        "hostname": "win-file-01", "team": "corporate", "role": "File server",
    }).json()["token"]

    resp = client.get(f"/download/installer/windows?token={token}")
    assert resp.status_code == 200
    assert "kite-agent-setup-win-file-01.exe" in resp.headers["content-disposition"]

    embedded = agent_package.read_footer(resp.content)
    assert embedded["token"] == token
    assert embedded["hostname"] == "win-file-01"
    assert embedded["team"] == "corporate"
    # Taken from the request, so an install reached over a new name or
    # scheme points hosts back at the address that actually worked.
    assert embedded["controller_url"] == "http://testserver"
    # The executable itself must survive intact ahead of the footer.
    assert resp.content.startswith(b"MZ installer payload")
    assert "ca_fingerprint" not in embedded       # this test controller publishes no CA


def test_installer_carries_the_controllers_ca_fingerprint(client, dist, db, logged_in):
    """The agent checks the controller's CA against it and pins it before enrolling."""
    from unittest.mock import patch
    from app import agent_package, controller_ca
    logged_in("admin")
    build_both(dist, installer=b"MZ installer payload")
    token = client.post("/enroll/tokens", json={"hostname": "win-ca-01"}).json()["token"]
    with patch.object(controller_ca, "describe", return_value={"available": True, "sha256": "ab" * 32}):
        resp = client.get(f"/download/installer/windows?token={token}")
    assert agent_package.read_footer(resp.content)["ca_fingerprint"] == "ab" * 32


def test_installer_refuses_a_used_token(client, dist, db, logged_in):
    logged_in("admin")
    build_both(dist, installer=b"MZ installer payload")
    token = client.post("/enroll/tokens", json={"hostname": "win-02"}).json()["token"]

    client.post("/agent/enroll", json={"token": token, "os_version": "Server 2022",
                                        "os_family": "windows"})
    resp = client.get(f"/download/installer/windows?token={token}")
    assert resp.status_code == 409
    assert "already been used" in resp.json()["detail"]


def test_installer_refuses_an_unknown_token(client, dist):
    build_both(dist, installer=b"MZ installer payload")
    resp = client.get("/download/installer/windows?token=not-a-real-token")
    assert resp.status_code == 404


def test_missing_installer_explains_itself(client, dist):
    resp = client.get("/download/installer/windows")
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "has not been built into this install" in detail
    assert "agent-windows/build.sh" in detail


def test_regenerating_replaces_rather_than_stacks(client, dist, db, logged_in):
    """
    The installer in dist/ could itself already carry a footer if someone
    copied a generated one back. Configuring must replace it, not append
    a second copy the reader would never reach.
    """
    from app import agent_package
    logged_in("admin")
    already = agent_package.configure(b"MZ installer payload", {"controller_url": "https://old", "token": "old"})
    build_exe(dist, already, name="kite-agent-setup.exe")
    build_exe(dist)

    token = client.post("/enroll/tokens", json={"hostname": "win-03"}).json()["token"]
    resp = client.get(f"/download/installer/windows?token={token}")
    embedded = agent_package.read_footer(resp.content)
    assert embedded["token"] == token
    assert embedded["controller_url"] == "http://testserver"
    assert resp.content.startswith(b"MZ installer payload")


def test_linux_bundle_is_described_when_staged(client, dist, logged_in):
    """
    The console needs to know whether the bundle exists before offering a
    download link for it. This branch computes a checksum, which an earlier
    version did via a helper that didn't exist -- every test passed because
    no test had ever staged the bundle, and it only blew up in a live 500.
    """
    logged_in("operator")
    content = b"fake linux agent bundle"
    (dist / downloads.LINUX_AGENT_BUNDLE).write_bytes(content)

    entry = [a for a in client.get("/download/agents").json() if a["platform"] == "linux"][0]

    assert entry["available"] is True
    assert entry["sha256"] == hashlib.sha256(content).hexdigest()
    assert entry["size_bytes"] == len(content)
    assert entry["build_command"] is None


def test_linux_bundle_says_how_to_stage_it_when_missing(client, dist, logged_in):
    logged_in("operator")

    entry = [a for a in client.get("/download/agents").json() if a["platform"] == "linux"][0]

    assert entry["available"] is False
    assert entry["sha256"] is None
    assert "build-release.sh" in entry["build_command"]
