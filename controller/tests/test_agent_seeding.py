"""
agent_releases.seed_agents: the Docker image's built-in agents reach the
directories the controller serves, where newer -- on a fresh install and
after `docker compose up --build`, never over a newer one placed by hand.
"""
import io
import tarfile

from app import agent_releases


def _bundle(path, version):
    data = f'AGENT_VERSION = "{version}"\n'.encode()
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("agent-linux/agent.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


def _seed(root, version):
    dist, repo = root / "dist", root / "repo"
    dist.mkdir(parents=True)
    (repo / "repodata").mkdir(parents=True)
    _bundle(dist / "kite-agent-linux.tar.gz", version)
    (dist / "kite-agent.exe").write_bytes(b"exe " + version.encode())
    (dist / "kite-agent-setup.exe").write_bytes(b"setup")
    (dist / "kite-agent.exe.version").write_text(version)
    (repo / f"kite-agent-{version}-1.noarch.rpm").write_bytes(b"rpm")
    (repo / "repodata" / "repomd.xml").write_text(f"<repomd>{version}</repomd>")


def test_a_fresh_install_gets_every_agent(tmp_path):
    _seed(tmp_path / "seed", "0.8.0")
    dist, repo = tmp_path / "data" / "dist", tmp_path / "data" / "repo"
    copied = agent_releases.seed_agents(tmp_path / "seed", dist, repo)
    assert len(copied) == 3
    assert agent_releases.bundle_info(dist)["version"] == "0.8.0"
    assert agent_releases.windows_info(dist)["version"] == "0.8.0" and (dist / "kite-agent-setup.exe").exists()
    assert agent_releases.published(repo) == ["0.8.0"] and "0.8.0" in (repo / "repodata" / "repomd.xml").read_text()
    assert agent_releases.seed_agents(tmp_path / "seed", dist, repo) == []        # second start: nothing to do


def test_an_upgrade_replaces_older_agents_but_never_newer_ones(tmp_path):
    _seed(tmp_path / "old", "0.7.0")
    dist, repo = tmp_path / "data" / "dist", tmp_path / "data" / "repo"
    agent_releases.seed_agents(tmp_path / "old", dist, repo)
    _seed(tmp_path / "new", "0.8.0")
    assert len(agent_releases.seed_agents(tmp_path / "new", dist, repo)) == 3
    assert agent_releases.published(repo) == ["0.8.0", "0.7.0"]
    _seed(tmp_path / "older", "0.6.0")
    assert agent_releases.seed_agents(tmp_path / "older", dist, repo) == []
    assert agent_releases.windows_info(dist)["version"] == "0.8.0"
