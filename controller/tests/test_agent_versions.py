"""
The Linux and Windows agents share one version number and are released
together, so "everything's on X" means one thing and Fleet offers one
version to update to. This fails the build the moment they drift apart.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LINUX = ROOT / "agent-linux" / "agent.py"
SPEC = ROOT / "agent-linux" / "packaging" / "kite-agent.spec"
WINDOWS = ROOT / "agent-windows" / "internal" / "agent" / "agent.go"


def _read(path: Path, pattern: str) -> str:
    if not path.is_file():
        pytest.skip(f"{path} isn't in this checkout")
    m = re.search(pattern, path.read_text(), re.MULTILINE)
    assert m, f"no version found in {path}"
    return m.group(1)


def test_linux_and_windows_agents_share_one_version():
    linux = _read(LINUX, r'^AGENT_VERSION = "([^"]+)"')
    windows = _read(WINDOWS, r'^const AgentVersion = "([^"]+)"')
    rpm = _read(SPEC, r"^Version:\s+(\S+)")
    assert linux == windows == rpm, f"agent.py {linux}, agent.go {windows}, spec {rpm}: bump them together"
