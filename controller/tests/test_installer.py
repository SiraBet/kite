"""
controller-install.sh's copy step, run on a throwaway tree. Run from a
checkout that has been used, it must not carry that checkout's database,
secrets or signing key over the installed controller's.
"""
import re
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "controller-install.sh"


def test_copy_leaves_runtime_files_behind(tmp_path):
    copy = re.search(r'^tar -C "\$HERE".*?xf -$', SCRIPT.read_text(), re.S | re.M).group(0)
    src, dst = tmp_path / "src", tmp_path / "dst"
    shipped = ["app/main.py", ".env.example", "dist/kite-agent.exe", "repo/kite-agent-1.0-1.noarch.rpm",
               "app/routers/backups.py"]
    runtime = [".env", "kite.db", "kite.db-wal", "kite.pre-migration-1.db", "secret_key",
               "enroll_secret", "signing/pubring.kbx", "backups/kite-1.db.gz", "venv/bin/python",
               "app/__pycache__/main.cpython-39.pyc"]
    for name in shipped + runtime:
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_text("x")
    dst.mkdir()
    subprocess.run(["bash", "-c", copy], check=True, env={"HERE": str(src), "INSTALL_DIR": str(dst), "PATH": "/usr/bin:/bin"})
    copied = sorted(str(p.relative_to(dst)) for p in dst.rglob("*") if p.is_file())
    assert copied == sorted(shipped)
