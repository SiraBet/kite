"""tools/seed_dev_fleet.py --scale: the large fleet developers check pages against keeps seeding."""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_scale_seeds_a_proportionate_fleet(tmp_path):
    db = tmp_path / "big.db"
    env = dict(os.environ, KITE_DB=str(db), KITE_DATA_DIR=str(tmp_path), KITE_STATE_DIR=str(tmp_path))
    out = subprocess.run([sys.executable, "tools/seed_dev_fleet.py", "--scale", "30"], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-2000:]
    con = sqlite3.connect(str(db))
    count = lambda table: con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: E731
    assert count("hosts") == 45 and count("machine_groups") == 40 and count("patch_defs") == 80
    assert count("host_vulns") > 0 and count("audit_log") > 3000
