"""
app/repo_signing.py: the controller signs its agent dnf repo -- each RPM
and the index -- with a key it makes once. The end-to-end test builds a
real RPM and runs where gpg, rpmbuild, rpmsign and createrepo_c exist
(CI installs them); the rest runs anywhere.
"""
import shutil
import subprocess
from unittest.mock import patch

import pytest

from app import repo_signing

TOOLS = ("gpg", "rpm", "rpmbuild", "rpmsign", "createrepo_c")


def test_without_the_tools_the_repo_stays_unsigned_and_says_why(tmp_path):
    with patch("app.repo_signing.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="rpm-sign"):
            repo_signing.sign_repo(tmp_path)
    assert not repo_signing.repo_signed(tmp_path)


def _tiny_rpm(where):
    top = where / "build"
    for d in ("SPECS", "SOURCES", "BUILD", "RPMS", "SRPMS", "BUILDROOT"):
        (top / d).mkdir(parents=True)
    spec = top / "SPECS" / "t.spec"
    spec.write_text("Name: kite-agent\nVersion: 9.9.9\nRelease: 1\nSummary: t\nLicense: none\nBuildArch: noarch\n"
                    "%description\nt\n%files\n")
    subprocess.run(["rpmbuild", "--define", f"_topdir {top}", "-bb", str(spec)], check=True, capture_output=True)
    return next((top / "RPMS").rglob("*.rpm"))


@pytest.mark.skipif(any(not shutil.which(t) for t in TOOLS), reason="needs " + ", ".join(TOOLS))
def test_signs_every_rpm_and_the_index_with_one_key(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copy(_tiny_rpm(tmp_path), repo)
    with patch.object(repo_signing, "KEY_DIR", tmp_path / "signing"):
        first = repo_signing.sign_repo(repo)
        assert first["signed"] == ["kite-agent-9.9.9-1.noarch.rpm"]
        assert repo_signing.repo_signed(repo)
        assert oct((tmp_path / "signing").stat().st_mode)[-3:] == "700"
        # the key and the signatures check out, as dnf on a host would see them
        keyring = tmp_path / "rpmdb"
        subprocess.run(["rpm", "--dbpath", str(keyring), "--import", str(repo / repo_signing.PUBLIC_KEY)], check=True)
        checked = subprocess.run(["rpm", "--dbpath", str(keyring), "-K", str(repo / first["signed"][0])],
                                 capture_output=True, text=True)
        assert checked.returncode == 0 and "NOKEY" not in checked.stdout, checked.stdout
        gpg = ["gpg", "--homedir", str(tmp_path / "signing"), "--verify",
               str(repo / "repodata" / "repomd.xml.asc"), str(repo / "repodata" / "repomd.xml")]
        assert subprocess.run(gpg, capture_output=True).returncode == 0
        # the same key next time, and nothing re-signed
        again = repo_signing.sign_repo(repo)
        assert again == {"key": first["key"], "signed": []}
