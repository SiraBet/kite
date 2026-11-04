"""
Unit tests for the agent's stage handlers.

These mock run_cmd/subprocess/os.path.exists rather than touching a real
package manager, which is what makes them safe to run anywhere: the
behaviour under test is the branching logic — which commands get built,
in what order, and how a failure at each step propagates.

Command construction is asserted against the exact argv the agent
builds, so a change to a dnf or apt invocation shows up here rather than
on a production host.
"""
import json
import os
import time

import pytest

import agent as agent_mod


@pytest.fixture(autouse=True)
def _holds_file(tmp_path, monkeypatch):
    """Where the agent records the holds it placed: a fresh file per test."""
    monkeypatch.setattr(agent_mod, "HOLDS_PATH", str(tmp_path / "holds.json"))


def make_agent(monkeypatch, pkg_manager):
    monkeypatch.setattr(agent_mod, "detect_package_manager", lambda: pkg_manager)
    config = {
        "controller_url": "https://controller.example",
        "host_id": 1,
        "agent_secret": "secret",
        "poll_interval": 900,
        "error_backoff": 20,
        "verify_tls": True,
    }
    a = agent_mod.Agent(config)
    # Container tests fake every runtime call; the readiness wait has its own tests below.
    a._wait_for_runtime = lambda: (True, 0)
    return a


# ---------- detect_package_manager ----------

def test_detect_package_manager_prefers_dnf(monkeypatch):
    monkeypatch.setattr(agent_mod.shutil, "which", lambda name: "/usr/bin/dnf" if name == "dnf" else None)
    assert agent_mod.detect_package_manager() == "dnf"


def test_detect_package_manager_apt_fallback(monkeypatch):
    monkeypatch.setattr(agent_mod.shutil, "which", lambda name: "/usr/bin/apt-get" if name == "apt-get" else None)
    assert agent_mod.detect_package_manager() == "apt"


def test_detect_package_manager_none_when_neither_present(monkeypatch):
    monkeypatch.setattr(agent_mod.shutil, "which", lambda name: None)
    assert agent_mod.detect_package_manager() is None


# ---------- run_cmd env plumbing ----------

def test_run_cmd_passes_env_through_to_subprocess(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0
        pid = 1

        def communicate(self, timeout=None):
            return "ok", ""

    def fake_popen(cmd, **kwargs):
        captured.update(kwargs)
        return FakeProc()

    monkeypatch.setattr(agent_mod.subprocess, "Popen", fake_popen)
    rc, out = agent_mod.run_cmd(["echo", "hi"], env={"FOO": "bar"})
    assert rc == 0 and out == "ok"
    assert captured["env"] == {"FOO": "bar"} and captured["start_new_session"] is True


def test_a_timed_out_command_is_stopped_with_everything_it_started(monkeypatch):
    """SIGTERM to the whole group first, so dnf/apt can finish the step it's on; and no hang
    on a child still holding the output pipe."""
    monkeypatch.setattr(agent_mod, "STOP_GRACE_SECONDS", 5)
    started = time.monotonic()
    # the shell leaves a background child holding stdout, then runs past its timeout
    rc, out = agent_mod.run_cmd(["bash", "-c", "sleep 300 & echo started; trap 'echo stopping; exit 3' TERM; sleep 300 & wait"],
                                timeout=1)
    assert rc == 1 and "timed out after 1s and was stopped" in out
    assert "started" in out and "stopping" in out          # its output kept; it got the SIGTERM
    assert time.monotonic() - started < 10


def test_a_command_ignoring_sigterm_is_killed(monkeypatch):
    monkeypatch.setattr(agent_mod, "STOP_GRACE_SECONDS", 1)
    started = time.monotonic()
    rc, out = agent_mod.run_cmd(["bash", "-c", "trap '' TERM; sleep 300"], timeout=1)
    assert rc == 1 and "timed out" in out and time.monotonic() - started < 15


# ---------- stage_preflight ----------

def test_preflight_fails_cleanly_with_no_package_manager(monkeypatch):
    a = make_agent(monkeypatch, None)
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, "should not run"))
    status, output = a.stage_preflight(1, [])
    assert status == "failed"
    assert "no supported package manager" in output


def test_preflight_apt_runs_update(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd",
                         lambda cmd, dry_run=False, timeout=1800, env=None: (calls.append(cmd), (0, "ok"))[1])
    status, output = a.stage_preflight(1, [])
    assert status == "done"
    assert ["apt-get", "-o", "DPkg::Lock::Timeout=300", "update"] in calls


def test_preflight_fails_when_apt_update_does(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (100, "E: Failed to fetch") if "update" in cmd else (0, ""))
    status, output = a.stage_preflight(1, [])
    assert status == "failed" and "Failed to fetch" in output


def test_preflight_fails_when_dnf_cant_read_its_repos(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (1, "Error: Failed to download metadata for repo 'baseos'")
                        if "check-update" in cmd else (0, ""))
    assert a.stage_preflight(1, [])[0] == "failed"
    # updates available (100), or only the local cache missing: fine
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (100, "openssl.x86_64 1:3.0.7-27 baseos"))
    assert a.stage_preflight(1, [])[0] == "done"
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (1, "Error: Cache-only enabled but no cache for 'baseos'")
                        if "check-update" in cmd else (0, ""))
    assert a.stage_preflight(1, [])[0] == "done"


# ---------- stage_excludes (apt) ----------

def test_excludes_apt_skip_mode_holds_package(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd",
                         lambda cmd, dry_run=False, timeout=1800, env=None: (calls.append(cmd), (0, "ok"))[1])
    status, output = a.stage_excludes(1, [{"pkg_pattern": "nginx", "mode": "skip"}])
    assert status == "done"
    assert calls == [["apt-mark", "showhold"], ["apt-mark", "hold", "nginx"]]


def test_excludes_apt_pin_mode_installs_then_holds(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd",
                         lambda cmd, dry_run=False, timeout=1800, env=None: (calls.append(cmd), (0, "ok"))[1])
    status, output = a.stage_excludes(1, [{"pkg_pattern": "curl", "mode": "pin", "version": "7.81.0-1ubuntu1"}])
    assert status == "done"
    assert calls[1][:2] == ["apt-get", "install"]
    assert "curl=7.81.0-1ubuntu1" in calls[1]
    assert calls[2] == ["apt-mark", "hold", "curl"]


def test_excludes_apt_pin_install_failure_stops_before_hold(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    calls = []

    def fake_run_cmd(cmd, dry_run=False, timeout=1800, env=None):
        calls.append(cmd)
        if cmd[:2] == ["apt-get", "install"]:
            return 1, "no candidate version"
        return 0, "ok"

    monkeypatch.setattr(agent_mod, "run_cmd", fake_run_cmd)
    status, output = a.stage_excludes(1, [{"pkg_pattern": "curl", "mode": "pin", "version": "999.0"}])
    assert status == "failed"
    assert calls[-1][:2] == ["apt-get", "install"]  # never reached apt-mark hold


def test_excludes_apt_rejects_wildcard_pattern(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run")))
    status, output = a.stage_excludes(1, [{"pkg_pattern": "kernel*", "mode": "skip"}])
    assert status == "done"
    assert "wildcard" in output


def _recording(monkeypatch, outputs=None):
    calls = []

    def fake_run_cmd(cmd, dry_run=False, timeout=1800, env=None):
        calls.append(cmd)
        return 0, (outputs or {}).get(tuple(cmd), "ok")

    monkeypatch.setattr(agent_mod, "run_cmd", fake_run_cmd)
    return calls


def test_a_removed_rule_releases_the_hold_kite_placed(monkeypatch):
    """Holds stayed forever once their rule was removed or changed."""
    a = make_agent(monkeypatch, "apt")
    _recording(monkeypatch)
    a.stage_excludes(1, [{"pkg_pattern": "nginx", "mode": "skip"}, {"pkg_pattern": "curl", "mode": "skip"}])

    calls = _recording(monkeypatch, {("apt-mark", "showhold"): "curl\nnginx\n"})
    status, output = a.stage_excludes(2, [{"pkg_pattern": "curl", "mode": "skip"}])
    assert status == "done"
    assert ["apt-mark", "unhold", "nginx"] in calls and ["apt-mark", "unhold", "curl"] not in calls
    assert "released nginx" in output

    calls = _recording(monkeypatch)
    a.stage_excludes(3, [])
    assert calls == [["apt-mark", "unhold", "curl"]]


def test_a_hold_placed_by_hand_is_never_released(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    _recording(monkeypatch, {("apt-mark", "showhold"): "linux-image-generic\n"})
    a.stage_excludes(1, [{"pkg_pattern": "linux-image-generic", "mode": "skip"}])   # a rule for it too
    calls = _recording(monkeypatch)
    a.stage_excludes(2, [])
    assert calls == []


def test_a_changed_pin_replaces_the_old_versionlock(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    _recording(monkeypatch)
    a.stage_excludes(1, [{"pkg_pattern": "openssl", "mode": "pin", "version": "3.0.7"}])
    calls = _recording(monkeypatch)
    status, output = a.stage_excludes(2, [{"pkg_pattern": "openssl", "mode": "pin", "version": "3.0.8"}])
    assert status == "done"
    assert calls == [["dnf", "versionlock", "delete", "openssl-3.0.7*"], ["dnf", "versionlock", "add", "openssl-3.0.8*"]]
    calls = _recording(monkeypatch)
    a.stage_excludes(3, [{"pkg_pattern": "openssl", "mode": "skip"}])
    assert calls == [["dnf", "versionlock", "delete", "openssl-3.0.8*"]]


def test_a_hold_that_wont_release_is_tried_again_next_run(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    _recording(monkeypatch)
    a.stage_excludes(1, [{"pkg_pattern": "openssl", "mode": "pin", "version": "3.0.7"}])
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (1, "versionlock plugin missing"))
    status, output = a.stage_excludes(2, [])
    assert status == "done" and "could not release openssl-3.0.7*" in output
    calls = _recording(monkeypatch)
    a.stage_excludes(3, [])
    assert calls == [["dnf", "versionlock", "delete", "openssl-3.0.7*"]]


# ---------- stage_snapshot (dnf_history rollback backend) ----------

_DNF_HISTORY_SAMPLE = """ID     | Command line             | Date and time    | Action(s)      | Altered
-------------------------------------------------------------------------------
    12 | update -y                | 2026-08-20 10:00 | Update         |    5
    11 | install nginx            | 2026-08-15 09:30 | Install        |    1
"""


def test_snapshot_dnf_history_captures_last_transaction_id(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(agent_mod, "run_cmd",
                         lambda cmd, dry_run=False, timeout=1800, env=None: (0, _DNF_HISTORY_SAMPLE))
    status, output = a.stage_snapshot(1, [])
    assert status == "done"
    assert "#12" in output
    assert "dnf history rollback 12" in output


def test_snapshot_dnf_history_handles_fresh_system_with_no_history(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    empty = "ID     | Command line             | Date and time    | Action(s)      | Altered\n" \
            "-------------------------------------------------------------------------------\n"
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, dry_run=False, timeout=1800, env=None: (0, empty))
    status, output = a.stage_snapshot(1, [])
    assert status == "done"
    assert "#0" in output
    assert "dnf history undo 1" in output


def test_snapshot_dnf_history_fails_on_non_dnf_host(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run")))
    status, output = a.stage_snapshot(1, [])
    assert status == "failed"
    assert "requires dnf" in output


def test_snapshot_dnf_history_reports_command_failure(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, dry_run=False, timeout=1800, env=None: (1, "dnf: command not found"))
    status, output = a.stage_snapshot(1, [])
    assert status == "failed"
    assert "dnf history list" in output


# ---------- stage_patch ----------

def test_patch_apt_upgrade_has_no_per_package_exclude_flag(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd",
                         lambda cmd, dry_run=False, timeout=1800, env=None: (calls.append(cmd), (0, "ok"))[1])
    status, output = a.stage_patch(1, [{"pkg_pattern": "nginx", "mode": "skip"}])
    assert status == "done"
    assert calls[0] == ["apt-get", "-o", "DPkg::Lock::Timeout=300", "update"]
    assert calls[1][-1] == "upgrade" and "DPkg::Lock::Timeout=300" in calls[1]
    assert not any("nginx" in part for part in calls[1])  # exclusion happens via hold, not a flag here


def test_a_failed_apt_update_stops_the_upgrade(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda cmd, **k: (calls.append(cmd), (100, "E: Could not get lock") if "update" in cmd else (0, ""))[1])
    status, output = a.stage_patch(1, [])
    assert status == "failed" and "Could not get lock" in output and len(calls) == 1


def test_patch_dnf_still_uses_exclude_flag(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd",
                         lambda cmd, dry_run=False, timeout=1800, env=None: (calls.append(cmd), (0, "ok"))[1])
    status, output = a.stage_patch(1, [{"pkg_pattern": "kernel*", "mode": "skip"}])
    assert status == "done"
    assert "--exclude=kernel*" in calls[0]


# ---------- stage_reboot ----------

def test_reboot_apt_detects_reboot_required_file(monkeypatch, tmp_path):
    a = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "STATE_PATH", str(tmp_path / "pending_reboot.json"))
    monkeypatch.setattr(agent_mod.os.path, "exists", lambda p: p == "/var/run/reboot-required")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd",
                         lambda cmd, dry_run=False, timeout=1800, env=None: (calls.append(cmd), (0, "ok"))[1])
    status, output = a.stage_reboot(1, [])
    assert status == "deferred"
    assert calls == [["systemctl", "reboot"]]
    state = json.loads((tmp_path / "pending_reboot.json").read_text())
    assert state["job_id"] == 1


def test_reboot_apt_no_reboot_needed(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod.os.path, "exists", lambda p: False)
    status, output = a.stage_reboot(1, [])
    assert status == "done"
    assert output == "no reboot required"


def test_reboot_dnf_still_uses_needs_restarting(monkeypatch, tmp_path):
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(agent_mod, "STATE_PATH", str(tmp_path / "pending_reboot.json"))
    calls = []

    def fake_run_cmd(cmd, dry_run=False, timeout=1800, env=None):
        calls.append(cmd)
        if cmd[0] == "needs-restarting":
            return 1, "reboot needed"
        return 0, "ok"

    monkeypatch.setattr(agent_mod, "run_cmd", fake_run_cmd)
    status, output = a.stage_reboot(1, [])
    assert status == "deferred"
    assert calls[0] == ["needs-restarting", "-r"]


# ---------- self-update ----------

def test_self_update_skips_on_apt_hosts(monkeypatch):
    """No .deb/apt repo exists for this agent yet (same stated gap as
    Debian/Ubuntu packaging) -- must not attempt a dnf command
    on a host that doesn't have dnf."""
    a = make_agent(monkeypatch, "apt")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a_, **kw: calls.append((a_, kw)) or (0, "ok"))
    a.self_update("9.9.9")
    assert calls == []


def test_self_update_runs_dnf_update_then_restarts_on_success(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    calls = []

    def fake_run_cmd(cmd, dry_run=False, timeout=1800, env=None):
        calls.append(cmd)
        return 0, "9.9.9" if cmd[0] == "rpm" else "upgraded"

    monkeypatch.setattr(agent_mod, "run_cmd", fake_run_cmd)
    assert a.self_update("9.9.9") is True
    assert calls == [["dnf", "-y", "--refresh", "upgrade", "kite-agent-9.9.9"],
                     ["rpm", "-q", "--qf", "%{VERSION}", "kite-agent"],
                     ["systemctl", "try-restart", "kite-agent"]]


def test_self_update_does_not_restart_when_dnf_installed_nothing(monkeypatch):
    """dnf says 'Nothing to do' with rc 0 when the version isn't in the repo; a restart
    into the same version would only loop (and forget the hourly limit)."""
    a = make_agent(monkeypatch, "dnf")
    calls = []

    def fake_run_cmd(cmd, dry_run=False, timeout=1800, env=None):
        calls.append(cmd)
        return 0, "0.7.2" if cmd[0] == "rpm" else "Nothing to do."

    monkeypatch.setattr(agent_mod, "run_cmd", fake_run_cmd)
    assert a.self_update("9.9.9") is False
    assert ["systemctl", "try-restart", "kite-agent"] not in calls
    assert a.self_update("9.9.9") is False and len(calls) == 2   # not tried again within the hour


def test_self_update_does_not_restart_on_dnf_failure(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    calls = []

    def fake_run_cmd(cmd, dry_run=False, timeout=1800, env=None):
        calls.append(cmd)
        return 1, "no space left on device"

    monkeypatch.setattr(agent_mod, "run_cmd", fake_run_cmd)
    a.self_update("9.9.9")
    assert calls == [["dnf", "-y", "--refresh", "upgrade", "kite-agent-9.9.9"]]  # no restart attempted after a failed update
    a.self_update("9.9.9")
    assert len(calls) == 1          # and not retried on the very next poll


def test_self_update_dry_run_does_not_execute(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    a.dry_run = True
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a_, **kw: calls.append((a_, kw)) or (0, "ok"))
    a.self_update("9.9.9")
    assert calls == []


# ---------- poll_next: self-update header plumbing ----------

class _FakeResponse:
    def __init__(self, json_body, headers=None):
        self._json_body = json_body
        self.headers = headers or {}

    def raise_for_status(self):
        pass

    def json(self):
        return self._json_body


def test_poll_next_sends_agent_version_and_surfaces_self_update_header(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    captured = {}

    def fake_get(url, params=None, timeout=None):
        captured["params"] = params
        return _FakeResponse(None, headers={"X-Kite-Self-Update": "9.9.9"})

    monkeypatch.setattr(a.session, "get", fake_get)
    instruction, ok, target = a.poll_next()
    assert ok is True
    assert instruction is None
    assert target == "9.9.9"
    assert captured["params"]["agent_version"] == agent_mod.AGENT_VERSION


def test_poll_next_no_self_update_header_gives_none_target(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(a.session, "get", lambda url, params=None, timeout=None: _FakeResponse({"job_id": 1}))
    instruction, ok, target = a.poll_next()
    assert ok is True
    assert instruction == {"job_id": 1}
    assert target is None


# ---------- stage_healthcheck ----------
#
# `systemctl --failed` exits 0 whether or not units failed, so rc says
# whether the CHECK ran -- not whether the host is healthy. Conflating
# the two reports "failed systemd units present" on a host where
# systemctl merely could not be executed.

def test_healthcheck_passes_when_no_units_failed(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, ""))
    assert agent.stage_healthcheck(1, []) == ("done", "no failed systemd units")


def test_healthcheck_fails_when_units_actually_failed(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda *a, **k: (0, "nginx.service loaded failed failed"))
    status, output = agent.stage_healthcheck(1, [])
    assert status == "failed"
    assert "failed systemd units present" in output
    assert "nginx.service" in output


def test_healthcheck_distinguishes_a_check_that_could_not_run(monkeypatch):
    """
    The bug: this reported "failed systemd units present: command not
    found ... systemctl" -- naming units as the problem when systemctl
    simply was not installed.
    """
    agent = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda *a, **k: (1, "command not found: [Errno 2] ... 'systemctl'"))
    status, output = agent.stage_healthcheck(1, [])
    assert status == "failed"
    assert "could not run the healthcheck" in output
    assert "failed systemd units present" not in output


def test_healthcheck_does_not_pass_a_check_that_errored_silently(monkeypatch):
    """
    The dangerous inverse: a non-zero exit with no output used to be
    reported as a clean healthcheck, marking the run healthy on the
    strength of a check that never actually ran.
    """
    agent = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (127, ""))
    assert agent.stage_healthcheck(1, [])[0] == "failed"


# ---------- container discovery ----------
#
# Read-only inventory. The parsing is tab-delimited on purpose (container
# names and image refs can contain spaces and colons), and management
# classification decides what kite may ever be allowed to do with a
# container, so both are pinned here.

def test_detect_container_runtime_prefers_docker(monkeypatch):
    monkeypatch.setattr(agent_mod.shutil, "which",
                        lambda n: "/usr/bin/" + n if n in ("docker", "podman") else None)
    assert agent_mod.detect_container_runtime() == "docker"


def test_detect_container_runtime_falls_back_to_podman(monkeypatch):
    monkeypatch.setattr(agent_mod.shutil, "which",
                        lambda n: "/usr/bin/podman" if n == "podman" else None)
    assert agent_mod.detect_container_runtime() == "podman"


def test_detect_container_runtime_none_when_absent(monkeypatch):
    monkeypatch.setattr(agent_mod.shutil, "which", lambda n: None)
    assert agent_mod.detect_container_runtime() is None


def test_discovery_is_a_no_op_without_a_runtime():
    assert agent_mod.discover_containers(None) == []


def test_discovery_parses_and_classifies(monkeypatch):
    rows = "\t".join(["abc123def4567", "web", "nginx:latest", "running",
                      "com.docker.compose.project=shop,com.docker.compose.service=web"])
    solo = "\t".join(["ffff11112222", "scratch", "alpine:3.19", "exited", ""])
    k8s = "\t".join(["999888777666", "k8s_api", "registry.k8s.io/pause:3.9", "running",
                     "io.kubernetes.pod.name=api-0"])
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, "\n".join([rows, solo, k8s])))

    found = {c["name"]: c for c in agent_mod.discover_containers("docker")}

    assert found["web"]["managed_by"] == "compose"
    assert found["web"]["compose_project"] == "shop"
    assert found["web"]["container_id"] == "abc123def456"   # truncated to 12
    assert found["scratch"]["managed_by"] == "standalone"
    assert found["scratch"]["state"] == "exited"
    assert found["k8s_api"]["managed_by"] == "kubernetes"


def test_discovery_survives_a_runtime_that_will_not_talk(monkeypatch):
    """A dead daemon or a permission error must not fail a patch run —
    inventory is supplementary."""
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda *a, **k: (1, "Cannot connect to the Docker daemon"))
    assert agent_mod.discover_containers("docker") == []


def test_digest_pinned_images_are_recognised():
    assert agent_mod._is_pinned("nginx@sha256:abc") is True
    assert agent_mod._is_pinned("nginx:latest") is False
    assert agent_mod._is_pinned("") is False


def test_drift_marks_a_moved_tag_as_updatable(monkeypatch):
    monkeypatch.setattr(agent_mod, "_local_image_identity", lambda *a, **k: ("sha256:old", "linux/amd64"))
    monkeypatch.setattr(agent_mod, "_registry_config_digest", lambda *a, **k: "sha256:new")
    containers = [{"image": "nginx:latest", "pinned": False}]

    agent_mod.check_image_drift("docker", containers)

    assert containers[0]["update_available"] is True
    assert containers[0]["image_digest"] == "sha256:old"


def test_drift_marks_a_matching_digest_as_current(monkeypatch):
    monkeypatch.setattr(agent_mod, "_local_image_identity", lambda *a, **k: ("sha256:same", "linux/amd64"))
    monkeypatch.setattr(agent_mod, "_registry_config_digest", lambda *a, **k: "sha256:same")
    containers = [{"image": "nginx:latest", "pinned": False}]

    agent_mod.check_image_drift("docker", containers)

    assert containers[0]["update_available"] is False


def test_unreachable_registry_stays_unknown_not_current(monkeypatch):
    """
    The important one. An unreadable registry must leave the answer as
    None; reporting False would claim the image is current on the
    strength of a comparison that never happened.
    """
    monkeypatch.setattr(agent_mod, "_local_image_identity", lambda *a, **k: ("sha256:local", "linux/amd64"))
    monkeypatch.setattr(agent_mod, "_registry_config_digest", lambda *a, **k: "")
    containers = [{"image": "private.registry/app:latest", "pinned": False}]

    agent_mod.check_image_drift("docker", containers)

    assert containers[0]["update_available"] is None


def test_pinned_images_are_never_checked_against_a_registry(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("a digest-pinned image must not be looked up")
    monkeypatch.setattr(agent_mod, "_registry_config_digest", fail)
    containers = [{"image": "nginx@sha256:abc", "pinned": True}]

    agent_mod.check_image_drift("docker", containers)

    assert containers[0]["update_available"] is False


def test_drift_queries_each_distinct_image_once(monkeypatch):
    """One registry round trip per image, not per container — a host
    running ten replicas of one image should cost one lookup."""
    calls = []
    monkeypatch.setattr(agent_mod, "_local_image_identity", lambda r, i, **k: ("sha256:old", "linux/amd64"))
    monkeypatch.setattr(agent_mod, "_registry_config_digest",
                        lambda r, i, p, **k: calls.append(i) or "sha256:new")
    containers = [{"image": "nginx:latest", "pinned": False} for _ in range(5)]
    containers.append({"image": "redis:7", "pinned": False})

    agent_mod.check_image_drift("docker", containers)

    assert sorted(calls) == ["nginx:latest", "redis:7"]


def test_drift_selects_the_manifest_matching_this_hosts_platform(monkeypatch):
    """
    A multi-arch tag returns one manifest per platform. Comparing against
    the wrong one reports drift that isn't there — which is what a naive
    "take the first entry" does on every image.
    """
    verbose = json.dumps([
        {"Descriptor": {"digest": "sha256:armmanifest",
                        "platform": {"os": "linux", "architecture": "arm64"}},
         "OCIManifest": {"config": {"digest": "sha256:arm-config"}}},
        {"Descriptor": {"digest": "sha256:amdmanifest",
                        "platform": {"os": "linux", "architecture": "amd64"}},
         "OCIManifest": {"config": {"digest": "sha256:amd-config"}}},
    ])
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, verbose))

    assert agent_mod._registry_config_digest("docker", "nginx:alpine", "linux/amd64") == "sha256:amd-config"
    assert agent_mod._registry_config_digest("docker", "nginx:alpine", "linux/arm64") == "sha256:arm-config"


def test_registry_lookup_handles_schema_v2_registries(monkeypatch):
    """OCI and Docker schema-2 registries name the manifest field
    differently; both have to work."""
    single = json.dumps({"Descriptor": {"digest": "sha256:x", "platform": {}},
                         "SchemaV2Manifest": {"config": {"digest": "sha256:v2-config"}}})
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, single))
    assert agent_mod._registry_config_digest("docker", "app:1", "linux/amd64") == "sha256:v2-config"


def test_registry_lookup_is_unknown_when_the_command_fails(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (1, "no such manifest"))
    assert agent_mod._registry_config_digest("docker", "private/app:1", "linux/amd64") == ""


def test_local_identity_parses_digest_and_platform(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda *a, **k: (0, "sha256:abc|amd64|linux|"))
    assert agent_mod._local_image_identity("docker", "nginx:alpine") == ("sha256:abc", "linux/amd64")


# ---------- stage_containers ----------
#
# `docker pull` alone changes nothing: a running container keeps its old
# image until recreated. Recreation is only safe where compose recorded
# the project, so this stage refuses everything else.

def _compose(name, service=None, workdir="/srv/app", managed_by="compose", image=None):
    return {"name": name, "managed_by": managed_by, "compose_project": "app",
            "compose_service": service or name, "image": image or f"{name}:latest",
            "compose_working_dir": workdir if managed_by == "compose" else ""}


def _compose_calls(calls):
    return [c for c in calls if "compose" in c]


def test_containers_stage_pulls_then_recreates(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, "sha256:abc"))[1])

    status, _ = agent.stage_containers(1, [_compose("web")])

    assert status == "done"
    compose = _compose_calls(calls)
    assert compose[0] == ["docker", "compose", "--project-directory", "/srv/app", "-p", "app",
                          "pull", "--ignore-pull-failures", "web"]
    assert compose[1] == ["docker", "compose", "--project-directory", "/srv/app", "-p", "app",
                          "up", "-d", "--no-deps", "web"]


def test_compose_is_run_the_way_the_project_was_brought_up(monkeypatch):
    """A project started with -p and -f files (and an env file) is a different project to
    compose without them: the labels say how, and inspect gives them intact."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    labels = {"com.docker.compose.project": "shop-prod",
              "com.docker.compose.project.working_dir": "/srv/shop",
              "com.docker.compose.project.config_files": "/srv/shop/compose.yml,/srv/shop/compose.prod.yml",
              "com.docker.compose.project.environment_file": "/srv/shop/prod.env",
              "com.docker.compose.service": "web"}
    calls = []

    def fake(cmd, **k):
        calls.append(cmd)
        if cmd[-1] == "{{json .Config.Labels}}":
            return 0, json.dumps(labels)
        return 0, "sha256:abc"
    monkeypatch.setattr(agent_mod, "run_cmd", fake)
    status, _ = agent.stage_containers(1, [_compose("web", workdir="/srv/shop")])
    assert status == "done"
    up = _compose_calls(calls)[-1]
    assert up == ["docker", "compose", "--project-directory", "/srv/shop", "-p", "shop-prod",
                  "-f", "/srv/shop/compose.yml", "-f", "/srv/shop/compose.prod.yml",
                  "--env-file", "/srv/shop/prod.env", "up", "-d", "--no-deps", "web"]


def test_containers_stage_groups_services_of_one_project(monkeypatch):
    """`pull` and `up` act on a whole project, so updating four services
    of the same project must not recreate it four times."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, "ok"))[1])

    agent.stage_containers(1, [_compose("web"), _compose("api"), _compose("worker")])

    compose = _compose_calls(calls)
    assert len(compose) == 2, compose      # one pull, one up
    assert compose[0][-3:] == ["api", "web", "worker"]


def test_containers_stage_separates_distinct_projects(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, "ok"))[1])

    agent.stage_containers(1, [_compose("web", workdir="/srv/a"), _compose("db", workdir="/srv/b")])

    compose = _compose_calls(calls)
    dirs = {c[c.index("--project-directory") + 1] for c in compose}
    assert dirs == {"/srv/a", "/srv/b"}
    assert len(compose) == 4               # pull + up, per project


def test_containers_stage_refuses_anything_not_compose_managed(monkeypatch):
    """The controller filters these out, but acting on the wrong
    container destroys a running service — so this re-checks."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))

    status, output = agent.stage_containers(1, [_compose("loose", managed_by="standalone")])

    assert status == "failed"
    assert "no updatable containers" in output
    assert "loose" in output


def test_containers_stage_refuses_compose_without_a_working_dir(monkeypatch):
    """Compose labels can be absent on a container created by an older
    compose; without the project directory there is no safe update."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))

    status, _ = agent.stage_containers(1, [_compose("web", workdir="")])
    assert status == "failed"


def test_a_failed_pull_does_not_abort_the_stage(monkeypatch):
    """
    A pull is preparation, not the operation. A compose project that
    mixes registry images with locally built ones is ordinary, and an
    image in no registry can never be pulled — aborting there would mean
    such a project could never be updated at all.
    """
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []

    def failing(cmd, **k):
        calls.append(cmd)
        return (1, "pull access denied") if "pull" in cmd else (0, "Container web Recreated")
    monkeypatch.setattr(agent_mod, "run_cmd", failing)

    status, output = agent.stage_containers(1, [_compose("web")])

    assert status == "done"
    assert any("up" in c for c in calls), "up must still run after a failed pull"
    assert "pull access denied" in output, "the failure stays visible in the stage output"


def test_a_failed_up_fails_the_stage(monkeypatch):
    """`up` is the step that actually changes what is running, so its
    failure is a real one."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda cmd, **k: (0, "ok") if "pull" in cmd else (1, "port is already allocated"))

    status, output = agent.stage_containers(1, [_compose("web")])

    assert status == "failed"
    assert "port is already allocated" in output


def test_containers_stage_needs_a_runtime(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = None
    status, output = agent.stage_containers(1, [_compose("web")])
    assert status == "failed"
    assert "no container runtime" in output


def test_discovery_records_the_compose_project_directory(monkeypatch):
    row = "\t".join(["abc", "web", "nginx:latest", "running",
                     "com.docker.compose.project=shop,"
                     "com.docker.compose.service=frontend,"
                     "com.docker.compose.project.working_dir=/srv/shop"])
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, row))

    c = agent_mod.discover_containers("docker")[0]

    assert c["compose_service"] == "frontend"
    assert c["compose_working_dir"] == "/srv/shop"


# ---------- pre-update capture and rollback ----------
#
# Capturing the image is a complete rollback point for a compose service:
# the compose file supplies everything else, and volumes survive
# recreation. `docker tag` copies nothing, and one tag per service means
# a new capture replaces the old one rather than accumulating.

def test_capture_happens_before_anything_is_pulled(monkeypatch):
    """Updating without a way back is what this is meant to prevent, so
    the capture must precede the pull, not follow it."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, "sha256:old"))[1])

    agent.stage_containers(1, [_compose("web", service="api")])

    tag_calls = [c for c in calls if c[:2] == ["docker", "tag"]]
    assert tag_calls, "expected the running image to be tagged"
    assert tag_calls[0][-1] == "kite-rollback/app_api:previous"
    assert calls.index(tag_calls[0]) < calls.index(_compose_calls(calls)[0])


def test_one_capture_per_service_replaces_the_previous(monkeypatch):
    """The tag name is deterministic, so re-tagging moves it onto the new
    image and the old one becomes collectable — disk stays bounded."""
    assert agent_mod.rollback_tag("shop", "web") == "kite-rollback/shop_web:previous"
    assert agent_mod.rollback_tag("shop", "web") == agent_mod.rollback_tag("shop", "web")
    assert agent_mod.rollback_tag("other", "web") != agent_mod.rollback_tag("shop", "web")


def test_a_failed_capture_aborts_before_updating(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []

    def run(cmd, **k):
        calls.append(cmd)
        return (1, "no such container") if "inspect" in cmd else (0, "ok")
    monkeypatch.setattr(agent_mod, "run_cmd", run)

    status, output = agent.stage_containers(1, [_compose("web")])

    assert status == "failed"
    assert "could not read the current image" in output
    assert not _compose_calls(calls), "nothing may be pulled or recreated without a capture"


def test_rollback_restores_the_capture_and_recreates(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, "sha256:saved"))[1])

    status, output = agent.stage_containers(
        1, {"action": "rollback", "containers": [_compose("web", service="api")]})

    assert status == "done"
    assert ["docker", "tag", "kite-rollback/app_api:previous", "web:latest"] in calls
    assert "restored" in output
    # Still ends in a recreate — that is what changes what is running.
    assert any("up" in c for c in _compose_calls(calls))


def test_rollback_never_pulls(monkeypatch):
    """Pulling during a rollback would fetch the very image being rolled
    back from."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, "sha256:x"))[1])

    agent.stage_containers(1, {"action": "rollback", "containers": [_compose("web")]})

    assert not any("pull" in c for c in calls)


def test_rollback_fails_when_there_is_no_capture(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"

    def run(cmd, **k):
        if "image" in cmd and "inspect" in cmd:
            return 1, "no such image"
        return 0, "ok"
    monkeypatch.setattr(agent_mod, "run_cmd", run)

    status, output = agent.stage_containers(
        1, {"action": "rollback", "containers": [_compose("web")]})

    assert status == "failed"
    assert "no capture to restore" in output


def test_rollback_refuses_a_digest_pinned_reference(monkeypatch):
    """A digest reference names exact content, so re-tagging it is not
    possible — and a pinned image was never updated in the first place."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (0, "ok"))
    pinned = dict(_compose("web"), image="nginx@sha256:abc")

    status, output = agent.stage_containers(1, {"action": "rollback", "containers": [pinned]})

    assert status == "failed"
    assert "digest-pinned" in output


def test_a_bare_list_payload_still_means_update(monkeypatch):
    """An older controller sends a plain list with no action."""
    agent = make_agent(monkeypatch, "apt")
    agent.container_runtime = "docker"
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, "sha256:a"))[1])

    agent.stage_containers(1, [_compose("web")])

    assert any("pull" in c for c in calls)


def test_discovery_reports_whether_a_capture_exists(monkeypatch):
    row = "\t".join(["abc", "shop-web-1", "nginx:latest", "running",
                     "com.docker.compose.project=shop,com.docker.compose.service=web"])
    other = "\t".join(["def", "shop-db-1", "postgres:16", "running",
                       "com.docker.compose.project=shop,com.docker.compose.service=db"])

    def run(cmd, **k):
        if cmd[1] == "images":
            return 0, "kite-rollback/shop_web:previous"
        return 0, "\n".join([row, other])
    monkeypatch.setattr(agent_mod, "run_cmd", run)

    found = {c["name"]: c for c in agent_mod.discover_containers("docker")}

    assert found["shop-web-1"]["rollback_available"] is True
    assert found["shop-db-1"]["rollback_available"] is False


def test_capture_listing_costs_one_call_regardless_of_container_count(monkeypatch):
    """A host with fifty services must not mean fifty image inspects."""
    rows = "\n".join("\t".join([f"id{i}", f"svc-{i}", "img:1", "running",
                                f"com.docker.compose.project=p,com.docker.compose.service=s{i}"])
                     for i in range(50))
    calls = []

    def run(cmd, **k):
        calls.append(cmd)
        return (0, "") if cmd[1] == "images" else (0, rows)
    monkeypatch.setattr(agent_mod, "run_cmd", run)

    agent_mod.discover_containers("docker")

    assert len([c for c in calls if c[1] == "images"]) == 1
    assert len(calls) == 2, "one ps, one images"


# ---------- update assessment ----------
#
# The ok flag is the thing to get right. A query that failed is not a
# host with nothing pending: one unreachable repository fails the whole
# dnf query, and reporting that as zero shows a host as fully patched
# when it has dozens of outstanding advisories.

DNF_OUTPUT = """RLSA-2026:58572 Moderate/Sec.  NetworkManager-1:1.54.3-5.el9_8.x86_64
RLSA-2026:58600 Important/Sec. openssl-1:3.2.2-6.el9_8.x86_64
RLBA-2026:39332 bugfix         kernel-tools-5.14.0-687.26.1.el9_8.x86_64"""

APT_OUTPUT = """Listing...
libpcre2-8-0/oldstable-security 10.42-1+deb12u1 amd64 [upgradable from: 10.42-1]
tzdata/oldstable 2024a-0+deb12u1 all [upgradable from: 2023c-5]"""


def test_dnf_assessment_reads_severity_and_advisory(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, DNF_OUTPUT))

    result = agent_mod.assess_updates("dnf")

    assert result["ok"] is True
    by_package = {u["package"]: u for u in result["updates"]}
    assert by_package["openssl"]["severity"] == "important"
    assert by_package["openssl"]["advisory"] == "RLSA-2026:58600"
    assert by_package["openssl"]["is_security"] is True
    assert by_package["NetworkManager"]["severity"] == "moderate"
    # A bugfix advisory is a pending update, but not a security one.
    assert by_package["kernel-tools"]["is_security"] is False
    assert by_package["kernel-tools"]["severity"] == "none"


def test_a_failed_dnf_query_is_not_zero_updates(monkeypatch):
    """The whole point of the ok flag."""
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda *a, **k: (1, "Failed to download metadata for repo 'x'"))

    result = agent_mod.assess_updates("dnf")

    assert result["ok"] is False
    assert result["updates"] == []
    assert "Failed to download metadata" in result["error"]


def test_apt_assessment_identifies_security_by_origin(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, APT_OUTPUT))

    result = agent_mod.assess_updates("apt")

    by_package = {u["package"]: u for u in result["updates"]}
    assert by_package["libpcre2-8-0"]["is_security"] is True
    assert by_package["tzdata"]["is_security"] is False


def test_apt_security_updates_have_no_invented_severity(monkeypatch):
    """
    apt publishes no per-advisory severity. Calling one 'low' or
    'important' would be making up a number nobody published.
    """
    monkeypatch.setattr(agent_mod, "run_cmd", lambda *a, **k: (0, APT_OUTPUT))

    by_package = {u["package"]: u for u in agent_mod.assess_updates("apt")["updates"]}

    assert by_package["libpcre2-8-0"]["severity"] == "unknown"
    assert by_package["tzdata"]["severity"] == "none"


def test_nevra_parsing_recovers_the_package_name():
    assert agent_mod._package_name_from_nevra("NetworkManager-1:1.54.3-5.el9_8.x86_64") == "NetworkManager"
    assert agent_mod._package_name_from_nevra("kernel-tools-5.14.0-687.el9.x86_64") == "kernel-tools"


def test_assessment_of_an_unknown_package_manager_is_not_ok():
    result = agent_mod.assess_updates(None)
    assert result["ok"] is False and result["updates"] == []


# ---------- severity-filtered patching ----------

def _patch_cmd(monkeypatch, pkg_manager, severity):
    agent = make_agent(monkeypatch, pkg_manager)
    agent._severity_filter = severity
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, "ok"))[1])
    if pkg_manager == "apt":
        monkeypatch.setattr(agent_mod, "_assess_apt", lambda *a, **k: {
            "ok": True, "error": "",
            "updates": [{"package": "openssl", "is_security": True},
                        {"package": "tzdata", "is_security": False}]})
    agent.stage_patch(1, [])
    return calls


def test_dnf_everything_is_unrestricted(monkeypatch):
    cmd = _patch_cmd(monkeypatch, "dnf", "")[0]
    assert cmd == ["dnf", "update", "-y", "--exclude=kite-agent"]


def test_dnf_patch_never_updates_the_agent_itself(monkeypatch):
    """The agent changes only by self-update (Settings decides the version), never mid-patch."""
    for severity in ("", "security", "Critical"):
        assert "--exclude=kite-agent" in _patch_cmd(monkeypatch, "dnf", severity)[0]


def test_dnf_security_only(monkeypatch):
    cmd = _patch_cmd(monkeypatch, "dnf", "security")[0]
    assert "--security" in cmd and not any(c.startswith("--sec-severity") for c in cmd)


def test_dnf_severity_list_implies_security(monkeypatch):
    """--sec-severity is ignored by dnf unless --security is also given,
    which would silently patch everything instead of the chosen levels."""
    cmd = _patch_cmd(monkeypatch, "dnf", "critical,important")[0]
    assert "--security" in cmd
    assert "--sec-severity=critical" in cmd
    assert "--sec-severity=important" in cmd


def test_apt_security_only_installs_just_the_security_packages(monkeypatch):
    calls = _patch_cmd(monkeypatch, "apt", "security")
    install = [c for c in calls if "install" in c][0]
    assert "--only-upgrade" in install
    assert "openssl" in install
    assert "tzdata" not in install, "a non-security package must not ride along"


def test_apt_degrades_a_severity_list_to_security_and_says_so(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    agent._severity_filter = "critical"
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (0, "ok"))
    monkeypatch.setattr(agent_mod, "_assess_apt", lambda *a, **k: {
        "ok": True, "error": "", "updates": [{"package": "openssl", "is_security": True}]})

    status, output = agent.stage_patch(1, [])

    assert status == "done"
    assert "no per-advisory severity" in output


def test_apt_will_not_guess_when_it_cannot_tell_what_is_security(monkeypatch):
    agent = make_agent(monkeypatch, "apt")
    agent._severity_filter = "security"
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (0, "ok"))
    monkeypatch.setattr(agent_mod, "_assess_apt", lambda *a, **k: {
        "ok": False, "error": "could not reach the archive", "updates": []})

    status, output = agent.stage_patch(1, [])

    assert status == "failed"
    assert "could not determine which updates are security" in output


# ---------- third-party sources: flatpak, snap ----------

# run_cmd is called several times per source (installed list, then the
# updates query). This dispatches canned output by the command, so a test
# can assert what each source parses without a real flatpak/snap present.
def _canned_run_cmd(outputs):
    def fake(cmd, *a, **k):
        key = cmd[0]
        # snap uses ("snap","list") vs ("snap","refresh","--list"); key on
        # the second word where there is one to tell them apart.
        for sig, (rc, out) in outputs.items():
            if all(tok in cmd for tok in sig.split()):
                return rc, out
        return 1, "no canned output for " + " ".join(cmd)
    return fake


FLATPAK_INSTALLED = "org.mozilla.firefox\t121.0\norg.videolan.VLC\t3.0.18"
FLATPAK_UPDATES = "org.mozilla.firefox\t122.0"


def test_flatpak_reports_current_and_available(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd", _canned_run_cmd({
        "flatpak list": (0, FLATPAK_INSTALLED),
        "flatpak remote-ls": (0, FLATPAK_UPDATES),
    }))
    result = agent_mod.assess_flatpak()
    assert result["ok"] is True
    u = result["updates"][0]
    assert u["package"] == "org.mozilla.firefox"
    assert u["current_version"] == "121.0" and u["new_version"] == "122.0"


def test_flatpak_query_failure_is_not_ok(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd", _canned_run_cmd({
        "flatpak list": (0, FLATPAK_INSTALLED),
        "flatpak remote-ls": (1, "error: Unable to reach remote"),
    }))
    result = agent_mod.assess_flatpak()
    assert result["ok"] is False and result["updates"] == []


SNAP_LIST = "Name  Version  Rev  Tracking  Publisher  Notes\ncore22  20240101  1234  latest/stable  canonical  base\nfirefox  121.0  456  latest/stable  mozilla  -"
SNAP_REFRESH = "Name  Version  Rev  Publisher  Notes\nfirefox  122.0  789  mozilla  -"


def test_snap_reports_available_version(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd", _canned_run_cmd({
        "snap list": (0, SNAP_LIST),
        "snap refresh": (0, SNAP_REFRESH),
    }))
    result = agent_mod.assess_snap()
    assert result["ok"] is True
    u = result["updates"][0]
    assert u["package"] == "firefox"
    assert u["current_version"] == "121.0" and u["new_version"] == "122.0"


def test_snap_all_up_to_date_is_empty_and_ok(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd", _canned_run_cmd({
        "snap list": (0, SNAP_LIST),
        "snap refresh": (0, "All snaps up to date."),
    }))
    result = agent_mod.assess_snap()
    assert result["ok"] is True and result["updates"] == []


def test_assess_all_sources_tags_and_skips_absent_tools(monkeypatch):
    monkeypatch.setattr(agent_mod, "assess_updates",
                        lambda pm: {"ok": True, "error": "", "updates": [{"package": "kernel", "new_version": "5.14"}]})
    # Only flatpak is installed; snap is absent and must not appear as a
    # source at all (not as a failing one).
    monkeypatch.setattr(agent_mod.shutil, "which",
                        lambda name: "/usr/bin/flatpak" if name == "flatpak" else None)
    monkeypatch.setattr(agent_mod, "assess_flatpak",
                        lambda *a, **k: {"ok": True, "error": "", "updates": [{"package": "org.x.App", "new_version": "2"}]})

    updates, sources = agent_mod.assess_all_sources("dnf")
    by_source = {u["package"]: u["source"] for u in updates}
    assert by_source["kernel"] == "os" and by_source["org.x.App"] == "flatpak"
    names = {s["name"] for s in sources}
    assert names == {"os", "flatpak"}  # snap absent, so not reported


# ---------- custom stage scripts ----------

def _capture_custom_script_env(monkeypatch, instruction):
    """Run one stage through the custom-script path, returning the env the
    script would have been launched with."""
    a = make_agent(monkeypatch, "dnf")
    captured = {}

    monkeypatch.setattr(agent_mod.os, "makedirs", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_mod.os, "chmod", lambda *args, **kwargs: None)

    class _FakeFile:
        def write(self, _):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: _FakeFile())

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(argv, **kwargs):
        captured.update(kwargs.get("env") or {})
        return _Proc()

    monkeypatch.setattr(agent_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(a, "report", lambda *args, **kwargs: None)
    a.run_stage(instruction)
    return captured


def _instruction(**over):
    base = {
        "job_id": 42,
        "stage_name": "patch",
        "excludes": [],
        "custom_script": "#!/bin/bash\ntrue\n",
    }
    base.update(over)
    return base


def test_custom_script_receives_the_runs_severity_scope(monkeypatch):
    """Without this the operator's "Critical + Important" choice is invisible
    to a custom patch script, which then silently patches everything."""
    env = _capture_custom_script_env(
        monkeypatch, _instruction(severity_filter="Critical,Important"))
    assert env["KITE_SEVERITY"] == "Critical,Important"


def test_custom_script_severity_is_empty_for_an_unscoped_run(monkeypatch):
    env = _capture_custom_script_env(monkeypatch, _instruction(severity_filter=""))
    assert env["KITE_SEVERITY"] == ""


def test_custom_script_receives_excludes_and_pins(monkeypatch):
    env = _capture_custom_script_env(monkeypatch, _instruction(excludes=[
        {"pkg_pattern": "kernel*", "mode": "skip", "version": ""},
        {"pkg_pattern": "nginx", "mode": "pin", "version": "1.24"},
    ]))
    assert env["KITE_EXCLUDES"] == "kernel*"
    assert env["KITE_PINS"] == "nginx=1.24"
    assert env["KITE_JOB_ID"] == "42"
    assert env["KITE_STAGE"] == "patch"


# ---------- network discovery ----------

SS_OUTPUT = """\
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1012,fd=3))
tcp   LISTEN 0      128             [::]:22            [::]:*    users:(("sshd",pid=1012,fd=4))
tcp   LISTEN 0      511        10.0.20.5:443        0.0.0.0:*    users:(("nginx",pid=2210,fd=6),("nginx",pid=2211,fd=6))
tcp   LISTEN 0      4096       127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=900,fd=5))
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=700,fd=12))
udp   UNCONN 0      0     [fe80::1]%eth0:546           [::]:*
tcp   ESTAB  0      0          10.0.20.5:22      10.0.20.9:51515 users:(("sshd",pid=3000,fd=4))
tcp   LISTEN 0      128                *:9100             *:*    users:(("node_exporter",pid=55,fd=3))
garbage line
"""

IP_ADDR = [
    {"ifname": "lo", "link_type": "loopback", "address": "00:00:00:00:00:00", "flags": ["LOOPBACK", "UP"],
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
    {"ifname": "eth0", "link_type": "ether", "address": "BC:24:11:AA:BB:CC", "flags": ["BROADCAST", "UP", "LOWER_UP"],
     "addr_info": [{"family": "inet", "local": "10.0.20.5", "prefixlen": 24, "scope": "global"},
                   {"family": "inet6", "local": "fe80::be24:11ff:feaa:bbcc", "prefixlen": 64, "scope": "link"}]},
    {"ifname": "eth1", "link_type": "ether", "address": "bc:24:11:00:00:01", "flags": ["BROADCAST"],
     "addr_info": []},
    {"ifname": "veth1a2b", "link_type": "ether", "address": "aa:aa:aa:aa:aa:aa", "flags": ["UP"],
     "linkinfo": {"info_kind": "veth"}, "addr_info": []},
    {"ifname": "docker0", "link_type": "ether", "address": "02:42:00:00:00:01", "flags": ["UP"],
     "linkinfo": {"info_kind": "bridge"},
     "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "scope": "global"}]},
]


def test_ss_parsing_keeps_listeners_and_handles_every_address_form():
    found = {(p["proto"], p["address"], p["port"]): p for p in agent_mod.parse_ss_listening(SS_OUTPUT)}
    assert ("tcp", "0.0.0.0", 22) in found and ("tcp", "::", 22) in found
    assert found[("tcp", "10.0.20.5", 443)]["process"] == "nginx"
    assert found[("tcp", "127.0.0.1", 5432)]["loopback"] is True
    assert found[("udp", "127.0.0.53", 53)]["loopback"] is True       # scope suffix stripped
    assert ("udp", "fe80::1", 546) in found and found[("udp", "fe80::1", 546)]["process"] == ""
    assert found[("tcp", "0.0.0.0", 9100)]["process"] == "node_exporter"  # '*' bound
    assert not any(p["port"] == 51515 or p["address"] == "10.0.20.9" for p in found.values())  # ESTAB dropped
    assert len(found) == 7


def test_ip_addr_parsing_skips_loopback_and_bare_plumbing():
    ifaces = {i["name"]: i for i in agent_mod.parse_ip_addr(IP_ADDR)}
    assert set(ifaces) == {"eth0", "eth1", "docker0"}
    assert ifaces["eth0"] == {"name": "eth0", "mac": "bc:24:11:aa:bb:cc", "kind": "", "up": True,
                              "addresses": ["10.0.20.5/24"]}   # link-local dropped, MAC lowercased
    assert ifaces["eth1"]["up"] is False and ifaces["eth1"]["addresses"] == []
    assert ifaces["docker0"]["kind"] == "bridge"


def test_discover_network_combines_the_three_commands(monkeypatch):
    def fake(cmd, **kw):
        if cmd[:2] == ["ip", "-d"]:
            return 0, json.dumps(IP_ADDR)
        if cmd[:3] == ["ip", "-j", "route"]:
            return 0, json.dumps([{"dst": "default", "gateway": "10.0.20.1", "dev": "eth0"}])
        if cmd[0] == "ss":
            return 0, SS_OUTPUT
        raise AssertionError(cmd)
    monkeypatch.setattr(agent_mod, "run_cmd", fake)
    net = agent_mod.discover_network()
    assert net["ok"] is True and net["default_gateway"] == "10.0.20.1"
    assert len(net["interfaces"]) == 3 and len(net["listening"]) == 7


def test_discover_network_says_when_it_could_not_tell(monkeypatch):
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda cmd, **kw: (0, json.dumps(IP_ADDR)) if cmd[0] == "ip" else (1, "command not found: ss"))
    net = agent_mod.discover_network()
    assert net["ok"] is False and "ss failed" in net["error"]
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **kw: (0, "not json"))
    assert agent_mod.discover_network()["ok"] is False


def test_inventory_report_carries_network_and_survives_its_failure(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    a.dry_run = False
    a.container_runtime = None
    sent = {}
    monkeypatch.setattr(agent_mod, "discover_containers", lambda runtime: [])
    monkeypatch.setattr(agent_mod, "assess_all_sources", lambda pm: ([], [{"name": "os", "ok": True, "error": ""}]))
    monkeypatch.setattr(a.session, "post", lambda url, json, timeout: sent.update(json))
    monkeypatch.setattr(agent_mod, "discover_network",
                        lambda: {"ok": True, "error": "", "interfaces": [], "default_gateway": "", "listening": []})
    a.report_containers()
    assert sent["network"]["ok"] is True

    def boom():
        raise RuntimeError("kaboom")
    monkeypatch.setattr(agent_mod, "discover_network", boom)
    sent.clear()
    a.report_containers()
    assert sent["network"]["ok"] is False and "kaboom" in sent["network"]["error"]
    assert "updates" in sent  # the rest of the report still went out


# ---------- dnf: updates that can't be installed ----------

_DNF_BEST_FAIL = """Last metadata expiration check: 0:14:09 ago.
(try to add '--skip-broken' to skip uninstallable packages or '--nobest' to use not only best candidate packages)
Error: 
 Problem: cannot install the best update candidate for package log-shipper-1.2.0-1.el8.x86_64
  - nothing provides libc.so.6(GLIBC_2.34)(64bit) needed by log-shipper-9.0.1-1.x86_64 from vendor-repo
  - nothing provides libm.so.6(GLIBC_2.29)(64bit) needed by log-shipper-9.0.1-1.x86_64 from vendor-repo
"""

_DNF_SKIPPED = """Dependencies resolved.
 Problem: cannot install the best update candidate for package log-shipper-1.2.0-1.el8.x86_64
  - nothing provides libc.so.6(GLIBC_2.34)(64bit) needed by log-shipper-9.0.1-1.x86_64 from vendor-repo
================================================================================
 Package          Arch      Version          Repository      Size
================================================================================
Upgrading:
 openssl          x86_64    1:1.1.1k-14.el8  baseos          710 k
Skipping packages with broken dependencies:
 other-agent      x86_64    3.0-1            vendor-repo     12 M

Transaction Summary
Complete!
"""


def _dnf_patch(monkeypatch, rc, out, skip=False):
    a = make_agent(monkeypatch, "dnf")
    a._skip_uninstallable = skip
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd",
                         lambda cmd, dry_run=False, timeout=1800, env=None: (calls.append(cmd), (rc, out))[1])
    status, output = a.stage_patch(1, [])
    return status, output, calls[0]


def test_an_uninstallable_update_is_named_with_its_repo_and_the_fix(monkeypatch):
    status, output, cmd = _dnf_patch(monkeypatch, 1, _DNF_BEST_FAIL)
    assert status == "failed"
    assert "--nobest" not in cmd and "--skip-broken" not in cmd       # off unless the policy asks
    first = output.splitlines()
    assert first[0].startswith("dnf stopped before installing anything")
    assert first[1] == ("[uninstallable] log-shipper 9.0.1-1 (from vendor-repo) needs libc.so.6(GLIBC_2.34)(64bit), "
                        "libm.so.6(GLIBC_2.29)(64bit), which this system doesn't provide")
    assert "add a 'skip' update rule" in output
    assert "nothing provides libc.so.6" in output                     # dnf's own words still follow


def test_skipping_uninstallable_updates_installs_the_rest_and_lists_them(monkeypatch):
    status, output, cmd = _dnf_patch(monkeypatch, 0, _DNF_SKIPPED, skip=True)
    assert status == "done"
    assert "--nobest" in cmd and "--skip-broken" in cmd
    lines = output.splitlines()
    assert lines[0].startswith("Installed what could be installed")
    assert any(l.startswith("[skipped] log-shipper 9.0.1-1 (from vendor-repo)") for l in lines)
    assert any(l.startswith("[skipped] other-agent 3.0-1 (from vendor-repo)") for l in lines)
    assert not any("openssl" in l for l in lines if l.startswith("[skipped]"))


def test_an_unrelated_dnf_failure_is_passed_through(monkeypatch):
    status, output, _ = _dnf_patch(monkeypatch, 1, "Error: Failed to download metadata for repo 'x'")
    assert status == "failed" and output == "Error: Failed to download metadata for repo 'x'"


def test_the_skip_flag_comes_from_the_instruction(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    seen = {}
    monkeypatch.setattr(a, "stage_patch", lambda job_id, excludes: (seen.setdefault("skip", a._skip_uninstallable), ("done", ""))[1])
    monkeypatch.setattr(a, "report", lambda *args, **kw: None)
    a.run_stage({"job_id": 1, "stage_name": "patch", "excludes": [], "skip_uninstallable": True})
    assert seen["skip"] is True



# ---------- the runtime just after a reboot ----------

class _Clock:
    def __init__(self):
        self.t = 0.0
    def monotonic(self):
        return self.t
    def sleep(self, s):
        self.t += s


def _real_wait(monkeypatch, agent):
    clock = _Clock()
    monkeypatch.setattr(agent_mod.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(agent_mod.time, "sleep", clock.sleep)
    return agent_mod.Agent._wait_for_runtime.__get__(agent), clock


def test_containers_wait_for_the_runtime_to_answer(monkeypatch):
    agent = make_agent(monkeypatch, "dnf")
    agent.container_runtime = "docker"
    agent._wait_for_runtime, clock = _real_wait(monkeypatch, agent)
    answers = iter([(1, "Cannot connect to the Docker daemon"), (1, "timed out"), (0, "27.1.1")])
    calls = []

    def fake(cmd, **k):
        calls.append(cmd)
        if cmd[1] == "info":
            return next(answers)
        return (0, "sha256:abc")
    monkeypatch.setattr(agent_mod, "run_cmd", fake)
    status, output = agent.stage_containers(1, [_compose("web")])
    assert status == "done"
    assert [c[1] for c in calls[:3]] == ["info", "info", "info"]        # nothing touched before it answered
    assert "waited 10s for docker to be ready" in output


def test_a_runtime_that_never_answers_fails_without_changing_anything(monkeypatch):
    agent = make_agent(monkeypatch, "dnf")
    agent.container_runtime = "docker"
    agent._wait_for_runtime, clock = _real_wait(monkeypatch, agent)
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (1, "no daemon"))[1])
    status, output = agent.stage_containers(1, [_compose("web")])
    assert status == "failed" and "did not answer for 300s" in output and "nothing was changed" in output
    assert all(c[1] == "info" for c in calls)


def test_a_slow_inspect_is_retried(monkeypatch):
    agent = make_agent(monkeypatch, "dnf")
    agent.container_runtime = "docker"
    monkeypatch.setattr(agent_mod.time, "sleep", lambda s: None)
    inspects = iter([(1, "command timed out after 90s: docker container inspect web"), (0, "sha256:abc")])

    def fake(cmd, **k):
        if cmd[1:3] == ["container", "inspect"] and cmd[-1] != "{{json .Config.Labels}}":
            return next(inspects)
        return (0, "ok")
    monkeypatch.setattr(agent_mod, "run_cmd", fake)
    status, output = agent.stage_containers(1, [_compose("web")])
    assert status == "done" and "captured web" in output


def test_a_real_inspect_error_is_not_retried(monkeypatch):
    agent = make_agent(monkeypatch, "dnf")
    agent.container_runtime = "docker"
    n = {"inspect": 0}

    def fake(cmd, **k):
        if cmd[1:3] == ["container", "inspect"]:
            n["inspect"] += 1
            return (1, "Error: No such container: web")
        return (0, "ok")
    monkeypatch.setattr(agent_mod, "run_cmd", fake)
    status, output = agent.stage_containers(1, [_compose("web")])
    assert status == "failed" and n["inspect"] == 1 and "No such container" in output



def test_self_update_ignores_a_malformed_target(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, ""))[1])
    a.self_update("1.0; rm -rf /")
    assert calls == []


# ---------- apt: what an upgrade left out ----------

_APT_UPGRADE = """Reading package lists...
Calculating upgrade...
The following upgrades have been deferred due to phasing:
  release-helper-core
The following packages have been kept back:
  kernel-meta kernel-headers-meta
  extra-meta
The following packages will be upgraded:
  openssl libssl3
2 upgraded, 0 newly installed, 0 to remove and 4 not upgraded.
"""


def test_apt_kept_back_and_phased_are_listed_first(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd",
                        lambda cmd, **k: (0, _APT_UPGRADE if "upgrade" in cmd else "Hit:1 http://archive"))
    status, output = a.stage_patch(1, [])
    lines = output.splitlines()
    assert status == "done" and lines[0].startswith("Installed what apt would install")
    kept = [l.split()[1] for l in lines if l.startswith("[kept-back]")]
    assert kept == ["kernel-meta", "kernel-headers-meta", "extra-meta"]      # wrapped lines included
    assert [l.split()[1] for l in lines if l.startswith("[phased]")] == ["release-helper-core"]
    assert "openssl" not in "\n".join(l for l in lines if l.startswith("["))


def test_apt_with_nothing_held_back_is_unchanged(monkeypatch):
    a = make_agent(monkeypatch, "apt")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (0, "2 upgraded, 0 not upgraded."))
    status, output = a.stage_patch(1, [])
    assert status == "done" and not output.startswith("Installed what apt")


# ---------- Debian/Ubuntu self-update from the controller's bundle ----------

import hashlib  # noqa: E402
import io  # noqa: E402
import tarfile  # noqa: E402


def _bundle(version, unit=b"[Service]\nExecStart=/usr/bin/python3 /opt/kite-agent/agent.py\n"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in {"agent-linux/agent.py": f'AGENT_VERSION = "{version}"\n'.encode(),
                           "agent-linux/enroll.py": b"# enroll\n",
                           "agent-linux/kite-agent.service": unit}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _Resp:
    def __init__(self, content, sha=None):
        self.content = content
        self.headers = {"X-Kite-Sha256": sha if sha is not None else hashlib.sha256(content).hexdigest()}

    def raise_for_status(self):
        pass


def _apt_agent(monkeypatch, tmp_path, content, sha=None):
    a = make_agent(monkeypatch, "apt")
    a.install_dir = str(tmp_path)
    a.UNIT_PATH = str(tmp_path / "kite-agent.service")
    (tmp_path / "agent.py").write_text('AGENT_VERSION = "0.1.11"\n')
    monkeypatch.setattr(a.session, "get", lambda url, **k: _Resp(content, sha))
    calls = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (calls.append(cmd), (0, ""))[1])
    return a, calls


def test_ubuntu_agent_updates_itself_from_the_bundle(monkeypatch, tmp_path):
    a, calls = _apt_agent(monkeypatch, tmp_path, _bundle("0.1.12"))
    a.self_update("0.1.12")
    assert (tmp_path / "agent.py").read_text() == 'AGENT_VERSION = "0.1.12"\n'
    assert (tmp_path / "agent.py.prev").read_text() == 'AGENT_VERSION = "0.1.11"\n'   # the way back
    assert (tmp_path / "enroll.py").exists()
    assert ["systemctl", "daemon-reload"] in calls                                  # new unit file
    assert calls[-1] == ["systemctl", "try-restart", "kite-agent"]


def test_ubuntu_update_refuses_a_bundle_of_another_version(monkeypatch, tmp_path):
    a, calls = _apt_agent(monkeypatch, tmp_path, _bundle("0.1.11"))
    a.self_update("0.1.12")
    assert (tmp_path / "agent.py").read_text() == 'AGENT_VERSION = "0.1.11"\n' and calls == []


def test_ubuntu_update_refuses_a_bundle_that_fails_its_checksum(monkeypatch, tmp_path):
    a, calls = _apt_agent(monkeypatch, tmp_path, _bundle("0.1.12"), sha="0" * 64)
    a.self_update("0.1.12")
    assert (tmp_path / "agent.py").read_text() == 'AGENT_VERSION = "0.1.11"\n' and calls == []
    a.self_update("0.1.12")                         # and doesn't retry on the very next poll
    assert calls == []


# ---------- installed software ----------

_RPM_OUT = ("openssl-libs\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\tRocky Enterprise Software Foundation\n"
            "gpg-pubkey\t0\tabc\t123\t(none)\t(none)\t(none)\n"
            "bash\t0\t5.1.8\t9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\t(none)\n")
_DPKG_OUT = ("libssl3t64\t3.0.13-0ubuntu3.4\tamd64\topenssl\t3.0.13-0ubuntu3.4\tii \n"
             "bash\t5.2.21-2ubuntu4\tamd64\t\t\tii \n"
             "oldpkg\t1.0\tamd64\toldpkg\t1.0\trc \n")


def test_rpm_packages_carry_their_source_rpm():
    items = agent_mod.parse_rpm_qa(_RPM_OUT)
    assert [i["name"] for i in items] == ["openssl-libs", "bash"]                 # no gpg-pubkey
    assert items[0]["version"] == "1:3.0.7-27.el9"                                 # epoch kept
    assert (items[0]["source_name"], items[0]["source_version"]) == ("openssl", "3.0.7-27.el9")
    assert items[1]["version"] == "5.1.8-9.el9" and items[1]["publisher"] == ""


def test_deb_packages_are_installed_ones_with_their_source():
    items = agent_mod.parse_dpkg_query(_DPKG_OUT)
    assert [i["name"] for i in items] == ["libssl3t64", "bash"]                   # 'rc' = removed, config left
    assert items[0]["source_name"] == "openssl"
    assert (items[1]["source_name"], items[1]["source_version"]) == ("bash", "5.2.21-2ubuntu4")   # source = itself


def test_snap_and_flatpak_lists():
    snaps = agent_mod.parse_snap_list("Name  Version  Rev  Tracking  Publisher  Notes\nlxd  5.21.2  29351  5.21/stable  canonical✓  -\n")
    assert snaps == [{"kind": "snap", "name": "lxd", "version": "5.21.2", "publisher": "canonical"}]
    flats = agent_mod.parse_flatpak_list("org.mozilla.firefox\t131.0\n")
    assert flats == [{"kind": "flatpak", "name": "org.mozilla.firefox", "version": "131.0"}]


def _software_agent(monkeypatch, items):
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(agent_mod, "collect_software", lambda pm, timeout=120: (list(items), ""))
    return a


class _R:
    def __init__(self, body, code=200):
        self._body, self.status_code = body, code

    def json(self):
        return self._body


def test_the_list_is_sent_only_when_it_changed(monkeypatch):
    items = agent_mod.parse_rpm_qa(_RPM_OUT)
    a = _software_agent(monkeypatch, items)
    first = a._software_payload()
    assert "items" in first and len(first["hash"]) == 64
    a._software_accepted(first, _R({"software_resend": False}))
    assert a._software_payload() == {"hash": first["hash"]}                     # unchanged: hash only


def test_the_controller_can_ask_for_the_list_again(monkeypatch):
    a = _software_agent(monkeypatch, agent_mod.parse_rpm_qa(_RPM_OUT))
    first = a._software_payload()
    a._software_accepted(first, _R({}))
    a._software_accepted({"hash": first["hash"]}, _R({"software_resend": True}))
    assert "items" in a._software_payload()
    a._software_accepted({"hash": first["hash"], "items": []}, _R({}, code=500))  # a failed report: send again
    assert "items" in a._software_payload()


def test_an_unreadable_package_database_sends_nothing(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(agent_mod, "collect_software", lambda pm, timeout=120: (None, "rpm -qa failed"))
    assert a._software_payload() is None


def test_the_hash_doesnt_depend_on_dict_order():
    one = [{"kind": "rpm", "name": "a", "version": "1"}]
    two = [{"version": "1", "name": "a", "kind": "rpm"}]
    assert agent_mod.software_hash(one) == agent_mod.software_hash(two)


# ---------- ensure_signed_repo ----------

_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n"
_OLD_REPO = ("[kite]\nname=kite agent\nbaseurl=https://controller.example/repo\nenabled=1\ngpgcheck=0\n"
             "sslverify=0\nskip_if_unavailable=1\n")


class _KeyResp:
    def __init__(self, status, text=""):
        self.status_code, self.text = status, text


def _signed_repo(monkeypatch, tmp_path, key=_KEY, signed=True, installed=None):
    repo, keyfile = tmp_path / "kite.repo", tmp_path / "pki" / "RPM-GPG-KEY-kite"
    repo.write_text(_OLD_REPO)
    if installed is not None:
        keyfile.parent.mkdir()
        keyfile.write_text(installed)
    monkeypatch.setattr(agent_mod, "REPO_FILE", str(repo))
    monkeypatch.setattr(agent_mod, "REPO_KEY_PATH", str(keyfile))
    a = make_agent(monkeypatch, "dnf")
    served = {"/repo/RPM-GPG-KEY-kite": _KeyResp(200, key) if signed else _KeyResp(404),
              "/repo/repodata/repomd.xml.asc": _KeyResp(200, "sig") if signed else _KeyResp(404)}
    monkeypatch.setattr(a.session, "get", lambda url, timeout=None: served[url[len(a.base):]])
    imported = []
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **kw: (imported.append(cmd), (0, ""))[1])
    return a, repo, keyfile, imported


def test_a_signed_controller_turns_signature_checks_on(monkeypatch, tmp_path):
    a, repo, keyfile, imported = _signed_repo(monkeypatch, tmp_path)
    assert "now checks" in a.ensure_signed_repo()
    text = repo.read_text()
    assert "gpgcheck=0" not in text and "gpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file://" in text
    assert text.startswith("[kite]\ngpgcheck=1") and "skip_if_unavailable=1" in text
    assert keyfile.read_text() == _KEY and imported == [["rpm", "--import", str(keyfile)]]
    assert a.ensure_signed_repo() == ""                       # already on: nothing to do


def test_an_unsigned_controller_leaves_the_repo_alone(monkeypatch, tmp_path):
    a, repo, keyfile, _ = _signed_repo(monkeypatch, tmp_path, signed=False)
    assert a.ensure_signed_repo() == "" and repo.read_text() == _OLD_REPO and not keyfile.exists()


def test_a_different_key_later_is_refused(monkeypatch, tmp_path):
    a, repo, keyfile, imported = _signed_repo(monkeypatch, tmp_path, installed="-----BEGIN PGP PUBLIC KEY BLOCK-----\nold\n")
    assert "mismatch" in a.ensure_signed_repo()
    assert repo.read_text() == _OLD_REPO and "old" in keyfile.read_text() and imported == []


def test_loop_sleeps_normally_when_self_update_installs_nothing(monkeypatch):
    """A failed or throttled self-update must fall through to the idle sleep, not poll again at once."""
    a = make_agent(monkeypatch, "dnf")
    polls, slept = [], []

    class _Stop(Exception):
        pass

    def sleep(seconds):
        slept.append(seconds)
        raise _Stop

    monkeypatch.setattr(a, "resume_pending_reboot", lambda: None)
    monkeypatch.setattr(a, "pin_controller_ca", lambda: "")
    monkeypatch.setattr(a, "ensure_signed_repo", lambda: "")
    monkeypatch.setattr(a, "poll_next", lambda: polls.append(1) or (None, True, "9.9.9"))
    monkeypatch.setattr(a, "self_update", lambda target: False)
    monkeypatch.setattr(a, "report_containers", lambda: None)
    monkeypatch.setattr(a, "_sleep_with_trigger_check", sleep)
    with pytest.raises(_Stop):
        a.loop()
    assert len(polls) == 1 and slept == [a.poll_interval]


def test_a_stage_handed_out_again_resends_its_report_instead_of_running_twice(monkeypatch):
    """A lost report makes the controller hand the same stage out again. Running it
    twice would re-take the containers' rollback point from the images just pulled."""
    a = make_agent(monkeypatch, "dnf")
    ran, reports = [], []
    monkeypatch.setattr(a, "stage_containers", lambda job_id, payload: ran.append(job_id) or ("done", "updated web"))
    monkeypatch.setattr(a, "report", lambda *args: reports.append(args))
    instruction = {"job_id": 9, "stage_name": "containers", "excludes": [], "containers": [{"name": "web"}]}

    a.run_stage(instruction)
    a.run_stage(dict(instruction))
    assert ran == [9]
    assert reports == [(9, "containers", "done", "updated web")] * 2

    a.run_stage(dict(instruction, job_id=10))     # another run's stage runs as usual
    assert ran == [9, 10]


# ---------- the controller's certificate ----------

# A throwaway self-signed root made for these tests.
_ROOT = """-----BEGIN CERTIFICATE-----
MIIBOzCB4qADAgECAgEBMAoGCCqGSM49BAMCMB0xGzAZBgNVBAMMEnBhdGNoY3Rs
IHRlc3Qgcm9vdDAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMB0xGzAZ
BgNVBAMMEnBhdGNoY3RsIHRlc3Qgcm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABL7I4XXIXhHZjq1/LHvgljmr80ZNhQcocO6r60ru+grnLDcidY3MPbd+Mra0
elxCnXO8roQC285OUl5n/WSYfsWjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDSAAwRQIgPKe/LSCmpZUD4n9P0mtp7omofchuDq4K2TzaQVg6ykoCIQCH
GOIPhCnLRfm/w7dILhQev4jiBHNSKDzg3tJvQSN5+A==
-----END CERTIFICATE-----
"""


def _insecure_agent(monkeypatch, tmp_path, served, checked_ok=True, repo_text=None):
    """An agent enrolled with --insecure; `served` is what GET /download/ca.crt answers."""
    conf = tmp_path / "agent.conf"
    conf.write_text(json.dumps({"controller_url": "https://controller.example", "host_id": 1,
                                "agent_secret": "s", "verify_tls": False}))
    repo = tmp_path / "kite.repo"
    repo.write_text(repo_text if repo_text is not None else "[kite]\nbaseurl=https://controller.example/repo\nsslverify=0\n")
    monkeypatch.setattr(agent_mod, "CONFIG_PATH", str(conf))
    monkeypatch.setattr(agent_mod, "CA_PATH", str(tmp_path / "controller-ca.crt"))
    monkeypatch.setattr(agent_mod, "REPO_FILE", str(repo))
    monkeypatch.setattr(agent_mod, "detect_package_manager", lambda: "dnf")
    a = agent_mod.Agent(json.loads(conf.read_text()))
    assert a.session.verify is False
    monkeypatch.setattr(a.session, "get", lambda url, timeout=None: served)
    checks = []

    def checked_get(url, timeout=None, verify=None):
        checks.append((url, verify, open(verify).read() if isinstance(verify, str) else None))
        if not checked_ok:
            raise agent_mod.requests.ConnectionError("certificate verify failed")

        class R:
            def raise_for_status(self):
                pass
        return R()
    monkeypatch.setattr(agent_mod.requests, "get", checked_get)
    return a, conf, repo, checks


def test_an_insecure_agent_pins_the_controllers_ca(monkeypatch, tmp_path):
    a, conf, repo, checks = _insecure_agent(monkeypatch, tmp_path, _KeyResp(200, _ROOT))
    note = a.pin_controller_ca()
    ca = str(tmp_path / "controller-ca.crt")
    assert "now checked against its CA" in note
    assert checks == [("https://controller.example/health", ca + ".new", _ROOT)]   # tried before switching
    assert open(ca).read() == _ROOT and a.session.verify == ca
    saved = json.loads(conf.read_text())
    assert saved["verify_tls"] is True and saved["ca_cert"] == ca and saved["agent_secret"] == "s"
    assert "sslverify=1\nsslcacert=" + ca in repo.read_text() and "sslverify=0" not in repo.read_text()
    assert a.pin_controller_ca() == ""          # done: nothing more to do


def test_a_check_that_fails_leaves_the_agent_as_it_was(monkeypatch, tmp_path):
    """Locking the agent out of its controller would be worse than not checking."""
    a, conf, repo, _ = _insecure_agent(monkeypatch, tmp_path, _KeyResp(200, _ROOT), checked_ok=False)
    assert "still not checked" in a.pin_controller_ca()
    assert a.session.verify is False and json.loads(conf.read_text())["verify_tls"] is False
    assert not list(tmp_path.glob("controller-ca.crt*")) and "sslverify=0" in repo.read_text()


def test_a_public_certificate_is_checked_against_the_system_cas(monkeypatch, tmp_path):
    a, conf, repo, checks = _insecure_agent(monkeypatch, tmp_path, _KeyResp(404, "public CA"))
    assert "the system CAs" in a.pin_controller_ca()
    assert checks[0][1] is True and a.session.verify is True
    assert "ca_cert" not in json.loads(conf.read_text())
    assert "sslverify=1\n" in repo.read_text() and "sslcacert" not in repo.read_text()


def test_junk_instead_of_a_certificate_changes_nothing(monkeypatch, tmp_path):
    a, conf, _, checks = _insecure_agent(monkeypatch, tmp_path, _KeyResp(200, "<html>proxy login</html>"))
    assert "isn't a certificate" in a.pin_controller_ca()
    assert checks == [] and a.session.verify is False


def test_a_pinned_ca_is_used_from_the_start(monkeypatch, tmp_path):
    ca = tmp_path / "controller-ca.crt"
    ca.write_text(_ROOT)
    a = agent_mod.Agent({"controller_url": "https://c", "host_id": 1, "agent_secret": "s",
                         "verify_tls": True, "ca_cert": str(ca)})
    assert a.session.verify == str(ca)


def test_enroll_checks_the_fingerprint_before_trusting_the_ca(monkeypatch, tmp_path):
    import enroll
    good = enroll.ca_fingerprint(_ROOT)
    monkeypatch.setattr(enroll.requests, "get", lambda url, timeout=None, verify=None: _KeyResp(200, _ROOT))
    assert enroll.fetch_controller_ca("https://c", good.upper()) == _ROOT       # case and colons don't matter
    assert enroll.fetch_controller_ca("https://c", ":".join(good[i:i + 2] for i in range(0, 64, 2))) == _ROOT
    with pytest.raises(SystemExit, match="impersonating"):
        enroll.fetch_controller_ca("https://c", "0" * 64)


def test_enroll_with_a_fingerprint_pins_the_ca_for_the_enrolment_itself(monkeypatch, tmp_path):
    import enroll
    monkeypatch.setattr(enroll, "CONFIG_PATH", str(tmp_path / "agent.conf"))
    monkeypatch.setattr(enroll, "CA_PATH", str(tmp_path / "controller-ca.crt"))
    monkeypatch.setattr(enroll.requests, "get", lambda url, timeout=None, verify=None: _KeyResp(200, _ROOT))
    posted = []

    class Enrolled:
        status_code = 200

        def json(self):
            return {"host_id": 4, "agent_secret": "s"}

    monkeypatch.setattr(enroll.requests, "post", lambda url, json=None, timeout=None, verify=None:
                        posted.append(verify) or Enrolled())
    monkeypatch.setattr(enroll.sys, "argv", ["enroll.py", "--controller", "https://c/", "--token", "t",
                                             "--ca-fingerprint", enroll.ca_fingerprint(_ROOT)])
    enroll.main()
    ca = str(tmp_path / "controller-ca.crt")
    assert posted == [ca] and open(ca).read() == _ROOT
    conf = json.loads((tmp_path / "agent.conf").read_text())
    assert conf["ca_cert"] == ca and conf["verify_tls"] is True and conf["controller_url"] == "https://c"


# ---------- reboot: asked for once, reported once it happened ----------

def _reboot_paths(monkeypatch, tmp_path, boot="boot-1"):
    monkeypatch.setattr(agent_mod, "STATE_PATH", str(tmp_path / "pending_reboot.json"))
    monkeypatch.setattr(agent_mod, "_boot_id", lambda: boot)


def test_a_refused_reboot_fails_the_stage(monkeypatch, tmp_path):
    _reboot_paths(monkeypatch, tmp_path)
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (1, "needs a reboot") if cmd[0] == "needs-restarting"
                        else (1, "Failed to reboot: Access denied"))
    status, output = a.stage_reboot(5, [])
    assert status == "failed" and "Access denied" in output
    assert not os.path.exists(agent_mod.STATE_PATH)


def test_an_agent_restart_isnt_a_reboot(monkeypatch, tmp_path):
    """A self-update restarting the agent while the reboot is pending mustn't report it done."""
    _reboot_paths(monkeypatch, tmp_path)
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(agent_mod, "run_cmd", lambda cmd, **k: (1, "") if cmd[0] == "needs-restarting" else (0, ""))
    assert a.stage_reboot(5, []) == ("deferred", "")
    reports = []
    monkeypatch.setattr(a, "report", lambda *args: reports.append(args) or True)
    a.resume_pending_reboot()
    assert reports == [] and a.reboot_pending()
    monkeypatch.setattr(agent_mod, "_boot_id", lambda: "boot-2")      # now it has rebooted
    a.resume_pending_reboot()
    assert [r[:3] for r in reports] == [(5, "reboot", "done")] and not os.path.exists(agent_mod.STATE_PATH)


def test_a_reboot_report_that_doesnt_arrive_is_sent_again(monkeypatch, tmp_path):
    _reboot_paths(monkeypatch, tmp_path, boot="boot-2")
    with open(agent_mod.STATE_PATH, "w") as f:
        json.dump({"job_id": 5, "boot_id": "boot-1"}, f)
    a = make_agent(monkeypatch, "dnf")
    monkeypatch.setattr(a, "report", lambda *args: False)
    a.resume_pending_reboot()
    assert os.path.exists(agent_mod.STATE_PATH)       # kept for the next try
    monkeypatch.setattr(a, "report", lambda *args: True)
    a.resume_pending_reboot()
    assert not os.path.exists(agent_mod.STATE_PATH)


def test_a_corrupt_reboot_file_is_set_aside_not_a_crash_loop(monkeypatch, tmp_path):
    _reboot_paths(monkeypatch, tmp_path)
    with open(agent_mod.STATE_PATH, "w") as f:
        f.write("{not json")
    a = make_agent(monkeypatch, "dnf")
    a.resume_pending_reboot()
    assert not os.path.exists(agent_mod.STATE_PATH) and os.path.exists(agent_mod.STATE_PATH + ".bad")


def test_after_asking_for_a_reboot_the_agent_waits_instead_of_polling(monkeypatch, tmp_path):
    """Polling straight away was handed the reboot stage again, and rebooted a second time."""
    _reboot_paths(monkeypatch, tmp_path)
    with open(agent_mod.STATE_PATH, "w") as f:
        json.dump({"job_id": 5, "boot_id": "boot-1"}, f)
    a = make_agent(monkeypatch, "dnf")
    polls, slept = [], []

    class _Stop(Exception):
        pass

    def sleep(seconds):
        slept.append(seconds)
        raise _Stop

    for name in ("pin_controller_ca", "ensure_signed_repo"):
        monkeypatch.setattr(a, name, lambda: "")
    monkeypatch.setattr(a, "poll_next", lambda: polls.append(1) or (None, True, None))
    monkeypatch.setattr(agent_mod.time, "sleep", sleep)
    with pytest.raises(_Stop):
        a.loop()
    assert polls == [] and slept == [a.REBOOT_WAIT_SECONDS]


def test_a_failing_startup_step_doesnt_stop_the_agent(monkeypatch):
    a = make_agent(monkeypatch, "dnf")
    polls = []

    class _Stop(Exception):
        pass

    def boom():
        raise OSError("read-only file system")

    monkeypatch.setattr(a, "resume_pending_reboot", lambda: None)
    monkeypatch.setattr(a, "reboot_pending", lambda: False)
    monkeypatch.setattr(a, "pin_controller_ca", boom)
    monkeypatch.setattr(a, "ensure_signed_repo", boom)

    def poll():
        polls.append(1)
        raise _Stop

    monkeypatch.setattr(a, "poll_next", poll)
    with pytest.raises(_Stop):
        a.loop()
    assert polls == [1]


def test_dnf_assessment_keeps_epel_ids_and_updates_without_errata(monkeypatch):
    """EPEL's ids have no '/' or ':' and were dropped; repos with no errata weren't seen at all."""
    info = ("RLSA-2026:1 Important/Sec. openssl-libs-1:3.0.7-27.el9.x86_64\n"
            "FEDORA-EPEL-2026-1a2b3c4d bugfix htop-3.3.0-2.el9.x86_64\n")
    check = ("openssl-libs.x86_64      1:3.0.7-27.el9      baseos\n"
             "htop.x86_64              3.3.0-2.el9         epel\n"
             "vendor-tool.noarch       2.1.0-1             vendor-repo\n"
             "Obsoleting Packages\n")

    def fake(cmd, **k):
        if "updateinfo" in cmd:
            return 0, info
        if "check-update" in cmd:
            return 100, check
        return 0, ""
    monkeypatch.setattr(agent_mod, "run_cmd", fake)
    got = {u["package"]: u for u in agent_mod._assess_dnf()["updates"]}
    assert got["htop"]["advisory"] == "FEDORA-EPEL-2026-1a2b3c4d"
    assert got["openssl-libs"]["severity"] == "important"
    assert got["vendor-tool"] == {"package": "vendor-tool", "new_version": "vendor-tool-2.1.0-1.noarch",
                                  "advisory": "", "severity": "none", "is_security": False}
    assert len(got) == 3


def test_repo_options_go_into_the_kite_section_only():
    text = ("[other]\nbaseurl=https://x\ngpgcheck=0\nsslverify=0\n\n"
            "[kite]\nname=kite agent\ngpgcheck=0\nsslverify=0\nskip_if_unavailable=1\n")
    out = agent_mod._set_repo_options(text, ["sslverify=1", "sslcacert=/etc/kite/controller-ca.crt"],
                                      ["sslverify", "sslcacert"])
    other, ours = out.split("[kite]")
    assert "sslverify=0" in other and "gpgcheck=0" in other            # untouched
    assert "sslverify=1\nsslcacert=/etc/kite/controller-ca.crt" in ours and "sslverify=0" not in ours
    assert "skip_if_unavailable=1" in ours
