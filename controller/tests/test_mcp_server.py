"""
tools/kite_mcp.py, the local read-only MCP server.

Two layers: the JSON-RPC/MCP handshake over real stdio (a subprocess,
the way an MCP client actually runs it), and the tools themselves, with
the server's HTTP client pointed at the app through TestClient and a
real read token -- so the controller-side auth is exercised too, not
mocked.
"""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import models
from app.main import app
from conftest import make_host

SCRIPT = Path(__file__).resolve().parent.parent / "tools" / "kite_mcp.py"

_spec = importlib.util.spec_from_file_location("kite_mcp", SCRIPT)
mcp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mcp)


class _TestController(mcp.Controller):
    """The real Controller's surface, served by TestClient instead of urllib."""
    def __init__(self, token):
        self.base, self.token = "http://testserver", token
        self.http = TestClient(app)

    def get(self, path, **params):
        resp = self.http.get(path, params={k: v for k, v in params.items() if v is not None},
                             headers={"Authorization": f"Bearer {self.token}"})
        if resp.status_code >= 400:
            raise mcp.ApiError(f"{path}: HTTP {resp.status_code} {resp.json().get('detail', '')}")
        return resp.json()


@pytest.fixture
def api(client, logged_in):
    logged_in("operator")
    return _TestController(client.post("/tokens", json={"name": "mcp-test"}).json()["token"])


def _call(api, name, **arguments):
    reply = mcp.handle(api, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": name, "arguments": arguments}})
    result = reply["result"]
    text = result["content"][0]["text"]
    return result["isError"], (text if result["isError"] else json.loads(text))


def _stdio(messages, env_extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("KITE_")}
    env.update(env_extra)
    proc = subprocess.run([sys.executable, str(SCRIPT)], input="\n".join(json.dumps(m) for m in messages) + "\n",
                          capture_output=True, text=True, env=env, timeout=30)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()], proc.stderr


def test_stdio_handshake_and_tool_list():
    replies, _ = _stdio([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        {"jsonrpc": "2.0", "id": 4, "method": "resources/list"},
    ], {"KITE_URL": "http://127.0.0.1:9", "KITE_TOKEN": "kite_x"})
    assert [r["id"] for r in replies] == [1, 2, 3, 4]  # the notification got no reply
    init = replies[0]["result"]
    assert init["protocolVersion"] == "2025-06-18"
    assert init["serverInfo"]["name"] == "kite"
    assert "untrusted" in init["instructions"]
    tools = replies[1]["result"]["tools"]
    assert {t["name"] for t in tools} >= {"fleet_summary", "list_hosts", "get_run", "proxmox_coverage", "fleet_topology"}
    assert all(t["annotations"]["readOnlyHint"] for t in tools)
    assert replies[2]["result"] == {}
    assert replies[3]["error"]["code"] == -32601


def test_unknown_protocol_version_gets_ours():
    reply = mcp.handle(None, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}})
    assert reply["result"]["protocolVersion"] == mcp.SUPPORTED_PROTOCOLS[0]


def test_misconfigured_server_still_starts_and_explains(tmp_path):
    replies, stderr = _stdio([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}},
    ], {})
    assert "KITE_URL is not set" in stderr
    assert replies[1]["result"]["isError"] is True
    assert "misconfigured" in replies[1]["result"]["content"][0]["text"]


def test_check_mode_rejects_a_non_token(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("hunter2\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("KITE_")}
    env.update({"KITE_URL": "http://127.0.0.1:9", "KITE_TOKEN_FILE": str(token_file)})
    proc = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True, env=env, timeout=30)
    assert proc.returncode == 1
    assert "start with 'kite_'" in proc.stderr


def test_whoami_and_fleet_summary(api):
    err, me = _call(api, "whoami")
    assert not err and me["role"] == "operator"
    err, summary = _call(api, "fleet_summary")
    assert not err and "fleet" in summary


def test_list_hosts_filters_and_unknown_is_not_zero(api, db):
    crit, _ = make_host(db)
    broken, _ = make_host(db)
    broken.updates_assessed_ok = False
    db.add(models.PendingUpdate(host_id=crit.id, package="kernel", severity="critical", is_security=True))
    db.commit()
    err, data = _call(api, "list_hosts", min_severity="critical")
    assert not err
    names = [h["hostname"] for h in data["hosts"]]
    assert crit.hostname in names and broken.hostname not in names
    err, data = _call(api, "list_hosts", search=broken.hostname)
    assert data["hosts"][0]["pending_updates"] is None


def test_get_host_by_short_name_and_pending_updates(api, db):
    host, _ = make_host(db, hostname=f"mcpbox{os.getpid()}.lab.example")
    db.add_all([models.PendingUpdate(host_id=host.id, package="openssl", severity="important", is_security=True),
                models.PendingUpdate(host_id=host.id, package="vim", severity="low")])
    db.commit()
    err, data = _call(api, "get_host", host=f"mcpbox{os.getpid()}")
    assert not err and data["host"]["id"] == host.id
    assert data["pending_by_severity"] == {"important": 1, "low": 1}
    err, data = _call(api, "list_pending_updates", host=host.hostname, security_only=True)
    assert [u["package"] for u in data["updates"]] == ["openssl"]
    err, data = _call(api, "list_pending_updates", package="openssl", min_severity="important")
    assert host.hostname in [u["hostname"] for u in data["updates"]]


def test_get_host_unknown_is_a_readable_tool_error(api):
    err, text = _call(api, "get_host", host="no-such-host-anywhere")
    assert err and "No host" in text


def test_runs_and_stage_output_truncation(api, db, monkeypatch):
    host, _ = make_host(db)
    job = models.Job(host_id=host.id, hostname=host.hostname, ticket_id="CHG-1", status="failed")
    db.add(job)
    db.flush()
    db.add(models.JobStage(job_id=job.id, stage_index=0, name="patch", executor="agent",
                           status="failed", output="x" * 50 + "THE-END"))
    db.commit()
    monkeypatch.setenv("KITE_MAX_OUTPUT", "10")
    err, runs = _call(api, "list_runs", host=host.hostname, status="failed")
    assert not err and runs["runs"][0]["failed_stages"] == ["patch"]
    assert runs["runs"][0]["created_at"]
    err, run = _call(api, "get_run", run_id=job.id)
    out = run["stages"][0]["output_untrusted"]
    assert out.endswith("xxxTHE-END") and "earlier characters omitted" in out


def test_tools_cannot_reach_write_endpoints(api):
    # Belt and braces: even a hand-built request with this token is refused.
    resp = api.http.post("/runs", json={}, headers={"Authorization": f"Bearer {api.token}"})
    assert resp.status_code == 403


def test_revoked_token_surfaces_as_tool_error(api, client):
    for t in client.get("/tokens").json():
        client.delete(f"/tokens/{t['id']}")
    err, text = _call(api, "list_hosts")
    assert err and "401" in text
