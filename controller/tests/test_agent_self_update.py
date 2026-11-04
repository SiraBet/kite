"""
agent self-update, controller side. The agent reports its own
version on every /jobs/next poll; when Settings -> agent_target_version
is set to something different, the controller signals it via the
X-Kite-Self-Update response header (never the JSON body, so the
existing Optional[AgentJobStageInstruction] response shape is untouched)
-- but only on an otherwise-idle poll, never alongside a real job-stage
instruction, so it can never preempt an in-flight run.
"""
from app.settings_store import set_setting
from conftest import make_host


def _poll(client, host, secret, version=None):
    params = {}
    if version is not None:
        params["agent_version"] = version
    return client.get(f"/agent/{host.id}/jobs/next", headers={"Authorization": f"Bearer {secret}"}, params=params)


def test_no_header_when_target_unset(client, db):
    host, secret = make_host(db)
    resp = _poll(client, host, secret, version="0.1.5")
    assert resp.status_code == 200
    assert "X-Kite-Self-Update" not in resp.headers


def test_no_header_when_version_matches_target(db, client):
    host, secret = make_host(db)
    set_setting(db, "agent_target_version", "0.1.6")
    resp = _poll(client, host, secret, version="0.1.6")
    assert "X-Kite-Self-Update" not in resp.headers


def test_header_set_when_target_differs_and_poll_is_idle(db, client):
    host, secret = make_host(db)
    set_setting(db, "agent_target_version", "0.1.6")
    resp = _poll(client, host, secret, version="0.1.5")
    assert resp.status_code == 200
    assert resp.json() is None
    assert resp.headers["X-Kite-Self-Update"] == "0.1.6"


def test_no_header_when_agent_sends_no_version(db, client):
    """Backward compat: an older agent build that doesn't send agent_version
    at all just never gets offered a self-update -- no crash, no header."""
    host, secret = make_host(db)
    set_setting(db, "agent_target_version", "0.1.6")
    resp = _poll(client, host, secret, version=None)
    assert resp.status_code == 200
    assert "X-Kite-Self-Update" not in resp.headers


def test_agent_version_is_recorded_on_host(db, client):
    host, secret = make_host(db)
    _poll(client, host, secret, version="0.1.6")
    db.refresh(host)
    assert host.agent_version == "0.1.6"


def test_self_update_header_never_set_alongside_a_real_instruction(db, client, logged_in):
    """The one safety property this feature depends on: a host with an
    active, dispatched job stage must never also see the self-update
    header on the same response."""
    from app.settings_store import set_setting as _set
    _set(db, "require_ticket", "false")
    logged_in(role="admin", username="su-admin-1")
    host, secret = make_host(db)
    set_setting(db, "agent_target_version", "9.9.9")

    run_resp = client.post("/runs", json={"host_id": host.id, "checklist": [{"item_index": 0, "item_text": "confirmed"}]})
    assert run_resp.status_code == 200

    resp = _poll(client, host, secret, version="0.1.5")
    assert resp.status_code == 200
    assert resp.json() is not None  # a real instruction (the preflight stage) is pending
    assert "X-Kite-Self-Update" not in resp.headers
