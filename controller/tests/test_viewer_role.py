"""
The read-only 'viewer' role (app/auth.py). Starting and cancelling runs
are open to any authenticated user rather than gated by require_role, so
a viewer is stopped by method in get_current_user, not by rank -- these
tests pin that it actually is, and that the narrow exceptions (its own
password and API tokens) still work.
"""
from app import models
from conftest import make_host


def test_admin_can_create_a_viewer(client, logged_in):
    logged_in("admin")
    resp = client.post("/users", json={"username": "auditor-1", "password": "a-long-password-1",
                                       "role": "viewer", "display_name": "Auditor"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["role"] == "viewer"


def test_viewer_reads_everything_the_console_shows(client, logged_in):
    logged_in("viewer")
    for path in ["/hosts", "/runs", "/dashboard", "/audit", "/schedules", "/defs",
                 "/proxmox/coverage", "/topology", "/auth/me", "/settings"]:
        assert client.get(path).status_code == 200, path


def test_viewer_cannot_start_or_cancel_a_run(client, logged_in, db):
    host, _ = make_host(db)
    job = models.Job(host_id=host.id, hostname=host.hostname, ticket_id="CHG-1", status="running")
    db.add(job)
    db.commit()
    logged_in("viewer")
    started = client.post("/runs", json={"host_id": host.id, "checklist": [{"item_index": 0, "item_text": "x"}]})
    assert started.status_code == 403
    assert "Read-only" in started.json()["detail"]
    assert client.post(f"/runs/{job.id}/cancel").status_code == 403


def test_viewer_cannot_change_anything_else(client, logged_in):
    logged_in("viewer")
    for method, path, body in [
        ("post", "/tickets", {"ticket_id": "CHG-9"}),
        ("post", "/proxmox/ignored", {"vmid": 1, "reason": "x"}),
        ("delete", "/hosts/1", None),
    ]:
        resp = getattr(client, method)(path, **({"json": body} if body is not None else {}))
        assert resp.status_code == 403, (method, path, resp.text)


def test_viewer_can_manage_own_tokens_and_password(client, logged_in):
    logged_in("viewer")
    created = client.post("/tokens", json={"name": "wall-display"})
    assert created.status_code == 200, created.text
    assert client.delete(f"/tokens/{created.json()['id']}").status_code == 200
    # Reaches the password check (wrong current password -> 401), i.e. not
    # refused as a write.
    resp = client.post("/auth/change-password", json={"current_password": "nope", "new_password": "x" * 12})
    assert resp.status_code == 401


def test_viewer_ranks_below_operator(client, logged_in):
    logged_in("viewer")
    assert client.get("/users").status_code == 403  # admin-only read
