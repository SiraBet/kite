"""
GET /hosts, GET /hosts/{id}, PATCH /hosts/{id}, POST /hosts/{id}/resolve-vmid,
DELETE /hosts/{id}. Both GETs are open to any logged-in role; the other
three require admin (see app/routers/hosts.py's require_role("admin")).
"""
from unittest.mock import patch

from app.proxmox import ProxmoxConfig
from conftest import make_host
from app import models
from app.proxmox import ProxmoxError


def _checklist():
    return [{"item_index": 0, "item_text": "confirmed"}]


def _start_run(client, host_id):
    return client.post("/runs", json={"host_id": host_id, "checklist": _checklist()})


# ---------- GET /hosts, GET /hosts/{id} ----------

def test_list_hosts_no_role_restriction(client, logged_in, db):
    logged_in(role="operator", username="host-list-1")
    make_host(db)
    resp = client.get("/hosts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_list_hosts_filters_by_team(client, logged_in, db):
    logged_in(role="operator", username="host-list-2")
    host_a, _ = make_host(db)
    host_a.team = "platform"
    host_b, _ = make_host(db)
    host_b.team = "web"
    db.commit()

    resp = client.get("/hosts", params={"team": "platform"})
    assert resp.status_code == 200
    hostnames = [h["hostname"] for h in resp.json()]
    assert host_a.hostname in hostnames
    assert host_b.hostname not in hostnames


def test_list_hosts_reports_active_job_id(client, logged_in, db):
    logged_in(role="admin", username="host-list-3")
    from app.settings_store import set_setting
    set_setting(db, "require_ticket", "false")
    host, _ = make_host(db)
    host.rollback_backend = "none"
    db.commit()
    job_id = _start_run(client, host.id).json()["id"]

    resp = client.get("/hosts")
    entry = next(h for h in resp.json() if h["id"] == host.id)
    assert entry["active_job_id"] == job_id


def test_get_host_success(client, logged_in, db):
    logged_in(role="operator", username="host-get-1")
    host, _ = make_host(db)
    resp = client.get(f"/hosts/{host.id}")
    assert resp.status_code == 200
    assert resp.json()["hostname"] == host.hostname


def test_get_host_404_for_nonexistent_id(client, logged_in):
    logged_in(role="operator", username="host-get-2")
    resp = client.get("/hosts/999999")
    assert resp.status_code == 404


# ---------- PATCH /hosts/{id} ----------

def test_patch_host_requires_admin(client, logged_in, db):
    host, _ = make_host(db)
    for role in ("operator", "lead"):
        logged_in(role=role, username=f"host-patch-role-{role}")
        resp = client.patch(f"/hosts/{host.id}", json={"team": "platform"})
        assert resp.status_code == 403, f"{role}: {resp.text}"


def test_patch_host_updates_every_patchable_field(client, logged_in, db):
    logged_in(role="admin", username="host-patch-1")
    host, _ = make_host(db)

    resp = client.patch(f"/hosts/{host.id}", json={
        "proxmox_vmid": 501,
        "proxmox_node": "pve-node-2",
        "role": "db",
        "team": "platform",
        "os_family": "rocky8",
        "rollback_backend": "dnf_history",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proxmox_vmid"] == 501
    assert body["proxmox_node"] == "pve-node-2"
    assert body["role"] == "db"
    assert body["team"] == "platform"
    assert body["os_family"] == "rocky8"
    assert body["rollback_backend"] == "dnf_history"


def test_patch_host_partial_update_leaves_other_fields_alone(client, logged_in, db):
    logged_in(role="admin", username="host-patch-2")
    host, _ = make_host(db)
    host.team = "platform"
    host.role = "web"
    db.commit()

    resp = client.patch(f"/hosts/{host.id}", json={"team": "data"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["team"] == "data"
    assert body["role"] == "web"  # untouched


def test_patch_host_rejects_invalid_rollback_backend(client, logged_in, db):
    logged_in(role="admin", username="host-patch-3")
    host, _ = make_host(db)
    resp = client.patch(f"/hosts/{host.id}", json={"rollback_backend": "not-a-real-backend"})
    assert resp.status_code == 400
    assert "rollback_backend must be one of" in resp.text


def test_patch_host_empty_string_clears_rollback_backend_override(client, logged_in, db):
    logged_in(role="admin", username="host-patch-4")
    host, _ = make_host(db)
    host.rollback_backend = "dnf_history"
    db.commit()

    resp = client.patch(f"/hosts/{host.id}", json={"rollback_backend": ""})
    assert resp.status_code == 200
    assert resp.json()["rollback_backend"] == ""


def test_patch_host_404_for_nonexistent_id(client, logged_in):
    logged_in(role="admin", username="host-patch-5")
    resp = client.patch("/hosts/999999", json={"team": "platform"})
    assert resp.status_code == 404


# ---------- POST /hosts/{id}/resolve-vmid ----------

def test_resolve_vmid_requires_admin(client, logged_in, db):
    host, _ = make_host(db)
    logged_in(role="lead", username="host-resolve-1")
    resp = client.post(f"/hosts/{host.id}/resolve-vmid")
    assert resp.status_code == 403


def test_resolve_vmid_400_without_smbios_uuid(client, logged_in, db):
    logged_in(role="admin", username="host-resolve-2")
    host, _ = make_host(db)
    assert not host.smbios_uuid
    resp = client.post(f"/hosts/{host.id}/resolve-vmid")
    assert resp.status_code == 400
    assert "SMBIOS UUID" in resp.text


def test_resolve_vmid_success_sets_vmid_and_logs(client, logged_in, db):
    logged_in(role="admin", username="host-resolve-3")
    host, _ = make_host(db)
    host.smbios_uuid = "8f3c1a2e-0000-0000-0000-000000000000"
    db.commit()

    with patch("app.rollback.resolve_proxmox_config", return_value=ProxmoxConfig(host="10.0.0.5", token_id="a@pve!b", token_secret="s")), \
         patch("app.proxmox.find_vmid_by_smbios_uuid", return_value=777):
        resp = client.post(f"/hosts/{host.id}/resolve-vmid")
    assert resp.status_code == 200, resp.text
    assert resp.json()["proxmox_vmid"] == 777

    entry = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.action == "vmid_auto_resolved")
        .order_by(models.AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert "777" in entry.detail


def test_resolve_vmid_404_when_no_match_found(client, logged_in, db):
    logged_in(role="admin", username="host-resolve-4")
    host, _ = make_host(db)
    host.smbios_uuid = "8f3c1a2e-0000-0000-0000-000000000001"
    db.commit()

    with patch("app.rollback.resolve_proxmox_config", return_value=ProxmoxConfig(host="10.0.0.5", token_id="a@pve!b", token_secret="s")), \
         patch("app.proxmox.find_vmid_by_smbios_uuid", return_value=None):
        resp = client.post(f"/hosts/{host.id}/resolve-vmid")
    assert resp.status_code == 404


def test_resolve_vmid_502_on_proxmox_error(client, logged_in, db):
    logged_in(role="admin", username="host-resolve-5")
    host, _ = make_host(db)
    host.smbios_uuid = "8f3c1a2e-0000-0000-0000-000000000002"
    db.commit()

    with patch("app.rollback.resolve_proxmox_config", return_value=ProxmoxConfig(host="10.0.0.5", token_id="a@pve!b", token_secret="s")), \
         patch("app.proxmox.find_vmid_by_smbios_uuid", side_effect=ProxmoxError("no route to host")):
        resp = client.post(f"/hosts/{host.id}/resolve-vmid")
    assert resp.status_code == 502
    assert "no route to host" in resp.text


# ---------- DELETE /hosts/{id} ----------

def test_delete_host_requires_admin(client, logged_in, db):
    host, _ = make_host(db)
    logged_in(role="lead", username="host-delete-1")
    resp = client.delete(f"/hosts/{host.id}")
    assert resp.status_code == 403


def test_delete_host_404_for_nonexistent_id(client, logged_in):
    logged_in(role="admin", username="host-delete-2")
    resp = client.delete("/hosts/999999")
    assert resp.status_code == 404


def test_delete_host_blocked_while_run_active(client, logged_in, db):
    logged_in(role="admin", username="host-delete-3")
    from app.settings_store import set_setting
    set_setting(db, "require_ticket", "false")
    host, _ = make_host(db)
    host.rollback_backend = "none"
    db.commit()
    _start_run(client, host.id)

    resp = client.delete(f"/hosts/{host.id}")
    assert resp.status_code == 409
    assert "active run" in resp.text


def test_delete_host_succeeds_and_logs(client, logged_in, db):
    logged_in(role="admin", username="host-delete-4")
    host, _ = make_host(db)
    hostname = host.hostname
    host_id = host.id

    resp = client.delete(f"/hosts/{host_id}")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert db.query(models.Host).filter(models.Host.id == host_id).first() is None

    entry = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.action == "host_removed")
        .order_by(models.AuditLog.id.desc())
        .first()
    )
    assert entry is not None
    assert entry.detail == hostname


def test_delete_host_orphans_its_non_active_jobs_no_fk_enforcement(client, logged_in, db):
    """
    Real, possibly-surprising behavior: app/models.py declares
    host_id as a ForeignKey("hosts.id") but app/db.py never runs
    PRAGMA foreign_keys=ON (SQLite's own default is OFF), and there's
    no ORM-level cascade configured on Job.host either. So deleting a
    host whose job is no longer active (queued/running) is allowed,
    and the finished job's row is left with a host_id pointing at a
    row that no longer exists -- not nulled, not cascaded, not blocked.

    Job.hostname (a snapshot taken at job creation -- see models.py)
    exists specifically to make this safe rather than a landmine: the
    job stays identifiable by name even though its live host relation
    is now dangling. This test pins both halves -- the dangling
    host_id (unchanged, deliberate trade-off, see the endpoint's
    docstring) and the fact that hostname survives it.
    """
    logged_in(role="lead", username="host-delete-orphan-lead")
    from app.settings_store import set_setting
    set_setting(db, "require_ticket", "false")
    host, _ = make_host(db)
    host.rollback_backend = "none"
    hostname = host.hostname
    db.commit()
    job_id = _start_run(client, host.id).json()["id"]
    cancel_resp = client.post(f"/runs/{job_id}/cancel")
    assert cancel_resp.status_code == 200  # now cancelled, not active

    logged_in(role="admin", username="host-delete-orphan-admin")
    resp = client.delete(f"/hosts/{host.id}")
    assert resp.status_code == 200, resp.text

    orphaned = db.query(models.Job).filter(models.Job.id == job_id).first()
    assert orphaned is not None
    assert orphaned.host_id == host.id  # still points at the now-deleted host row
    assert db.query(models.Host).filter(models.Host.id == host.id).first() is None
    assert orphaned.hostname == hostname  # survives the host's deletion

    # The API response for this now-orphaned job still shows a real
    # hostname, not a null/missing field a frontend would have to guard.
    get_resp = client.get(f"/runs/{job_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["hostname"] == hostname


def test_a_host_still_checking_in_can_be_removed_and_its_agent_is_then_turned_away(client, logged_in, db):
    host, secret = make_host(db)
    hdr = {"Authorization": f"Bearer {secret}"}
    assert client.get(f"/agent/{host.id}/jobs/next", headers=hdr).status_code == 200   # online, just checked in
    logged_in(role="admin", username="host-delete-live")
    assert client.delete(f"/hosts/{host.id}").status_code == 200
    assert client.get(f"/agent/{host.id}/jobs/next", headers=hdr).status_code in (401, 403, 404)


def test_editing_a_host_is_in_the_activity_log(client, logged_in, db):
    """The VM link and rollback backend decide what gets snapshotted and restored; changing
    them left no trace of who did it."""
    logged_in(role="admin", username="host-edit-admin")
    host, _ = make_host(db)

    assert client.patch(f"/hosts/{host.id}", json={"proxmox_vmid": 612, "team": "Edge"}).status_code == 200
    entry = (db.query(models.AuditLog).filter(models.AuditLog.action == "host_edited")
             .order_by(models.AuditLog.id.desc()).first())
    assert entry.actor == "host-edit-admin" and host.hostname in entry.detail
    assert "proxmox_vmid: unset → 612" in entry.detail and "team: unset → Edge" in entry.detail
    assert entry.tone == "warning"

    # Saving the same values again changes nothing, and says nothing.
    count = db.query(models.AuditLog).filter(models.AuditLog.action == "host_edited").count()
    assert client.patch(f"/hosts/{host.id}", json={"proxmox_vmid": 612, "team": "Edge"}).status_code == 200
    assert db.query(models.AuditLog).filter(models.AuditLog.action == "host_edited").count() == count
