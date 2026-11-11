from app import models
from app.auth import create_session
from app.security import verify_password
from conftest import make_user


def test_reset_password_requires_admin(client, logged_in, db):
    logged_in(role="lead", username="pr-lead-1")
    target, _ = make_user(db, "pr-target-1", "operator")
    resp = client.post(f"/users/{target.id}/reset-password")
    assert resp.status_code == 403


def test_reset_password_returns_new_password_once(client, logged_in, db):
    logged_in(role="admin", username="pr-admin-1")
    target, old_password = make_user(db, "pr-target-2", "operator")

    resp = client.post(f"/users/{target.id}/reset-password")
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == target.username
    new_password = body["new_password"]
    assert new_password != old_password
    assert len(new_password) > 8

    db.refresh(target)
    assert verify_password(new_password, target.password_hash)
    assert not verify_password(old_password, target.password_hash)


def test_reset_password_invalidates_existing_sessions(client, logged_in, db):
    logged_in(role="admin", username="pr-admin-2")
    target, _ = make_user(db, "pr-target-3", "operator")
    # Simulate a pre-existing logged-in session for the target, without
    # touching the shared TestClient's own cookie (still authenticated
    # as the admin) -- same session-creation path a real login uses.
    create_session(db, target)
    assert db.query(models.Session).filter(models.Session.user_id == target.id).count() == 1

    resp = client.post(f"/users/{target.id}/reset-password")
    assert resp.status_code == 200
    assert db.query(models.Session).filter(models.Session.user_id == target.id).count() == 0


def test_reset_password_404_for_unknown_user(client, logged_in):
    logged_in(role="admin", username="pr-admin-3")
    resp = client.post("/users/999999/reset-password")
    assert resp.status_code == 404


def test_reset_password_audit_logged(client, logged_in, db):
    logged_in(role="admin", username="pr-admin-4")
    target, _ = make_user(db, "pr-target-4", "operator")
    client.post(f"/users/{target.id}/reset-password")
    entry = (
        db.query(models.AuditLog)
        .filter(models.AuditLog.action == "password_reset", models.AuditLog.detail.like(f"%{target.username}%"))
        .first()
    )
    assert entry is not None
    assert entry.actor == "pr-admin-4"


# ---------- PATCH /users/{id} (role/display_name edits) ----------

def test_patch_user_requires_admin(client, logged_in, db):
    logged_in(role="lead", username="pu-lead-1")
    target, _ = make_user(db, "pu-target-1", "operator")
    resp = client.patch(f"/users/{target.id}", json={"role": "admin"})
    assert resp.status_code == 403


def test_patch_user_changes_role(client, logged_in, db):
    logged_in(role="admin", username="pu-admin-1")
    target, _ = make_user(db, "pu-target-2", "operator")
    resp = client.patch(f"/users/{target.id}", json={"role": "lead"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "lead"
    db.refresh(target)
    assert target.role == "lead"


def test_patch_user_rejects_invalid_role(client, logged_in, db):
    logged_in(role="admin", username="pu-admin-2")
    target, _ = make_user(db, "pu-target-3", "operator")
    resp = client.patch(f"/users/{target.id}", json={"role": "superuser"})
    assert resp.status_code == 400


def test_patch_user_changes_display_name_only(client, logged_in, db):
    logged_in(role="admin", username="pu-admin-3")
    target, _ = make_user(db, "pu-target-4", "operator")
    resp = client.patch(f"/users/{target.id}", json={"display_name": "Pat User"})
    assert resp.status_code == 200
    assert resp.json()["display_name"] == "Pat User"
    assert resp.json()["role"] == "operator"  # unchanged


def test_patch_user_404_for_unknown_user(client, logged_in):
    logged_in(role="admin", username="pu-admin-4")
    resp = client.patch("/users/999999", json={"role": "admin"})
    assert resp.status_code == 404


def test_an_admin_cant_demote_themselves(client, logged_in, db):
    """Done by the last admin, nobody would be left to manage users or settings."""
    me = logged_in(role="admin", username="la-self-1")
    resp = client.patch(f"/users/{me.id}", json={"role": "operator"})
    assert resp.status_code == 400 and "your own role" in resp.json()["detail"]
    db.refresh(me)
    assert me.role == "admin"
    assert client.patch(f"/users/{me.id}", json={"display_name": "Still Admin"}).status_code == 200


def test_create_user_refuses_a_name_that_differs_only_by_case(client, logged_in):
    """Sign-in treats those as one account, so two of them could never both be used."""
    logged_in(role="admin", username="case-admin")
    body = {"password": "long-enough-password", "role": "operator"}
    assert client.post("/users", json={"username": "Morgan", **body}).status_code == 200
    resp = client.post("/users", json={"username": "morgan", **body})
    assert resp.status_code == 409
    assert "Morgan" in resp.json()["detail"]


def test_create_user_trims_the_username(client, logged_in):
    logged_in(role="admin", username="trim-admin")
    body = {"password": "long-enough-password", "role": "operator"}
    assert client.post("/users", json={"username": "  riley ", **body}).json()["username"] == "riley"
    assert client.post("/users", json={"username": "   ", **body}).status_code == 400
