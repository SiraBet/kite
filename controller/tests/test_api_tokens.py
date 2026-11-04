"""
API tokens (app/routers/api_tokens.py, app/auth.py's bearer path): the
credential the local MCP server uses. The properties that matter are the
ones that keep a token weaker than a session -- read-only whatever the
owner's role, unable to manage tokens, dead on expiry, revocation, a
password reset or account deletion.
"""
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app import models
from app.main import app
from app.security import hash_secret


def _create(client, name="mcp", **extra):
    resp = client.post("/tokens", json={"name": name, **extra})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _bearer(token):
    # A fresh client, so no session cookie rides along and the request is
    # judged on the token alone.
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def test_create_returns_token_once_and_stores_only_its_hash(client, logged_in, db):
    logged_in("operator")
    created = _create(client)
    assert created["token"].startswith("kite_")
    assert created["prefix"] == created["token"][:len("kite_") + 4]
    assert created["scope"] == "read"
    row = db.query(models.ApiToken).filter(models.ApiToken.id == created["id"]).one()
    assert row.token_hash == hash_secret(created["token"])
    assert created["token"] not in (row.token_hash, row.prefix)
    listed = client.get("/tokens").json()
    assert [t["id"] for t in listed] == [created["id"]]
    assert "token" not in listed[0]


def test_token_reads_as_its_owner(client, logged_in):
    user = logged_in("lead")
    api = _bearer(_create(client)["token"])
    me = api.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == user.username
    assert api.get("/hosts").status_code == 200


def test_read_token_is_refused_on_every_write_even_for_admin(client, logged_in):
    logged_in("admin")
    api = _bearer(_create(client)["token"])
    for method, path, body in [
        ("post", "/runs", {}), ("put", "/settings/require_ticket", {"value": "true"}),
        ("patch", "/hosts/1", {}), ("delete", "/users/1", None), ("post", "/auth/change-password", {}),
    ]:
        resp = getattr(api, method)(path, **({"json": body} if body is not None else {}))
        assert resp.status_code == 403, (method, path, resp.text)
        assert "read-only" in resp.json()["detail"]


def test_token_cannot_manage_tokens(client, logged_in):
    logged_in("admin")
    created = _create(client)
    api = _bearer(created["token"])
    assert api.get("/tokens").status_code == 403
    assert api.get("/tokens?all=true").status_code == 403
    # Writes are refused by scope before they'd reach the session check.
    assert api.delete(f"/tokens/{created['id']}").status_code == 403


def test_role_cap_still_applies(client, logged_in):
    logged_in("operator")
    api = _bearer(_create(client)["token"])
    assert api.get("/users").status_code == 403  # admin-only listing


def test_invalid_expired_and_foreign_tokens_are_401(client, logged_in, db):
    logged_in("operator")
    created = _create(client)
    assert _bearer("kite_not-a-real-token").get("/hosts").status_code == 401
    assert _bearer("some-agent-secret").get("/hosts").status_code == 401
    row = db.query(models.ApiToken).filter(models.ApiToken.id == created["id"]).one()
    row.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    resp = _bearer(created["token"]).get("/hosts")
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"]


def test_bearer_header_wins_over_cookie(client, logged_in):
    logged_in("admin")
    client.headers["Authorization"] = "Bearer kite_bogus"
    try:
        assert client.get("/hosts").status_code == 401
    finally:
        del client.headers["Authorization"]


def test_expiry_is_mandatory_and_bounded(client, logged_in):
    logged_in("operator")
    assert client.post("/tokens", json={"name": "x", "expires_in_days": 0}).status_code == 422
    assert client.post("/tokens", json={"name": "x", "expires_in_days": 366}).status_code == 422
    assert client.post("/tokens", json={"name": "x", "scope": "admin"}).status_code == 400
    assert client.post("/tokens", json={"name": "<script>"}).status_code == 422
    created = _create(client, expires_in_days=7)
    expires = datetime.fromisoformat(created["expires_at"])
    assert timedelta(days=6) < expires - datetime.utcnow() <= timedelta(days=7)


def test_revoke_own_token_kills_it(client, logged_in):
    logged_in("operator")
    created = _create(client)
    api = _bearer(created["token"])
    assert api.get("/hosts").status_code == 200
    assert client.delete(f"/tokens/{created['id']}").status_code == 200
    assert api.get("/hosts").status_code == 401


def test_cannot_see_or_revoke_someone_elses_token_unless_admin(client, logged_in):
    logged_in("operator")
    theirs = _create(client)
    logged_in("lead")
    assert client.delete(f"/tokens/{theirs['id']}").status_code == 404
    assert client.get("/tokens?all=true").status_code == 403
    assert theirs["id"] not in [t["id"] for t in client.get("/tokens").json()]
    logged_in("admin")
    assert theirs["id"] in [t["id"] for t in client.get("/tokens?all=true").json()]
    assert client.delete(f"/tokens/{theirs['id']}").status_code == 200


def test_password_reset_and_user_delete_revoke_tokens(client, logged_in, db):
    owner = logged_in("operator")
    token = _create(client)["token"]
    owner2 = logged_in("operator")
    token2 = _create(client)["token"]
    logged_in("admin")
    assert client.post(f"/users/{owner.id}/reset-password").status_code == 200
    assert _bearer(token).get("/hosts").status_code == 401
    assert client.delete(f"/users/{owner2.id}").status_code == 200
    assert _bearer(token2).get("/hosts").status_code == 401


def test_last_used_is_recorded(client, logged_in, db):
    logged_in("operator")
    created = _create(client)
    assert created["last_used_at"] is None
    _bearer(created["token"]).get("/hosts")
    row = db.query(models.ApiToken).filter(models.ApiToken.id == created["id"]).one()
    db.refresh(row)
    assert row.last_used_at is not None


def test_token_lifecycle_is_audited(client, logged_in, db):
    logged_in("operator")
    created = _create(client, name="audit-me")
    client.delete(f"/tokens/{created['id']}")
    actions = [a.action for a in db.query(models.AuditLog).filter(models.AuditLog.detail.contains("audit-me")).all()]
    assert "api_token_created" in actions and "api_token_revoked" in actions
