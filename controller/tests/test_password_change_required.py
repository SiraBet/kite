"""
A password someone else chose -- an admin's reset, a new account, the
first-run admin -- only gets its owner signed in. Until they choose their
own, every request but "who am I", "change my password" and "sign out" is
refused (auth._refuse_until_password_changed), and the console shows only
that step.
"""
import uuid

from app import models
from app.bootstrap import bootstrap_admin
from conftest import make_user


def _name():
    return f"u-{uuid.uuid4().hex[:8]}"


def _sign_in(client, username, password):
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def test_a_reset_password_is_temporary(client, logged_in, db):
    target, _ = make_user(db, _name(), "operator")
    logged_in("admin")
    temp = client.post(f"/users/{target.id}/reset-password").json()
    assert temp["must_change_password"] is True and len(temp["new_password"]) >= 12

    client.post("/auth/logout")
    me = _sign_in(client, target.username, temp["new_password"])
    assert me["must_change_password"] is True
    r = client.get("/hosts")
    assert r.status_code == 403 and r.json()["detail"] == "password_change_required"
    assert client.get("/auth/me").json()["must_change_password"] is True       # still allowed

    same = client.post("/auth/change-password", json={"current_password": temp["new_password"],
                                                      "new_password": temp["new_password"]})
    assert same.status_code == 400                                             # must actually change
    ok = client.post("/auth/change-password", json={"current_password": temp["new_password"],
                                                    "new_password": "my-own-long-passphrase"})
    assert ok.status_code == 200
    assert client.get("/hosts").status_code == 200                             # in, without signing in again
    assert client.get("/auth/me").json()["must_change_password"] is False


def test_the_admin_can_type_the_temporary_password(client, logged_in, db):
    target, _ = make_user(db, _name(), "operator")
    logged_in("admin")
    short = client.post(f"/users/{target.id}/reset-password", json={"temporary_password": "short"})
    assert short.status_code == 400
    typed = client.post(f"/users/{target.id}/reset-password", json={"temporary_password": "handed-over-in-person"})
    assert typed.json()["new_password"] == "handed-over-in-person"
    client.post("/auth/logout")
    assert _sign_in(client, target.username, "handed-over-in-person")["must_change_password"] is True


def test_new_accounts_choose_their_own_password_unless_told_otherwise(client, logged_in, db):
    logged_in("admin")
    a, b = _name(), _name()
    assert client.post("/users", json={"username": a, "password": "initial-password-1", "role": "operator"}).json()["must_change_password"] is True
    assert client.post("/users", json={"username": b, "password": "initial-password-2", "role": "operator",
                                       "must_change_password": False}).json()["must_change_password"] is False
    client.post("/auth/logout")
    assert _sign_in(client, b, "initial-password-2")["must_change_password"] is False
    assert client.get("/hosts").status_code == 200


def test_api_tokens_are_refused_too(client, logged_in, db):
    user = logged_in("operator")
    raw = client.post("/tokens", json={"name": "t"}).json()["token"]
    db.query(models.User).filter_by(id=user.id).update({"must_change_password": True})
    db.commit()
    r = client.get("/hosts", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 403 and r.json()["detail"] == "password_change_required"


def test_the_first_run_admin_chooses_their_own_password(capsys):
    # bootstrap only acts on an empty users table, so give it one of its own
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine("sqlite://")
    models.Base.metadata.create_all(engine)
    fresh = sessionmaker(bind=engine)()
    try:
        bootstrap_admin(fresh)
        assert fresh.query(models.User).filter_by(username="admin").one().must_change_password is True
        assert "choose your own password" in capsys.readouterr().out
    finally:
        fresh.close()
