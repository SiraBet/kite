from conftest import make_user
from app import security


def test_login_wrong_password_rejected(client, db):
    make_user(db, "wrongpass-user", "operator", password="correct-horse")
    resp = client.post("/auth/login", json={"username": "wrongpass-user", "password": "not-it"})
    assert resp.status_code == 401


def test_login_unknown_user_rejected(client):
    resp = client.post("/auth/login", json={"username": "nobody-like-this", "password": "x"})
    assert resp.status_code == 401


def test_login_unknown_user_and_wrong_password_give_the_same_error(client, db):
    """Same message for both cases so a login form can't be used to enumerate usernames."""
    make_user(db, "enum-check-user", "operator", password="correct-horse")
    wrong_password = client.post("/auth/login", json={"username": "enum-check-user", "password": "nope"})
    unknown_user = client.post("/auth/login", json={"username": "does-not-exist-at-all", "password": "nope"})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["detail"] == unknown_user.json()["detail"]


def test_login_success_sets_session_and_returns_profile(client, db):
    _, password = make_user(db, "good-login-user", "lead")
    resp = client.post("/auth/login", json={"username": "good-login-user", "password": password})
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "good-login-user"
    assert body["role"] == "lead"
    assert "kite_session" in resp.cookies


def test_protected_endpoint_requires_session(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401


def test_me_reflects_logged_in_user(client, logged_in):
    logged_in(role="operator", username="me-check-user")
    resp = client.get("/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == "me-check-user"


def test_logout_invalidates_session(client, logged_in):
    logged_in(role="admin", username="logout-user")
    assert client.get("/auth/me").status_code == 200

    resp = client.post("/auth/logout")
    assert resp.status_code == 200
    assert client.get("/auth/me").status_code == 401


def test_operator_cannot_reach_admin_only_endpoint(client, logged_in):
    logged_in(role="operator", username="operator-blocked")
    resp = client.put("/settings/require_ticket", json={"value": "false"})
    assert resp.status_code == 403


def test_admin_can_reach_admin_only_endpoint(client, logged_in):
    logged_in(role="admin", username="admin-allowed")
    resp = client.put("/settings/require_ticket", json={"value": "false"})
    assert resp.status_code == 200


def test_login_returns_503_when_password_hasher_is_saturated(client, db):
    """
    Regression test for a real availability bug a load test found: every
    failed login (real or bogus username) burns a full PBKDF2 hash by
    design (see security.py's login-timing fix) -- under a big enough
    concurrent flood, that CPU cost piled up badly enough that ~82% of
    requests timed out client-side instead of getting any response at
    all. The fix (security.py's _PBKDF2_CONCURRENCY / acquire timeout)
    is meant to fail fast with a clean 503 once no hashing capacity is
    available, rather than let requests hang -- this pins that exact
    behavior without needing an actual 300-way concurrent flood in the
    test suite: hold every available hashing slot open, then confirm a
    login attempt gets a fast 503 instead of hanging or 401ing.
    """
    make_user(db, "hasher-busy-user", "operator", password="correct-horse")

    acquired = []
    try:
        # Real capacity is small (max(2, cpu_count())) -- 64 is just a
        # generous upper bound so the loop always exhausts it and stops
        # on the first failed non-blocking acquire, whatever it is.
        for _ in range(64):
            if not security._PBKDF2_CONCURRENCY.acquire(blocking=False):
                break
            acquired.append(True)

        resp = client.post("/auth/login", json={"username": "hasher-busy-user", "password": "wrong"})
        assert resp.status_code == 503
    finally:
        for _ in acquired:
            security._PBKDF2_CONCURRENCY.release()

    # Slots are free again -- a normal login attempt works as usual.
    resp = client.post("/auth/login", json={"username": "hasher-busy-user", "password": "wrong"})
    assert resp.status_code == 401
