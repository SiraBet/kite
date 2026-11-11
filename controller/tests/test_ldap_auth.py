"""
LDAP/AD "search + bind" authentication.

ldap3.Connection is mocked rather than run against a live directory —
the same approach used for requests.post and smtplib.SMTP elsewhere in
this suite (see test_notifications.py), so the tests stay hermetic.

Covers app/ldap_auth.py directly, plus the just-in-time provisioning and
local-account-precedence behaviour in auth_router.py's login().
"""
from unittest.mock import patch, MagicMock

import ldap3

from app import models, ldap_auth
from app.settings_store import set_setting


def _configure(db, **overrides):
    set_setting(db, "ldap_enabled", "true")
    set_setting(db, "ldap_server_uri", "ldap://dc.example.com")
    set_setting(db, "ldap_user_base_dn", "ou=people,dc=example,dc=com")
    set_setting(db, "ldap_user_filter", "(uid={username})")
    set_setting(db, "ldap_default_role", "operator")
    for k, v in overrides.items():
        set_setting(db, k, v)


class _FakeEntry:
    def __init__(self, dn):
        self.entry_dn = dn


def _connection_factory(search_entries, bind_error=None, captured=None):
    """
    Stands in for ldap3.Connection: call #1 is the search-account bind
    (returns a connection whose .search() sets up .entries and records
    the base_dn/filter it was called with into `captured`, if given),
    call #2 is the found user's own bind (raises bind_error if given,
    else just "succeeds" — auto_bind not actually validating anything in
    the fake).
    """
    state = {"n": 0}

    def factory(server, user=None, password=None, auto_bind=None, receive_timeout=None):
        state["n"] += 1
        conn = MagicMock()
        if state["n"] == 1:
            if captured is not None:
                captured["bind_user"] = user
            conn.entries = search_entries

            def _search(base_dn, filt, attributes=None):
                if captured is not None:
                    captured["base_dn"] = base_dn
                    captured["filter"] = filt
            conn.search = _search
        else:
            if bind_error:
                raise bind_error
        return conn
    return factory


# ---------- ldap_auth.authenticate ----------

def test_authenticate_false_when_not_enabled(db):
    assert ldap_auth.authenticate(db, "alice", "pw") is False


def test_authenticate_false_on_empty_password(db):
    _configure(db)
    assert ldap_auth.authenticate(db, "alice", "") is False


def test_authenticate_true_on_successful_search_and_bind(db):
    _configure(db)
    factory = _connection_factory([_FakeEntry("uid=alice,ou=people,dc=example,dc=com")])
    with patch("app.ldap_auth.ldap3.Connection", side_effect=factory):
        assert ldap_auth.authenticate(db, "alice", "correct-password") is True


def test_authenticate_false_when_user_not_found(db):
    _configure(db)
    factory = _connection_factory([])
    with patch("app.ldap_auth.ldap3.Connection", side_effect=factory):
        assert ldap_auth.authenticate(db, "ghost", "pw") is False


def test_authenticate_false_when_search_is_ambiguous(db):
    _configure(db)
    factory = _connection_factory([_FakeEntry("uid=a,..."), _FakeEntry("uid=b,...")])
    with patch("app.ldap_auth.ldap3.Connection", side_effect=factory):
        assert ldap_auth.authenticate(db, "dup", "pw") is False


def test_authenticate_false_when_user_bind_fails(db):
    _configure(db)
    factory = _connection_factory([_FakeEntry("uid=alice,...")],
                                   bind_error=ldap3.core.exceptions.LDAPBindError("invalid credentials"))
    with patch("app.ldap_auth.ldap3.Connection", side_effect=factory):
        assert ldap_auth.authenticate(db, "alice", "wrong-password") is False


def test_authenticate_escapes_username_in_filter(db):
    """
    A username crafted to inject extra filter clauses (e.g. widen the
    search to match anyone) must have its special characters escaped
    before reaching the LDAP filter — this is the LDAP-injection
    equivalent of parameterizing a SQL query.
    """
    from ldap3.utils.conv import escape_filter_chars
    _configure(db)
    captured = {}
    injected_username = "a)(uid=*"
    factory = _connection_factory([_FakeEntry("uid=x,...")], captured=captured)
    with patch("app.ldap_auth.ldap3.Connection", side_effect=factory):
        ldap_auth.authenticate(db, injected_username, "pw")
    assert captured["filter"] == f"(uid={escape_filter_chars(injected_username)})"
    assert captured["filter"] != f"(uid={injected_username})"  # the raw, unescaped injection


def test_authenticate_uses_anonymous_search_bind_when_no_bind_dn(db):
    _configure(db)  # ldap_bind_dn left unset -- '' by default
    captured = {}
    factory = _connection_factory([_FakeEntry("uid=alice,...")], captured=captured)
    with patch("app.ldap_auth.ldap3.Connection", side_effect=factory):
        ldap_auth.authenticate(db, "alice", "pw")
    assert captured["bind_user"] is None  # anonymous search bind, no service account configured


# ---------- the connection to the directory ----------
# Every password typed at sign-in crosses it, and whoever can answer in the
# directory's place decides who gets in.

def _transport_used(db, **settings):
    """The (server, auto_bind) authenticate() opens its connections with."""
    _configure(db, **settings)
    seen = {}

    def factory(server, user=None, password=None, auto_bind=None, receive_timeout=None):
        seen.setdefault("server", server)
        seen.setdefault("auto_bind", auto_bind)
        conn = MagicMock()
        conn.entries = [_FakeEntry("uid=alice,ou=people,dc=example,dc=com")]
        return conn

    try:
        with patch("app.ldap_auth.ldap3.Connection", side_effect=factory):
            assert ldap_auth.authenticate(db, "alice", "pw") is True
    finally:
        for key in ("ldap_verify_cert", "ldap_starttls", "ldap_ca_cert_file"):
            set_setting(db, key, "")
    return seen["server"], seen["auto_bind"]


def test_ldaps_checks_the_directorys_certificate(db):
    import ssl
    server, auto_bind = _transport_used(db, ldap_server_uri="ldaps://dc.example.com")
    assert server.ssl is True
    assert server.tls.validate == ssl.CERT_REQUIRED
    assert auto_bind is True


def test_plain_ldap_is_upgraded_with_starttls_before_any_bind(db):
    import ssl
    server, auto_bind = _transport_used(db, ldap_server_uri="ldap://dc.example.com")
    assert server.ssl is False
    assert auto_bind == ldap3.AUTO_BIND_TLS_BEFORE_BIND     # the password never goes out in clear text
    assert server.tls.validate == ssl.CERT_REQUIRED


def test_certificate_check_and_starttls_can_each_be_turned_off(db):
    import ssl
    server, _ = _transport_used(db, ldap_server_uri="ldaps://dc.example.com", ldap_verify_cert="false")
    assert server.tls.validate == ssl.CERT_NONE
    _, auto_bind = _transport_used(db, ldap_server_uri="ldap://dc.example.com", ldap_starttls="false")
    assert auto_bind is True


def test_a_missing_ca_file_fails_the_login_rather_than_skipping_the_check(db):
    _configure(db, ldap_server_uri="ldaps://dc.example.com", ldap_ca_cert_file="/nonexistent/ca.pem")
    try:
        with patch("app.ldap_auth.ldap3.Connection") as conn:
            assert ldap_auth.authenticate(db, "alice", "pw") is False
        conn.assert_not_called()
    finally:
        set_setting(db, "ldap_ca_cert_file", "")


def test_ldap_transport_settings_only_take_true_or_false(client, logged_in):
    logged_in(role="admin", username="ldap-tls-admin")
    for key in ("ldap_verify_cert", "ldap_starttls"):
        assert client.put(f"/settings/{key}", json={"value": "off"}).status_code == 400
        assert client.put(f"/settings/{key}", json={"value": "true"}).status_code == 200


# ---------- login() integration: local precedence + JIT provisioning ----------

def test_login_local_user_never_touches_ldap(db, client):
    from conftest import make_user
    _configure(db)
    make_user(db, "local-1", "operator", password="localpass123")
    with patch("app.ldap_auth.authenticate") as mock_ldap:
        resp = client.post("/auth/login", json={"username": "local-1", "password": "localpass123"})
    assert resp.status_code == 200
    assert mock_ldap.call_count == 0


def test_login_unknown_username_tries_ldap_and_provisions_on_success(db, client):
    _configure(db, ldap_default_role="lead")
    with patch("app.ldap_auth.authenticate", return_value=True):
        resp = client.post("/auth/login", json={"username": "newldapuser", "password": "whatever"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "lead"
    user = db.query(models.User).filter(models.User.username == "newldapuser").first()
    assert user is not None
    assert user.auth_source == "ldap"


def test_login_ldap_failure_gives_generic_401(db, client):
    _configure(db)
    with patch("app.ldap_auth.authenticate", return_value=False):
        resp = client.post("/auth/login", json={"username": "nobody", "password": "wrong"})
    assert resp.status_code == 401


def test_login_existing_ldap_user_reauthenticates_every_time_not_cached(db, client):
    _configure(db)
    with patch("app.ldap_auth.authenticate", return_value=True):
        client.post("/auth/login", json={"username": "repeatuser", "password": "first-pw"})
    with patch("app.ldap_auth.authenticate", return_value=False) as mock_ldap:
        resp = client.post("/auth/login", json={"username": "repeatuser", "password": "changed-pw"})
    assert mock_ldap.call_count == 1
    assert resp.status_code == 401  # no locally-cached password ever lets this succeed instead


# ---------- one account per person, however the name is typed ----------
# A directory matches names without regard to case. If "Alice" and "alice"
# were separate accounts here, a role change made to one could be undone by
# signing in as the other and being provisioned again at the default role.

def test_login_with_different_case_reuses_the_account_and_its_role(db, client):
    _configure(db, ldap_default_role="operator")
    with patch("app.ldap_auth.authenticate", return_value=True):
        assert client.post("/auth/login", json={"username": "casey", "password": "pw"}).status_code == 200
    account = db.query(models.User).filter(models.User.username == "casey").one()
    account.role = "viewer"   # an admin restricts the account
    db.commit()

    with patch("app.ldap_auth.authenticate", return_value=True):
        resp = client.post("/auth/login", json={"username": "CASEY", "password": "pw"})
    assert resp.status_code == 200
    assert (resp.json()["username"], resp.json()["role"]) == ("casey", "viewer")
    assert db.query(models.User).filter(models.User.username.ilike("casey")).count() == 1


def test_first_ldap_login_stores_the_username_in_lower_case(db, client):
    _configure(db)
    with patch("app.ldap_auth.authenticate", return_value=True) as mock_ldap:
        resp = client.post("/auth/login", json={"username": "  Jordan.Lee ", "password": "pw"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "jordan.lee"
    assert resp.json()["display_name"] == "Jordan.Lee"
    assert mock_ldap.call_args.args[1] == "Jordan.Lee"   # the directory is asked about the name as typed


def test_local_account_matched_by_case_still_checks_its_own_password(db, client):
    from conftest import make_user
    _configure(db)
    make_user(db, "LocalMixed", "admin", password="localpass123")
    with patch("app.ldap_auth.authenticate", return_value=True) as mock_ldap:
        wrong = client.post("/auth/login", json={"username": "localmixed", "password": "not-the-password"})
        right = client.post("/auth/login", json={"username": "localmixed", "password": "localpass123"})
    assert wrong.status_code == 401
    assert right.status_code == 200 and right.json()["username"] == "LocalMixed"
    assert mock_ldap.call_count == 0   # never handed to the directory, never provisioned a second account


def test_accounts_that_already_differ_only_by_case_stay_separate(db, client):
    from conftest import make_user
    make_user(db, "legacy", "viewer", password="lower-password-1")
    make_user(db, "LEGACY", "admin", password="upper-password-1")
    lower = client.post("/auth/login", json={"username": "legacy", "password": "lower-password-1"})
    upper = client.post("/auth/login", json={"username": "LEGACY", "password": "upper-password-1"})
    assert (lower.json()["role"], upper.json()["role"]) == ("viewer", "admin")


# ---------- password endpoints are blocked for ldap-sourced accounts ----------

def test_change_password_rejected_for_ldap_user(db, client):
    _configure(db)
    with patch("app.ldap_auth.authenticate", return_value=True):
        client.post("/auth/login", json={"username": "ldapchange", "password": "pw"})
    resp = client.post("/auth/change-password", json={"current_password": "pw", "new_password": "newpassword123"})
    assert resp.status_code == 400


def test_admin_reset_password_rejected_for_ldap_user(db, client, logged_in):
    _configure(db)
    with patch("app.ldap_auth.authenticate", return_value=True):
        c2 = client  # same shared client — provision then switch sessions below
        c2.post("/auth/login", json={"username": "ldapreset", "password": "pw"})
    target = db.query(models.User).filter(models.User.username == "ldapreset").first()

    logged_in(role="admin", username="ldap-admin-1")  # logs the shared client back in as this admin
    resp = client.post(f"/users/{target.id}/reset-password")
    assert resp.status_code == 400
