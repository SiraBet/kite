"""
app.db binds its SQLAlchemy engine to KITE_DB at import time, so the
test DB path has to be set before anything under app/ is imported —
that's why this happens at module scope here rather than inside a
fixture.
"""
import os
import tempfile

_TEST_DB = tempfile.mktemp(suffix=".db")
os.environ["KITE_DB"] = _TEST_DB
os.environ.setdefault("KITE_ENROLL_SECRET", "test-enroll-secret")
# The TestClient's peer address is "testclient"; treat it as a trusted
# proxy so X-Forwarded-For behaves the way it does behind the documented
# Caddy front-end (see app/rate_limit.py). Without this the peer-aware
# limiter would ignore XFF in tests, since a bare TestClient is a direct,
# untrusted client rather than something sitting behind a proxy.
os.environ.setdefault("KITE_TRUSTED_PROXIES", "testclient,127.0.0.1,::1")
# Never Caddy's real admin API (app/controller_ca.py): a port nothing listens on.
os.environ["KITE_CADDY_ADMIN"] = "http://127.0.0.1:9"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app import models  # noqa: E402
from app.security import hash_password, generate_secret, hash_secret  # noqa: E402
from app.rate_limit import limiter  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _test_db():
    init_db()
    yield
    try:
        os.remove(_TEST_DB)
    except OSError:
        pass


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """
    The limiter's storage is process-global, and every test request
    comes from the same TestClient "address" — without a reset between
    tests, an earlier test's login/enroll calls would count against a
    later, unrelated test's quota. test_rate_limit.py deliberately
    exceeds the limit within a single test to verify it actually works.
    """
    limiter.reset()
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


def make_user(db, username, role, password="test-password-123"):
    user = models.User(
        username=username, password_hash=hash_password(password),
        role=role, display_name=username,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user, password


@pytest.fixture
def logged_in(client, db):
    """Returns a function that creates a user with the given role and
    logs the shared `client` in as them, so route dependencies that
    read the session cookie work in subsequent requests."""
    def _login(role="admin", username=None):
        import uuid
        username = username or f"{role}-{uuid.uuid4().hex[:8]}"
        user, password = make_user(db, username, role)
        resp = client.post("/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200, resp.text
        return user
    return _login


def make_host(db, hostname=None, os_family="rocky9"):
    import uuid
    hostname = hostname or f"host-{uuid.uuid4().hex[:8]}"
    secret = generate_secret()
    host = models.Host(
        hostname=hostname, os_family=os_family,
        agent_secret_hash=hash_secret(secret), status="healthy",
    )
    db.add(host)
    db.commit()
    db.refresh(host)
    return host, secret


@pytest.fixture
def legacy_proxmox():
    """
    A configured single Proxmox connection the pre-connections way
    (Settings/.env), which list_connections() reports as connection None.
    """
    from unittest.mock import patch
    from app.proxmox import ProxmoxConfig
    cfg = ProxmoxConfig(host="10.0.0.5", node="pve1", token_id="kite@pve!t", token_secret="s")
    with patch("app.rollback.resolve_proxmox_config", return_value=cfg):
        yield cfg


@pytest.fixture(autouse=True)
def _no_leftover_proxmox_connections():
    """
    Proxmox connection rows change how every Proxmox reader behaves (they
    replace the legacy single connection), and the test DB is shared --
    so a test that adds one must not leave it behind for the next.
    """
    yield
    session = SessionLocal()
    try:
        session.query(models.Host).filter(models.Host.proxmox_connection_id.isnot(None)) \
            .update({models.Host.proxmox_connection_id: None}, synchronize_session=False)
        # Everything learned through a connection goes with it -- as the real
        # DELETE does -- or a reused id would inherit another test's rows.
        for model in (models.ProxmoxBridge, models.ProxmoxGuestNic, models.ProxmoxIgnoredGuest, models.ProxmoxGuestFlag):
            session.query(model).filter(model.connection_id.isnot(None)).delete(synchronize_session=False)
        session.query(models.ProxmoxConnection).delete()
        session.commit()
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _no_controller_ca(tmp_path, monkeypatch):
    """No CA unless a test publishes one (app/controller_ca.py): nothing from Caddy, nothing kept on disk."""
    from app import controller_ca
    monkeypatch.setattr(controller_ca, "CACHE", tmp_path / "controller-ca.crt")
    controller_ca._state.update(at=0.0, pem="")
    yield
    controller_ca._state.update(at=0.0, pem="")


@pytest.fixture(autouse=True)
def _no_vulnerability_downloads():
    """
    Vulnerability data (app/vulnerabilities.py, app/third_party.py) is never
    fetched from the internet in tests: a test that needs it patches in a
    fake, and NVD's pause between requests is dropped.
    """
    from unittest.mock import patch
    from app import third_party, vulnerabilities, windows_os

    class _Offline:
        def get(self, url, **kwargs):
            raise RuntimeError(f"network disabled in tests: {url}")

    with patch.object(vulnerabilities, "_http", _Offline()), patch.object(third_party, "NVD_GAP_SECONDS", 0), \
            patch.object(third_party, "NVD_GAP_WITH_KEY", 0), patch.object(windows_os, "GAP_SECONDS", 0):
        yield
