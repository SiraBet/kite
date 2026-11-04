"""
app/controller_ca.py: which root the controller publishes for agents to
pin, and GET /download/ca.crt. Caddy's admin API is faked; the
certificate is made here.
"""
import hashlib
import ssl
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import controller_ca


def _root(cn="Test Local Authority - Root"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


ROOT = _root()


class _Caddy:
    """Answers like Caddy's admin API: its TLS policies, and its local CA."""

    def __init__(self, issuers=("internal",), root=ROOT, up=True):
        self.issuers, self.root, self.up = issuers, root, up

    def get(self, url, timeout=None):
        if not self.up:
            raise requests.ConnectionError("connection refused")

        class R:
            def __init__(self, body):
                self.body = body

            def json(self):
                return self.body
        if url.endswith("/config/apps/tls/automation/policies"):
            return R([{"issuers": [{"module": m} for m in self.issuers]}] if self.issuers else None)
        return R({"root_certificate": self.root})


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(controller_ca, "CA_FILE", "")   # conftest gives each test an empty CACHE


def _ask(caddy):
    controller_ca._state.update(at=0.0)
    with patch.object(controller_ca.requests, "get", caddy.get):
        return controller_ca.current()


def test_caddys_own_root_is_published_with_its_fingerprint():
    assert _ask(_Caddy()) == ROOT.strip() + "\n"
    info = controller_ca.describe()
    assert info["available"] and info["sha256"] == hashlib.sha256(ssl.PEM_cert_to_DER_cert(ROOT)).hexdigest()


def test_nothing_is_published_when_caddy_uses_a_public_ca():
    """--domain: Let's Encrypt. Pinning Caddy's unused local root would lock agents out."""
    assert _ask(_Caddy()) and controller_ca.CACHE.exists()
    assert _ask(_Caddy(issuers=("acme",))) == ""
    assert not controller_ca.CACHE.exists()
    assert _ask(_Caddy(issuers=())) == ""
    assert _ask(_Caddy(issuers=("internal", "acme"))) == ""


def test_the_last_root_is_kept_while_caddy_cant_be_asked():
    assert _ask(_Caddy())
    controller_ca._state.update(pem="")      # as after a restart: only the copy on disk
    assert _ask(_Caddy(up=False)) == ROOT.strip() + "\n"


def test_a_configured_file_wins(tmp_path, monkeypatch):
    other = _root("Some Other Root")
    (tmp_path / "ca.pem").write_text(other)
    monkeypatch.setattr(controller_ca, "CA_FILE", str(tmp_path / "ca.pem"))
    assert _ask(_Caddy()) == other.strip() + "\n"


def test_anything_but_one_certificate_is_refused():
    assert _ask(_Caddy(root="not a certificate")) == ""
    assert _ask(_Caddy(root=ROOT + ROOT)) == ""


def test_the_root_downloads_without_a_session(client, logged_in):
    controller_ca._state.update(at=float("inf"), pem=ROOT)   # "fresh": no Caddy asked
    r = client.get("/download/ca.crt")
    assert r.status_code == 200 and r.text == ROOT
    logged_in("viewer")
    assert client.get("/download/ca").json() == {
        "available": True, "sha256": hashlib.sha256(ssl.PEM_cert_to_DER_cert(ROOT)).hexdigest()}


def test_no_root_is_a_404(client):
    controller_ca._state.update(at=float("inf"), pem="")
    assert client.get("/download/ca.crt").status_code == 404
