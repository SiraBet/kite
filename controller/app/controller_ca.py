"""
The certificate authority agents check the controller's HTTPS against.

By default Caddy serves the controller with certificates from its own
local CA: a leaf reissued every 12 hours and an intermediate every week,
both signed by a root that lasts ten years. Nothing outside trusts that
root, so agents used to turn certificate checks off altogether
(--insecure), and anyone between a host and the controller could stand
in for it.

Instead the controller publishes the root (GET /download/ca.crt) and
the console puts its SHA-256 fingerprint in every enrol command: the
host downloads the root, checks the fingerprint, and from then on
trusts that root alone for the controller. The fingerprint is the same
one a browser shows for the root, so it can be checked by eye too.

Where the root comes from, first found:
  - KITE_CA_CERT, a PEM file (Docker, or any proxy other than Caddy);
  - Caddy's admin API on this machine (KITE_CADDY_ADMIN, default
    http://localhost:2019), but only while Caddy issues the controller's
    certificates itself. With --domain (Let's Encrypt) there's nothing
    to publish: agents check a public certificate the normal way.
The last root read from Caddy is kept in STATE_DIR, so a Caddy admin
API that's briefly away doesn't change what the console hands out.
"""
import hashlib
import os
import ssl
import threading
import time
from pathlib import Path

import requests

from .config import STATE_DIR
from .logging_config import logger

CA_FILE = os.environ.get("KITE_CA_CERT", "")
CADDY_ADMIN = os.environ.get("KITE_CADDY_ADMIN", "http://localhost:2019").rstrip("/")
CACHE = STATE_DIR / "controller-ca.crt"
REFRESH_SECONDS = 3600

_lock = threading.Lock()
_state = {"at": 0.0, "pem": ""}


def _one_cert(pem: str) -> str:
    """The PEM if it holds exactly one certificate, else ''."""
    pem = (pem or "").strip()
    if pem.count("-----BEGIN CERTIFICATE-----") != 1:
        return ""
    try:
        ssl.PEM_cert_to_DER_cert(pem)
    except ValueError:
        return ""
    return pem + "\n"


def fingerprint(pem: str) -> str:
    """SHA-256 of the certificate (DER), lowercase hex: what a browser shows for it."""
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def _from_caddy():
    """
    Caddy's root, '' when Caddy's certificates come from somewhere else
    (Let's Encrypt), or None when Caddy can't be asked.
    """
    try:
        policies = requests.get(f"{CADDY_ADMIN}/config/apps/tls/automation/policies", timeout=3).json() or []
        internal = bool(policies) and all(
            p.get("issuers") and all(i.get("module") == "internal" for i in p["issuers"]) for p in policies)
        if not internal:
            return ""
        return _one_cert(requests.get(f"{CADDY_ADMIN}/pki/ca/local", timeout=3).json().get("root_certificate", ""))
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        return None


def _read(path) -> str:
    try:
        return _one_cert(Path(path).read_text())
    except OSError:
        return ""


def current() -> str:
    """The root agents should trust, as PEM, or '' when there's none to publish."""
    if CA_FILE:
        return _read(CA_FILE)
    with _lock:
        if _state["at"] and time.monotonic() - _state["at"] < REFRESH_SECONDS:
            return _state["pem"]
        pem = _from_caddy()
        if pem is None:                      # Caddy not answering: keep to what it last said
            pem = _state["pem"] or _read(CACHE)
        elif pem:
            if pem != _read(CACHE):
                try:
                    CACHE.write_text(pem)
                except OSError as e:
                    logger.warning("could not keep a copy of the controller's CA: %s", e)
        else:
            CACHE.unlink(missing_ok=True)
        _state.update(at=time.monotonic(), pem=pem)
        return pem


def describe() -> dict:
    pem = current()
    return {"available": bool(pem), "sha256": fingerprint(pem) if pem else ""}
