from conftest import make_user


def test_login_rate_limit_uses_the_proxy_appended_ip_not_client_supplied_one(client, db):
    """
    A reverse proxy appends the real client IP to any existing
    X-Forwarded-For header rather than replacing it, so the entry the
    proxy itself added is the LAST one, not the first. Reading the first
    entry trusts a value the client sent, letting anyone bypass the
    per-IP limit by rotating a fake leading entry.

    See app/rate_limit.py's docstring. This pins the behaviour so an
    edit that goes back to reading the first entry fails here.
    """
    make_user(db, "xff-victim", "operator", password="correct-horse")

    # A client can set its own X-Forwarded-For on the original request;
    # rotate a fake FIRST entry on every attempt while the (simulated)
    # proxy-appended REAL entry stays constant as the last one — the
    # limiter must still key on that last entry and block after 5.
    for i in range(5):
        resp = client.post(
            "/auth/login", json={"username": "xff-victim", "password": "wrong"},
            headers={"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.50"},
        )
        assert resp.status_code == 401

    blocked = client.post(
        "/auth/login", json={"username": "xff-victim", "password": "wrong"},
        headers={"X-Forwarded-For": "10.0.0.99, 203.0.113.50"},
    )
    assert blocked.status_code == 429

    # A genuinely different last (proxy-appended) entry is a different
    # client as far as the limiter is concerned — proves the fix keys
    # per real-client-IP rather than either "always blocked" or
    # "never blocked" regardless of header content.
    other_client = client.post(
        "/auth/login", json={"username": "xff-victim", "password": "wrong"},
        headers={"X-Forwarded-For": "10.0.0.1, 203.0.113.51"},
    )
    assert other_client.status_code == 401


def test_login_is_rate_limited_after_repeated_attempts(client, db):
    make_user(db, "rate-limit-victim", "operator", password="correct-horse")

    # The configured limit is 5/minute — the first 5 attempts (wrong
    # password each time) should each get a normal 401, not a 429.
    for _ in range(5):
        resp = client.post("/auth/login", json={"username": "rate-limit-victim", "password": "wrong"})
        assert resp.status_code == 401

    # The 6th attempt in the same window should be blocked outright.
    blocked = client.post("/auth/login", json={"username": "rate-limit-victim", "password": "wrong"})
    assert blocked.status_code == 429


def test_self_enroll_is_rate_limited_after_repeated_attempts(client):
    for _ in range(20):
        resp = client.post("/agent/self-enroll", json={
            "secret": "wrong-secret", "hostname": "rl-host",
            "os_version": "x", "os_family": "", "smbios_uuid": "",
            "poll_interval_seconds": 900, "proxmox_vmid": None,
        })
        assert resp.status_code == 401

    blocked = client.post("/agent/self-enroll", json={
        "secret": "wrong-secret", "hostname": "rl-host",
        "os_version": "x", "os_family": "", "smbios_uuid": "",
        "poll_interval_seconds": 900, "proxmox_vmid": None,
    })
    assert blocked.status_code == 429


def test_trusted_proxies_can_be_networks():
    """In Docker, Caddy is a container on a private network, not loopback (docker-compose.yml)."""
    from types import SimpleNamespace
    from unittest.mock import patch

    from app import rate_limit

    nets, names = rate_limit._parse("10.89.0.0/24, ::1, testclient, bogus/99")
    with patch.object(rate_limit, "_TRUSTED_NETS", nets), patch.object(rate_limit, "_TRUSTED_NAMES", names):
        def key(peer, xff):
            req = SimpleNamespace(client=SimpleNamespace(host=peer), headers={"x-forwarded-for": xff})
            return rate_limit._rate_limit_key(req)
        assert key("10.89.0.3", "1.2.3.4, 203.0.113.9") == "203.0.113.9"      # Caddy's container
        assert key("::1", "203.0.113.9") == "203.0.113.9"
        assert key("testclient", "203.0.113.9") == "203.0.113.9"
        assert key("198.51.100.7", "203.0.113.9") == "198.51.100.7"           # not a proxy: its own address
