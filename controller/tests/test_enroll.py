import uuid

from app import models, monitoring


def _enroll_payload(hostname):
    return {
        "os_version": "Rocky Linux 9.8", "os_family": "rocky9",
        "smbios_uuid": "", "poll_interval_seconds": 900, "proxmox_vmid": None,
    }


def test_token_enroll_full_flow(client, logged_in):
    logged_in(role="admin", username="token-admin")
    hostname = f"token-host-{uuid.uuid4().hex[:8]}"

    token_resp = client.post("/enroll/tokens", json={"hostname": hostname, "team": "sre", "role": "web"})
    assert token_resp.status_code == 200
    token = token_resp.json()["token"]

    enroll_resp = client.post("/agent/enroll", json={"token": token, **_enroll_payload(hostname)})
    assert enroll_resp.status_code == 200
    body = enroll_resp.json()
    assert "host_id" in body and "agent_secret" in body

    # A one-time token is exactly that.
    reuse_resp = client.post("/agent/enroll", json={"token": token, **_enroll_payload(hostname)})
    assert reuse_resp.status_code == 409


def test_token_enroll_rejects_unknown_token(client):
    resp = client.post("/agent/enroll", json={"token": "not-a-real-token", **_enroll_payload("whatever")})
    assert resp.status_code == 404


def test_self_enroll_requires_correct_shared_secret(client):
    hostname = f"self-host-{uuid.uuid4().hex[:8]}"
    wrong = client.post("/agent/self-enroll", json={
        "secret": "definitely-wrong", "hostname": hostname, **_enroll_payload(hostname),
    })
    assert wrong.status_code == 401

    right = client.post("/agent/self-enroll", json={
        "secret": "test-enroll-secret", "hostname": hostname, **_enroll_payload(hostname),
    })
    assert right.status_code == 200
    assert "agent_secret" in right.json()


def test_agent_credential_required_for_agent_endpoints(client):
    hostname = f"cred-host-{uuid.uuid4().hex[:8]}"
    enroll_resp = client.post("/agent/self-enroll", json={
        "secret": "test-enroll-secret", "hostname": hostname, **_enroll_payload(hostname),
    })
    host_id = enroll_resp.json()["host_id"]
    real_secret = enroll_resp.json()["agent_secret"]

    no_auth = client.get(f"/agent/{host_id}/jobs/next")
    assert no_auth.status_code == 401

    wrong_secret = client.get(f"/agent/{host_id}/jobs/next", headers={"Authorization": "Bearer wrong-one"})
    assert wrong_secret.status_code == 401

    right_secret = client.get(f"/agent/{host_id}/jobs/next", headers={"Authorization": f"Bearer {real_secret}"})
    assert right_secret.status_code == 200


def test_token_enroll_requires_admin(client, logged_in):
    logged_in(role="operator", username="token-operator")
    resp = client.post("/enroll/tokens", json={"hostname": "irrelevant", "team": "", "role": ""})
    assert resp.status_code == 403


def test_enrollment_counts_as_contact(client, db):
    """
    A freshly enrolled host used to have last_seen NULL until its first
    poll, which connectivity_tier reads as 'offline' — so the dashboard
    said 0% reachable right after a successful enrollment.
    """
    resp = client.post("/agent/self-enroll", json={
        "secret": "test-enroll-secret", "hostname": "just-enrolled",
        "os_version": "Rocky 9", "os_family": "rocky9",
    })
    assert resp.status_code == 200, resp.text

    host = db.query(models.Host).filter(models.Host.hostname == "just-enrolled").one()
    assert host.last_seen is not None
    assert monitoring.connectivity_tier(host) == "healthy"
