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


# ---------- Which VM a host is linked to ----------
# The VM id decides which VM the controller snapshots and offers to
# restore for a host, so an enrolling agent only gets to name one when an
# admin issued its token, and never gets to change one that's already set.

def _token_for(client, logged_in, hostname):
    logged_in(role="admin", username=f"vmid-admin-{uuid.uuid4().hex[:8]}")
    return client.post("/enroll/tokens", json={"hostname": hostname, "team": "", "role": ""}).json()["token"]


def _host(db, hostname):
    db.expire_all()
    return db.query(models.Host).filter(models.Host.hostname == hostname).one()


def _audited(db, action, hostname):
    return [r for r in db.query(models.AuditLog).filter(models.AuditLog.action == action).all()
            if hostname in (r.detail or "")]


def test_token_enroll_takes_the_agents_vmid(client, logged_in, db):
    hostname = f"vmid-token-{uuid.uuid4().hex[:8]}"
    token = _token_for(client, logged_in, hostname)
    resp = client.post("/agent/enroll", json={"token": token, **_enroll_payload(hostname), "proxmox_vmid": 4101})
    assert resp.status_code == 200, resp.text
    assert _host(db, hostname).proxmox_vmid == 4101
    assert not _audited(db, "enroll_vmid_ignored", hostname)


def test_self_enroll_ignores_the_agents_vmid(client, db):
    """Anyone holding the shared secret could otherwise link a host to any VM."""
    hostname = f"vmid-self-{uuid.uuid4().hex[:8]}"
    resp = client.post("/agent/self-enroll", json={
        "secret": "test-enroll-secret", "hostname": hostname, **_enroll_payload(hostname), "proxmox_vmid": 4102,
    })
    assert resp.status_code == 200, resp.text
    assert _host(db, hostname).proxmox_vmid is None
    assert len(_audited(db, "enroll_vmid_ignored", hostname)) == 1


def test_self_re_enroll_cannot_repoint_a_linked_host(client, db):
    """A host that re-enrols itself must not be able to move its link to another VM."""
    hostname = f"vmid-repoint-{uuid.uuid4().hex[:8]}"
    payload = {"secret": "test-enroll-secret", "hostname": hostname, **_enroll_payload(hostname),
               "smbios_uuid": str(uuid.uuid4())}
    assert client.post("/agent/self-enroll", json=payload).status_code == 200
    host = _host(db, hostname)
    host.proxmox_vmid = 4103   # as an admin, or the SMBIOS match, would have set it
    db.commit()

    resp = client.post("/agent/self-enroll", json={**payload, "proxmox_vmid": 4999})
    assert resp.status_code == 200, resp.text
    assert _host(db, hostname).proxmox_vmid == 4103


def test_token_re_enroll_keeps_an_existing_link(client, logged_in, db):
    hostname = f"vmid-keep-{uuid.uuid4().hex[:8]}"
    first = _token_for(client, logged_in, hostname)
    assert client.post("/agent/enroll", json={"token": first, **_enroll_payload(hostname),
                                              "proxmox_vmid": 4104}).status_code == 200

    second = _token_for(client, logged_in, hostname)
    resp = client.post("/agent/enroll", json={"token": second, **_enroll_payload(hostname), "proxmox_vmid": 4998})
    assert resp.status_code == 200, resp.text
    assert _host(db, hostname).proxmox_vmid == 4104
    assert len(_audited(db, "enroll_vmid_ignored", hostname)) == 1
