"""
Regression tests for the pre-public security hardening: enrollment input
validation, hostname-takeover binding, X-Forwarded-For trust, and the
security response headers. Uses the shared fixtures in conftest.py.
"""
import uuid

import pytest

from app.rate_limit import _rate_limit_key

SECRET = "test-enroll-secret"


def _uniq(prefix):
    # Unique per call — the test DB is session-scoped and shared with
    # every other test, so a fixed hostname could collide with a row left
    # by another test and make the identity-binding assertions flaky.
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


@pytest.fixture(autouse=True)
def _no_proxmox_autoresolve(db):
    # The session-scoped DB is shared with every other test; some leave
    # Proxmox creds in Settings. With a SMBIOS UUID present, enrollment
    # would then attempt a real (unreachable) Proxmox lookup. Clear the
    # host so resolve_proxmox_config() short-circuits and these tests
    # exercise enrollment on its own.
    from app.settings_store import set_setting
    set_setting(db, "rollback_proxmox_host", "")
    yield


def _enroll(client, hostname, **kw):
    body = {"secret": SECRET, "hostname": hostname, "os_version": "1.0"}
    body.update(kw)
    return client.post("/agent/self-enroll", json=body)


# ---------- Identifier validation (XSS at the source) ----------

def test_valid_enrollment_succeeds(client):
    r = _enroll(client, _uniq("app-web"), team="Web Ops", os_family="rocky9")
    assert r.status_code == 200
    assert "agent_secret" in r.json()


@pytest.mark.parametrize("field,value", [
    ("hostname", "x');alert(1);//"),
    ("hostname", "<script>bad</script>"),
    ("team", "<img src=x onerror=alert(1)>"),
    ("team", "a'-alert(1)-'"),
    ("os_family", "a';x"),
    ("os_family", "<svg onload=1>"),
])
def test_injection_identifiers_are_rejected(client, field, value):
    if field == "hostname":
        r = _enroll(client, value)
    else:
        r = _enroll(client, _uniq("safe-host"), **{field: value})
    assert r.status_code == 422, f"{field}={value!r} should be rejected"


def test_empty_hostname_rejected(client):
    assert _enroll(client, "").status_code == 422


# ---------- Hostname-takeover binding (trust on first use) ----------

def test_same_hardware_may_reenroll(client):
    h = _uniq("bind")
    assert _enroll(client, h, smbios_uuid="UUID-AAA").status_code == 200
    assert _enroll(client, h, smbios_uuid="UUID-AAA").status_code == 200


def test_different_hardware_cannot_take_over(client):
    h = _uniq("bind")
    assert _enroll(client, h, smbios_uuid="UUID-AAA").status_code == 200
    assert _enroll(client, h, smbios_uuid="UUID-BBB").status_code == 409
    # Omitting the UUID entirely on a bound host is refused too.
    assert _enroll(client, h).status_code == 409


def test_the_shared_secret_cant_take_over_a_host_with_no_hardware_id(client, logged_in):
    """
    The shared secret is in every install command. A host with no hardware id on record (every
    Windows host whose agent sent none) could be re-enrolled with it by anyone holding it -- taking
    its job stream, root scripts included. Now only a one-time token, which an admin issues for
    that hostname, re-enrolls it; the hardware id it brings is adopted, and binds from then on.
    """
    h = _uniq("bind")
    assert _enroll(client, h).status_code == 200                          # new host, no UUID
    r = _enroll(client, h, smbios_uuid="UUID-CCC")
    assert r.status_code == 409 and "one-time token" in r.json()["detail"]
    logged_in("admin")
    token = client.post("/enroll/tokens", json={"hostname": h}).json()["token"]
    assert client.post("/agent/enroll", json={"token": token, "os_version": "1.0",
                                              "smbios_uuid": "UUID-CCC"}).status_code == 200   # adopted
    assert _enroll(client, h, smbios_uuid="UUID-CCC").status_code == 200  # same machine: fine
    assert _enroll(client, h, smbios_uuid="UUID-DDD").status_code == 409  # other hardware: refused
    assert _enroll(client, h).status_code == 409                          # none at all: refused


def test_only_admins_see_hardware_ids(client, logged_in, db):
    h = _uniq("uuid")
    host_id = _enroll(client, h, smbios_uuid="UUID-EEE").json()["host_id"]
    for role, seen in (("viewer", ""), ("operator", ""), ("lead", ""), ("admin", "UUID-EEE")):
        logged_in(role)
        assert client.get(f"/hosts/{host_id}").json()["smbios_uuid"] == seen
        listed = next(x for x in client.get("/hosts").json() if x["id"] == host_id)
        assert listed["smbios_uuid"] == seen
    from app import models
    db.expire_all()
    assert db.get(models.Host, host_id).smbios_uuid == "UUID-EEE"      # hidden in the answer, not erased


@pytest.mark.parametrize("pattern, ok", [
    ("openssl*", True), ("kernel-core", True), ("python3.11-libs", True), ("KB5046617", True),
    ("*Silverlight*", True), ("2024-01 Cumulative Update (KB503)", True), ("perl(DBI)", True),
    ("*", False), ("**?", False), ("-x", False), ("--exclude=*", False), ("a;rm -rf /", False),
    ("a$(id)", False), ("a\nb", False), ("'quoted'", False), ("x" * 201, False), ("", False),
])
def test_rule_patterns_are_checked(client, logged_in, pattern, ok):
    logged_in("admin")
    r = client.post("/defs", json={"pkg_pattern": pattern, "mode": "skip", "reason": "test"})
    assert (r.status_code == 200) is ok, (pattern, r.status_code, r.text)
    if ok:
        client.delete(f"/defs/{r.json()['id']}")


def test_pin_versions_are_checked(client, logged_in):
    logged_in("admin")
    good = client.post("/defs", json={"pkg_pattern": "nginx", "mode": "pin", "version": "1:1.24.0-1.el9", "reason": "t"})
    assert good.status_code == 200
    client.delete(f"/defs/{good.json()['id']}")
    for bad in ("-1", "1.0;id", "1 0"):
        assert client.post("/defs", json={"pkg_pattern": "nginx", "mode": "pin", "version": bad,
                                          "reason": "t"}).status_code == 422


# ---------- X-Forwarded-For trust ----------

class _Req:
    def __init__(self, peer, xff=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff} if xff else {}


def test_xff_ignored_from_untrusted_peer():
    # A direct network client spoofing the header -> its real socket peer wins.
    assert _rate_limit_key(_Req("203.0.113.9", xff="1.2.3.4")) == "203.0.113.9"


def test_xff_trusted_only_from_proxy_peer_reads_last_entry():
    assert _rate_limit_key(_Req("127.0.0.1", xff="9.9.9.9, 203.0.113.9")) == "203.0.113.9"


# ---------- Security headers ----------

def test_security_headers_present(client):
    h = client.get("/").headers
    assert "default-src 'self'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"


def test_an_agent_reports_its_hardware_id_once_none_is_on_record(client, db):
    """Windows hosts enrolled without one get it from their next inventory report,
    authenticated by their own credential; it's never replaced afterwards."""
    from app import models
    h = _uniq("inv-uuid")
    body = _enroll(client, h).json()
    auth = {"Authorization": f"Bearer {body['agent_secret']}"}
    url = f"/agent/{body['host_id']}/inventory"
    assert client.post(url, headers=auth, json={"runtime": "", "containers": [],
                                                 "smbios_uuid": "ABCD-1234"}).status_code == 200
    db.expire_all()
    assert db.get(models.Host, body["host_id"]).smbios_uuid == "abcd-1234"
    client.post(url, headers=auth, json={"runtime": "", "containers": [], "smbios_uuid": "other"})
    db.expire_all()
    assert db.get(models.Host, body["host_id"]).smbios_uuid == "abcd-1234"
    assert _enroll(client, h, smbios_uuid="abcd-1234").status_code == 200   # now re-enrolls like a Linux host


# ---------- writes must come from the console's own origin ----------
# SameSite=Lax treats every port and sibling service on the controller's
# host name as the same site, so the cookie alone doesn't keep them out.

def test_a_write_from_another_origin_is_refused(client, logged_in, db):
    from app import models
    logged_in(role="admin", username="origin-admin")
    before = db.query(models.ChecklistItem).count()
    for origin in ("https://evil.example", "http://testserver:8081", "null"):
        resp = client.post("/checklist-items", json={"text": "planted"}, headers={"Origin": origin})
        assert resp.status_code == 403, origin
    assert db.query(models.ChecklistItem).count() == before


def test_writes_from_the_console_and_from_non_browsers_still_work(client, logged_in, db):
    from app import models
    logged_in(role="admin", username="origin-admin-2")
    same = client.post("/checklist-items", json={"text": "from the console"}, headers={"Origin": "http://testserver"})
    assert same.status_code == 200, same.text
    no_origin = client.post("/checklist-items", json={"text": "from a script"})      # agents, curl, the MCP server
    assert no_origin.status_code == 200, no_origin.text
    # Removed directly: the API keeps the last item, which these may be.
    db.query(models.ChecklistItem).filter(
        models.ChecklistItem.id.in_([same.json()["id"], no_origin.json()["id"]])).delete(synchronize_session=False)
    db.commit()


def test_reads_are_not_affected_by_origin(client, logged_in):
    logged_in(role="viewer", username="origin-viewer")
    assert client.get("/hosts", headers={"Origin": "https://evil.example"}).status_code == 200


# ---------- an agent's reports have a size ----------
# Everything an agent sends is stored and shown, and one machine could
# otherwise fill the database with a single request. Over-long values are
# cut rather than refused, so the rest of the report still lands.

def _agent(db):
    from conftest import make_host
    host, secret = make_host(db)
    return host, {"Authorization": f"Bearer {secret}"}


def test_an_oversized_inventory_is_cut_down_not_stored_whole(client, db):
    from app import models, schemas
    host, auth = _agent(db)
    report = {
        "runtime": "docker",
        "containers": [{"name": f"c{i}", "image": "img"} for i in range(schemas.MAX_REPORTED_CONTAINERS + 50)],
        "updates": [{"package": "p" * 5000, "new_version": "1", "advisory": "a" * 5000, "severity": "critical"}],
        "updates_ok": True,
        "update_sources": [{"name": "os", "ok": True}],
    }
    resp = client.post(f"/agent/{host.id}/inventory", json=report, headers=auth)
    assert resp.status_code == 200, resp.text
    assert db.query(models.Container).filter(models.Container.host_id == host.id).count() == schemas.MAX_REPORTED_CONTAINERS
    update = db.query(models.PendingUpdate).filter(models.PendingUpdate.host_id == host.id).one()
    assert len(update.package) == 500 and len(update.advisory) == 500
    assert update.severity == "critical"                       # the rest of the row is intact


def test_stage_output_keeps_its_end(client, db):
    """The end of the output is where a failed stage says what went wrong."""
    from app import jobs_engine, models
    host, auth = _agent(db)
    host.rollback_backend = "none"
    job = models.Job(host_id=host.id, hostname=host.hostname, ticket_id="", operator="t", operator_role="admin")
    db.add(job)
    db.commit()
    for i, (name, executor) in enumerate(models.STAGE_SEQUENCE):
        db.add(models.JobStage(job_id=job.id, stage_index=i, name=name, executor=executor))
    db.commit()
    jobs_engine.advance_job(db, job)
    stage = next(s for s in sorted(job.stages, key=lambda s: s.stage_index) if s.status == "running")

    output = "x" * 200_000 + "THE ACTUAL ERROR"
    resp = client.post(f"/agent/{host.id}/jobs/{job.id}/stages/{stage.name}/report",
                       json={"status": "failed", "output": output}, headers=auth)
    assert resp.status_code == 200, resp.text
    db.refresh(stage)
    assert len(stage.output) == 64_000 and stage.output.endswith("THE ACTUAL ERROR")


def test_enrollment_text_is_bounded(client, db):
    from app import models
    resp = client.post("/agent/self-enroll", json={
        "secret": "test-enroll-secret", "hostname": "bounded-host", "os_version": "v" * 10_000, "os_family": "rocky9",
    })
    assert resp.status_code == 200, resp.text
    assert len(db.query(models.Host).filter(models.Host.hostname == "bounded-host").one().os_version) == 200
