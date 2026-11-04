"""
Risk-based patching: what's pending on each host, how severe, and
restricting a run to a severity band.

The distinction this file exists to pin is "we don't know" versus
"nothing pending". A single unreachable repository fails a host's whole
update query, and showing such a host as fully patched is worse than
showing nothing at all.
"""
from app import models
from conftest import make_host


def _report(client, host, secret, updates, ok=True, error=""):
    return client.post(
        f"/agent/{host.id}/inventory",
        json={"runtime": "", "containers": [], "updates": updates,
              "updates_ok": ok, "updates_error": error},
        headers={"Authorization": f"Bearer {secret}"},
    )


def _update(package, severity="none", is_security=False, advisory="RLSA-1"):
    return {"package": package, "new_version": "1.2.3", "advisory": advisory,
            "severity": severity, "is_security": is_security}


def _clear(db):
    db.query(models.PendingUpdate).delete()
    for h in db.query(models.Host).all():
        h.updates_assessed_ok = None
    db.commit()


def _start(client, host, **kw):
    body = {"host_id": host.id, "checklist": [{"item_index": 0, "item_text": "ok"}]}
    body.update(kw)
    return client.post("/runs", json=body)


# ---------- reporting ----------

def test_pending_updates_are_stored_with_severity(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [
        _update("openssl", "important", True),
        _update("kernel-tools", "none", False, advisory="RLBA-9"),
    ])

    rows = {u.package: u for u in db.query(models.PendingUpdate).filter(
        models.PendingUpdate.host_id == host.id)}
    assert rows["openssl"].severity == "important" and rows["openssl"].is_security is True
    assert rows["kernel-tools"].is_security is False
    db.refresh(host)
    assert host.updates_assessed_ok is True


def test_a_failed_assessment_does_not_blank_what_we_knew(client, db, logged_in):
    """
    Wiping the list on a failed query would read as "this host is now
    fully patched", which is the opposite of what happened.
    """
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [_update("openssl", "critical", True)])

    _report(client, host, secret, [], ok=False, error="Failed to download metadata for repo 'x'")

    rows = db.query(models.PendingUpdate).filter(models.PendingUpdate.host_id == host.id).all()
    assert len(rows) == 1, "the last known list must survive a failed query"
    db.refresh(host)
    assert host.updates_assessed_ok is False
    assert "Failed to download metadata" in host.updates_error


def test_a_successful_empty_assessment_does_clear_the_list(client, db, logged_in):
    """A host that really has nothing pending must stop listing what it
    had before it was patched."""
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [_update("openssl", "critical", True)])

    _report(client, host, secret, [])

    assert db.query(models.PendingUpdate).filter(models.PendingUpdate.host_id == host.id).count() == 0
    db.refresh(host)
    assert host.updates_assessed_ok is True


def test_host_updates_are_listed_most_severe_first(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [
        _update("zlib", "low", True), _update("openssl", "critical", True),
        _update("curl", "moderate", True), _update("tzdata", "none", False),
    ])

    order = [u["package"] for u in client.get(f"/hosts/{host.id}/updates").json()]

    assert order == ["openssl", "curl", "zlib", "tzdata"]


# ---------- fleet aggregation ----------

def test_dashboard_counts_risk_by_severity(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [
        _update("a", "critical", True), _update("b", "important", True),
        _update("c", "moderate", True), _update("d", "none", False),
    ])

    risk = client.get("/dashboard").json()["risk"]

    assert risk["total"] == 4
    assert risk["security"] == 3
    assert risk["by_severity"]["critical"] == 1
    assert risk["hosts_with_critical"] == 1


def test_unassessed_hosts_are_counted_separately(client, db, logged_in):
    """Never folded into the totals — an unqueryable host has an unknown
    number pending, not zero."""
    _clear(db)
    logged_in("operator")
    good, good_secret = make_host(db)
    broken, broken_secret = make_host(db)
    _report(client, good, good_secret, [_update("a", "critical", True)])
    _report(client, broken, broken_secret, [], ok=False, error="repo unreachable")

    risk = client.get("/dashboard").json()["risk"]

    assert risk["total"] == 1, "the broken host contributes no phantom zero"
    assert risk["unassessed"] >= 1


def test_worst_hosts_rank_by_severity_before_volume(client, db, logged_in):
    """One critical outranks forty moderates — that is the whole point of
    ranking by risk rather than by count."""
    _clear(db)
    logged_in("operator")
    one_critical, s1 = make_host(db, hostname="has-critical")
    many_moderate, s2 = make_host(db, hostname="has-volume")
    _report(client, one_critical, s1, [_update("a", "critical", True)])
    _report(client, many_moderate, s2, [_update(f"p{i}", "moderate", True) for i in range(40)])

    worst = client.get("/dashboard").json()["risk"]["worst_hosts"]

    assert worst[0]["hostname"] == "has-critical"


# ---------- severity-filtered runs ----------

def test_a_run_can_be_restricted_to_a_severity_band(client, db, logged_in):
    logged_in("admin")
    host, _ = make_host(db)
    job = _start(client, host, severity_filter="critical,important").json()
    assert job["severity_filter"] == "critical,important"


def test_security_only_is_accepted(client, db, logged_in):
    logged_in("admin")
    host, _ = make_host(db)
    assert _start(client, host, severity_filter="security").json()["severity_filter"] == "security"


def test_all_normalises_to_no_filter(client, db, logged_in):
    logged_in("admin")
    host, _ = make_host(db)
    assert _start(client, host, severity_filter="all").json()["severity_filter"] == ""


def test_a_typo_in_a_severity_is_refused(client, db, logged_in):
    """Silently matching nothing would patch an empty set and report
    success."""
    logged_in("admin")
    host, _ = make_host(db)
    resp = _start(client, host, severity_filter="hihg")
    assert resp.status_code == 400
    assert "Unknown severity" in resp.text


def test_a_severity_filter_is_refused_on_a_containers_only_run(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    client.post(f"/agent/{host.id}/inventory", json={"runtime": "docker", "containers": [{
        "container_id": "a", "name": "web", "image": "i:1", "state": "running",
        "managed_by": "compose", "compose_project": "p", "compose_service": "web",
        "compose_working_dir": "/srv/p", "pinned": False, "update_available": True}]},
        headers={"Authorization": f"Bearer {secret}"})

    resp = _start(client, host, scope="containers", severity_filter="critical")

    assert resp.status_code == 400
    assert "patches none" in resp.text


def test_the_agent_is_told_the_filter(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    _start(client, host, severity_filter="critical")

    hdr = {"Authorization": f"Bearer {secret}"}
    instruction = client.get(f"/agent/{host.id}/jobs/next", headers=hdr).json()

    assert instruction["severity_filter"] == "critical"


def test_deleting_a_host_removes_its_pending_updates(client, db, logged_in):
    _clear(db)
    logged_in("admin")
    host, secret = make_host(db)
    _report(client, host, secret, [_update("openssl", "critical", True)])

    assert client.delete(f"/hosts/{host.id}").status_code == 200
    assert db.query(models.PendingUpdate).filter(models.PendingUpdate.host_id == host.id).count() == 0


# ---------- fleet column ----------

def test_fleet_carries_worst_severity_and_count(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db, hostname="risk-fleet")
    _report(client, host, secret, [
        _update("a", "moderate", True), _update("b", "critical", True), _update("c", "low", True),
    ])

    row = [h for h in client.get("/hosts").json() if h["hostname"] == "risk-fleet"][0]

    assert row["pending_updates"] == 3
    assert row["max_severity"] == "critical"


def test_an_unassessed_host_reports_no_phantom_zero(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db, hostname="risk-unknown")
    _report(client, host, secret, [], ok=False, error="repo unreachable")

    row = [h for h in client.get("/hosts").json() if h["hostname"] == "risk-unknown"][0]

    assert row["updates_assessed_ok"] is False
    assert row["pending_updates"] == 0   # the flag is what distinguishes this from clean


def test_fleet_counts_come_from_one_query(client, db, logged_in):
    """Per-host counts must not become an N+1 as the fleet grows."""
    _clear(db)
    logged_in("operator")
    for i in range(6):
        host, secret = make_host(db, hostname=f"n1-{i}")
        _report(client, host, secret, [_update("openssl", "critical", True)])

    from sqlalchemy import event
    from app.db import engine
    seen = []
    def count(conn, cursor, statement, *a):
        if "pending_updates" in statement.lower():
            seen.append(statement)
    event.listen(engine, "before_cursor_execute", count)
    try:
        client.get("/hosts")
    finally:
        event.remove(engine, "before_cursor_execute", count)

    assert len(seen) == 1, f"expected one grouped query, saw {len(seen)}"


# ---------- notification on new findings ----------

def test_a_newly_appearing_critical_is_announced(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db, hostname="alerting-host")
    _report(client, host, secret, [_update("openssl", "critical", True)])

    entries = db.query(models.AuditLog).filter(
        models.AuditLog.action == "critical_update_found").all()
    assert any("alerting-host" in e.detail and "openssl" in e.detail for e in entries)
    assert entries[-1].tone == "danger"


def test_the_same_finding_is_not_re_announced_every_poll(client, db, logged_in):
    """Re-reporting the same advisory on every check-in turns the
    notification channel into noise nobody reads."""
    _clear(db)
    logged_in("operator")
    # Hostnames are UNIQUE and the test database is session-scoped, so a
    # literal one has to be unique across every test file, not just this
    # one. test_containers.py already uses "quiet-host".
    host, secret = make_host(db, hostname="no-repeat-host")
    _report(client, host, secret, [_update("openssl", "critical", True)])
    before = db.query(models.AuditLog).filter(
        models.AuditLog.action == "critical_update_found").count()

    for _ in range(3):
        _report(client, host, secret, [_update("openssl", "critical", True)])

    after = db.query(models.AuditLog).filter(
        models.AuditLog.action == "critical_update_found").count()
    assert after == before


def test_a_moderate_finding_is_not_announced(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db, hostname="moderate-host")
    _report(client, host, secret, [_update("curl", "moderate", True)])

    entries = db.query(models.AuditLog).filter(
        models.AuditLog.action == "critical_update_found").all()
    assert not any("moderate-host" in e.detail for e in entries)


def test_metrics_expose_risk_and_containers(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [_update("openssl", "critical", True)])

    body = client.get("/metrics").text

    assert 'kite_pending_updates{severity="critical"}' in body
    assert "kite_hosts_unassessed" in body
    assert "kite_containers_outdated" in body


def test_the_reason_an_assessment_failed_reaches_the_console(client, db, logged_in):
    """
    "Unknown" without a reason sends an operator to the host's log for
    something the controller already knows. The agent reports why; the
    API has to pass it on.
    """
    logged_in("operator")
    host, secret = make_host(db)
    resp = client.post(
        f"/agent/{host.id}/inventory",
        json={"runtime": "", "containers": [], "updates": [], "updates_ok": False,
              "updates_error": "Cannot download repomd.xml: All mirrors were tried"},
        headers={"Authorization": f"Bearer {secret}"},
    )
    assert resp.status_code == 200, resp.text

    body = client.get(f"/hosts/{host.id}").json()
    assert body["updates_assessed_ok"] is False
    assert "All mirrors were tried" in body["updates_error"]


def test_a_successful_assessment_carries_no_stale_reason(client, db, logged_in):
    """A host that recovers must not keep showing the failure it recovered from."""
    logged_in("operator")
    host, secret = make_host(db)
    headers = {"Authorization": f"Bearer {secret}"}
    client.post(f"/agent/{host.id}/inventory",
                json={"runtime": "", "containers": [], "updates": [], "updates_ok": False,
                      "updates_error": "repo unreachable"}, headers=headers)
    client.post(f"/agent/{host.id}/inventory",
                json={"runtime": "", "containers": [], "updates": [], "updates_ok": True,
                      "updates_error": ""}, headers=headers)

    body = client.get(f"/hosts/{host.id}").json()
    assert body["updates_assessed_ok"] is True
    assert not body["updates_error"]
