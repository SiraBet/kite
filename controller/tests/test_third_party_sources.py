"""
Third-party update sources (winget/flatpak/snap) reported alongside OS
updates.

The rule this file pins is the multi-source form of "we could not tell
is not nothing": each source is refreshed independently, so one manager
failing must never blank another's findings, and a source that was not
assessed at all must keep whatever was last known for it.
"""
from app import models
from conftest import make_host


def _report(client, host, secret, updates, update_sources=None, ok=True, error=""):
    body = {"runtime": "", "containers": [], "updates": updates,
            "updates_ok": ok, "updates_error": error}
    if update_sources is not None:
        body["update_sources"] = update_sources
    return client.post(
        f"/agent/{host.id}/inventory", json=body,
        headers={"Authorization": f"Bearer {secret}"},
    )


def _u(package, source="os", current="", new="1.0", severity="none", is_security=False):
    return {"package": package, "new_version": new, "advisory": "", "severity": severity,
            "is_security": is_security, "source": source, "current_version": current}


def _rows(db, host):
    return {(u.package, u.source): u for u in db.query(models.PendingUpdate).filter(
        models.PendingUpdate.host_id == host.id)}


def test_updates_are_stored_with_their_source_and_current_version(client, db, logged_in):
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret,
            [_u("kernel", "os", new="5.14"),
             _u("Google Chrome", "winget", current="116.0", new="117.0")],
            update_sources=[{"name": "os", "ok": True}, {"name": "winget", "ok": True}])

    rows = _rows(db, host)
    assert rows[("kernel", "os")].current_version == ""
    chrome = rows[("Google Chrome", "winget")]
    assert chrome.current_version == "116.0" and chrome.new_version == "117.0"


def test_a_failing_source_does_not_blank_a_working_one(client, db, logged_in):
    logged_in("operator")
    host, secret = make_host(db)
    # First poll: both sources succeed.
    _report(client, host, secret,
            [_u("kernel", "os"), _u("Notepad++", "winget", current="8.5", new="8.6")],
            update_sources=[{"name": "os", "ok": True}, {"name": "winget", "ok": True}])
    # Second poll: winget failed (service hiccup), OS is fine and now clean.
    _report(client, host, secret,
            [],
            update_sources=[{"name": "os", "ok": True},
                            {"name": "winget", "ok": False, "error": "winget exited 1"}])

    rows = _rows(db, host)
    # OS row is gone (assessed clean), the winget finding is kept -- we
    # could not re-check winget, so its last known list stands.
    assert ("kernel", "os") not in rows
    assert ("Notepad++", "winget") in rows


def test_a_source_not_reported_is_left_untouched(client, db, logged_in):
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret,
            [_u("Zoom", "winget", current="5.0", new="5.1")],
            update_sources=[{"name": "winget", "ok": True}])
    # A later report that only mentions the OS source must not disturb the
    # winget rows -- winget simply was not part of this report.
    _report(client, host, secret,
            [_u("kernel", "os")],
            update_sources=[{"name": "os", "ok": True}])

    rows = _rows(db, host)
    assert ("Zoom", "winget") in rows and ("kernel", "os") in rows


def test_a_legacy_agent_report_is_treated_as_the_os_source(client, db, logged_in):
    logged_in("operator")
    host, secret = make_host(db)
    # No update_sources at all -- an agent from before third-party support.
    _report(client, host, secret, [_u("openssl", "os", severity="important", is_security=True)])
    rows = _rows(db, host)
    assert rows[("openssl", "os")].severity == "important"
    db.refresh(host)
    assert host.updates_assessed_ok is True


def test_a_new_third_party_critical_is_announced(client, db, logged_in):
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret,
            [_u("7-Zip", "winget", current="21.0", new="23.0", severity="critical", is_security=True)],
            update_sources=[{"name": "winget", "ok": True}])
    row = db.query(models.AuditLog).filter(
        models.AuditLog.action == "critical_update_found").order_by(models.AuditLog.id.desc()).first()
    assert row is not None and "7-Zip" in row.detail
