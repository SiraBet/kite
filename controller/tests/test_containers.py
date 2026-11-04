"""
Container inventory: what agents report, how it is stored, and how it
aggregates onto the dashboard.

The tri-state `update_available` is the thing most worth pinning. True
means the tag demonstrably moved upstream; False means it demonstrably
did not; None means the comparison could not be made (private registry,
no network, locally built image). None must never be presented as, or
counted as, "up to date".
"""
from app import models
from conftest import make_host


def _report(client, host, secret, containers, runtime="docker"):
    return client.post(
        f"/agent/{host.id}/inventory",
        json={"runtime": runtime, "containers": containers},
        headers={"Authorization": f"Bearer {secret}"},
    )


def _container(name, **overrides):
    base = {
        "container_id": "abc123def456", "name": name, "image": f"{name}:latest",
        "image_digest": "", "state": "running", "managed_by": "standalone",
        "compose_project": "", "pinned": False, "update_available": None,
    }
    base.update(overrides)
    return base


def _clear(db):
    db.query(models.Container).delete()
    db.commit()


def test_inventory_requires_the_hosts_own_credential(client, db):
    host, _ = make_host(db)
    assert client.post(f"/agent/{host.id}/inventory",
                       json={"runtime": "docker", "containers": []}).status_code == 401

    _, other_secret = make_host(db)
    resp = _report(client, host, other_secret, [])
    assert resp.status_code == 401, "one host's credential must not write another's inventory"


def test_reported_containers_are_stored(client, db):
    _clear(db)
    host, secret = make_host(db)
    resp = _report(client, host, secret, [
        _container("web", managed_by="compose", compose_project="shop", update_available=True),
        _container("db", pinned=True, image="postgres@sha256:aaa", update_available=False),
    ])
    assert resp.status_code == 200 and resp.json()["stored"] == 2

    rows = {c.name: c for c in db.query(models.Container).filter(models.Container.host_id == host.id)}
    assert rows["web"].managed_by == "compose" and rows["web"].compose_project == "shop"
    assert rows["web"].update_available is True
    assert rows["db"].pinned is True and rows["db"].update_available is False
    db.refresh(host)
    assert host.container_runtime == "docker"


def test_a_later_report_replaces_rather_than_accumulates(client, db):
    """
    An agent sends its complete current set, so a container missing from
    a later report is genuinely gone and must stop being displayed.
    """
    _clear(db)
    host, secret = make_host(db)
    _report(client, host, secret, [_container("old-one"), _container("survivor")])
    _report(client, host, secret, [_container("survivor")])

    names = [c.name for c in db.query(models.Container).filter(models.Container.host_id == host.id)]
    assert names == ["survivor"]


def test_a_host_with_no_runtime_clears_its_inventory(client, db):
    _clear(db)
    host, secret = make_host(db)
    _report(client, host, secret, [_container("gone-tomorrow")])
    _report(client, host, secret, [], runtime="")

    assert db.query(models.Container).filter(models.Container.host_id == host.id).count() == 0
    db.refresh(host)
    assert host.container_runtime == ""


def test_undetermined_is_not_counted_as_up_to_date(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [
        _container("drifted", update_available=True),
        _container("current", update_available=False),
        _container("unreachable-registry", update_available=None),
        _container("frozen", pinned=True, update_available=False),
    ])

    summary = client.get("/dashboard").json()["containers"]
    assert summary["total"] == 4
    assert summary["outdated"] == 1
    assert summary["unknown"] == 1      # counted on its own, not folded into either answer
    assert summary["pinned"] == 1
    assert summary["hosts_with_containers"] == 1


def test_pinned_images_are_never_counted_as_unknown(client, db, logged_in):
    """A digest-pinned image cannot drift, so an undetermined comparison
    on one is not a gap in our knowledge — it's a non-question."""
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [_container("frozen", pinned=True, update_available=None)])

    summary = client.get("/dashboard").json()["containers"]
    assert summary["unknown"] == 0
    assert summary["pinned"] == 1


def test_worst_hosts_ranks_by_outdated_count(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    busy, busy_secret = make_host(db, hostname="busy-host")
    quiet, quiet_secret = make_host(db, hostname="quiet-host")
    _report(client, busy, busy_secret, [_container(f"c{i}", update_available=True) for i in range(3)])
    _report(client, quiet, quiet_secret, [_container("c0", update_available=True)])

    worst = client.get("/dashboard").json()["containers"]["worst_hosts"]
    assert [w["hostname"] for w in worst] == ["busy-host", "quiet-host"]
    assert worst[0]["outdated"] == 3


def test_host_container_listing_puts_problems_first(client, db, logged_in):
    _clear(db)
    logged_in("operator")
    host, secret = make_host(db)
    _report(client, host, secret, [
        _container("zeta-current", update_available=False),
        _container("alpha-unknown", update_available=None),
        _container("mid-outdated", update_available=True),
    ])

    names = [c["name"] for c in client.get(f"/hosts/{host.id}/containers").json()]
    assert names == ["mid-outdated", "alpha-unknown", "zeta-current"]


def test_container_listing_404s_for_an_unknown_host(client, db, logged_in):
    logged_in("operator")
    assert client.get("/hosts/999999/containers").status_code == 404


def test_deleting_a_host_removes_its_container_rows(client, db, logged_in):
    """SQLite has foreign keys off, so nothing cascades on its own."""
    _clear(db)
    logged_in("admin")
    host, secret = make_host(db)
    _report(client, host, secret, [_container("doomed")])

    assert client.delete(f"/hosts/{host.id}").status_code == 200
    assert db.query(models.Container).filter(models.Container.host_id == host.id).count() == 0
