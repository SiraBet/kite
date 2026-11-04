"""
Installed software from agents: the full list only when it
changed, a hash otherwise, and a resend request when the hash isn't the
one stored.
"""
from app import models
from conftest import make_host

H = "a" * 64
H2 = "b" * 64


def _inv(client, host, secret, software):
    return client.post(f"/agent/{host.id}/inventory", json={"runtime": "", "containers": [], "software": software},
                       headers={"Authorization": f"Bearer {secret}"})


ITEMS = [
    {"kind": "deb", "name": "openssl", "version": "3.0.13-0ubuntu3.4", "arch": "amd64",
     "source_name": "openssl", "source_version": "3.0.13-0ubuntu3.4"},
    {"kind": "deb", "name": "libssl3t64", "version": "3.0.13-0ubuntu3.4", "arch": "amd64",
     "source_name": "openssl", "source_version": "3.0.13-0ubuntu3.4"},
    {"kind": "snap", "name": "lxd", "version": "5.21.2"},
    {"kind": "os", "name": "ubuntu", "version": "24.04"},
]


def test_a_full_list_is_stored_and_replaced(client, logged_in, db):
    host, secret = make_host(db)
    r = _inv(client, host, secret, {"hash": H, "items": ITEMS})
    assert r.status_code == 200 and r.json()["software_resend"] is False
    logged_in("viewer")
    got = client.get(f"/hosts/{host.id}/software").json()
    assert got["reported_at"] and len(got["items"]) == 4
    assert {i["name"] for i in got["items"] if i["source_name"] == "openssl"} == {"openssl", "libssl3t64"}
    _inv(client, host, secret, {"hash": H2, "items": ITEMS[:1]})
    assert len(client.get(f"/hosts/{host.id}/software").json()["items"]) == 1


def test_an_unchanged_list_is_just_a_hash(client, db):
    host, secret = make_host(db)
    _inv(client, host, secret, {"hash": H, "items": ITEMS})
    r = _inv(client, host, secret, {"hash": H})
    assert r.json()["software_resend"] is False
    assert db.query(models.HostSoftware).filter_by(host_id=host.id).count() == 4


def test_a_hash_the_controller_doesnt_hold_asks_for_the_list(client, db):
    host, secret = make_host(db)
    assert _inv(client, host, secret, {"hash": H}).json()["software_resend"] is True


def test_bad_items_are_dropped_not_the_report(client, db):
    host, secret = make_host(db)
    bad = ITEMS + [{"kind": "nonsense", "name": "x"}, {"kind": "rpm", "name": ""}, {"kind": "app", "name": "y" * 500}]
    assert _inv(client, host, secret, {"hash": H, "items": bad}).status_code == 200
    assert db.query(models.HostSoftware).filter_by(host_id=host.id).count() == 4


def test_older_agents_leave_it_alone_and_deleting_the_host_clears_it(client, logged_in, db):
    host, secret = make_host(db)
    _inv(client, host, secret, {"hash": H, "items": ITEMS})
    client.post(f"/agent/{host.id}/inventory", json={"runtime": "", "containers": []},
                headers={"Authorization": f"Bearer {secret}"})
    assert db.query(models.HostSoftware).filter_by(host_id=host.id).count() == 4
    logged_in("admin")
    assert client.delete(f"/hosts/{host.id}").status_code == 200
    assert db.query(models.HostSoftware).filter_by(host_id=host.id).count() == 0
