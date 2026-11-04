"""
Machine groups (app/groups.py, routers/groups.py): created on their own,
renamed, deleted; machines in several; group scripts winning over the
OS family's stage by stage, never two for one stage; and update rules
applying to every machine or to OS families, groups and machines.
"""
import io

import pytest

from app import groups, models
from conftest import make_host


@pytest.fixture
def clean(db):
    yield
    db.query(models.MachineGroupMember).delete()
    db.query(models.MachineGroup).delete()
    db.query(models.PatchDefTarget).delete()
    db.query(models.PatchDef).delete()
    db.query(models.OsScript).filter(models.OsScript.os_family.like("gt-%")).delete(synchronize_session=False)
    db.query(models.OsScriptHistory).filter(models.OsScriptHistory.os_family.like("gt-%")).delete(synchronize_session=False)
    db.commit()


def _script(db, owner, stage, content):
    db.add(models.OsScript(os_family=owner, stage_name=stage, filename=f"{stage}.sh", content=content))
    db.commit()


def _upload(client, owner, stage, text="echo hi"):
    return client.post(f"/os-scripts/{owner}/{stage}/upload", files={"file": ("s.sh", io.BytesIO(text.encode()))})


def test_a_group_lives_on_its_own(client, logged_in, db, clean):
    a, _ = make_host(db, os_family="gt-os")
    logged_in("operator")
    assert client.post("/groups", json={"name": "gt-dbs"}).status_code == 403
    logged_in("admin")
    g = client.post("/groups", json={"name": "gt-dbs", "description": "database servers"}).json()
    assert g["host_ids"] == [] and g["description"] == "database servers"     # no script needed
    assert client.post("/groups", json={"name": "gt-dbs"}).status_code == 400  # taken
    assert client.post("/groups", json={"name": "gt-os"}).status_code == 400   # an OS family's name
    assert client.post("/groups", json={"name": "bad/name"}).status_code == 400

    assert _upload(client, "gt-dbs", "patch").status_code == 200
    client.post(f"/groups/{g['id']}/members", json={"host_ids": [a.id]})
    # its only script removed: the group stays, with its machines
    assert client.delete("/os-scripts/gt-dbs/patch").status_code == 200
    assert [x["host_ids"] for x in client.get("/groups").json() if x["id"] == g["id"]] == [[a.id]]

    # renamed: its scripts and their history follow it
    _upload(client, "gt-dbs", "preflight")
    r = client.patch(f"/groups/{g['id']}", json={"name": "gt-databases"})
    assert r.status_code == 200 and r.json()["name"] == "gt-databases"
    assert [s["os_family"] for s in client.get(f"/os-scripts/host/{a.id}").json()] == ["gt-databases"]
    assert client.get("/os-scripts/gt-databases/patch/history").json()

    # deleted: machines stay, scripts go to history
    assert client.delete(f"/groups/{g['id']}").status_code == 200
    assert client.get(f"/os-scripts/host/{a.id}").json() == []
    notes = [h["note"] for h in client.get("/os-scripts/gt-databases/preflight/history").json()]
    assert "deleted with its group" in notes
    db.refresh(a)
    assert a.group_ids == []


def test_group_scripts_win_stage_by_stage_and_never_twice(client, logged_in, db, clean):
    a, _ = make_host(db, os_family="gt-os")
    w, _ = make_host(db, os_family="windows")
    _script(db, "gt-os", "patch", "family patch")
    _script(db, "gt-os", "preflight", "family preflight")
    logged_in("admin")
    g1 = client.post("/groups", json={"name": "gt-one", "host_ids": [a.id]}).json()
    g2 = client.post("/groups", json={"name": "gt-two"}).json()
    assert _upload(client, "gt-one", "patch", "group patch").status_code == 200
    db.expire_all()
    assert groups.script_for(db, a, "patch").content == "group patch"
    assert groups.script_for(db, a, "preflight").content == "family preflight"
    assert groups.script_for(db, a, "excludes") is None

    # a second group without scripts: fine, several groups per machine
    assert client.post(f"/groups/{g2['id']}/members", json={"host_ids": [a.id]}).status_code == 200
    # ...but not a second patch script for the same machine
    r = _upload(client, "gt-two", "patch")
    assert r.status_code == 400 and "also in gt-one" in r.json()["detail"]
    assert _upload(client, "gt-two", "preflight").status_code == 200       # another stage is fine
    # and a group with Linux scripts takes no Windows machine
    r = client.post(f"/groups/{g1['id']}/members", json={"host_ids": [w.id]})
    assert r.status_code == 400 and "Windows" in r.json()["detail"]
    assert client.post(f"/groups/{g1['id']}/members", json={"host_ids": [999999]}).status_code == 404
    client.post(f"/groups/{g2['id']}/members/remove", json={"host_ids": [a.id]})
    db.expire_all()
    assert a.group_ids == [g1["id"]]
    assert {e.action for e in db.query(models.AuditLog).filter(models.AuditLog.action.like("group_%"))} >= {
        "group_created", "group_members_added", "group_members_removed"}


def test_the_agent_is_sent_its_groups_script(db, clean):
    from app.routers.agent import _find_ready_instruction

    host, _ = make_host(db, os_family="gt-run-os")
    host.groups = [models.MachineGroup(name="gt-run")]
    _script(db, "gt-run-os", "patch", "family patch")
    _script(db, "gt-run", "patch", "group patch")
    rule = models.PatchDef(pkg_pattern="gt-pkg", mode="skip", reason="r",
                           targets=[models.PatchDefTarget(kind="group", value=str(host.groups[0].id))])
    db.add(rule)
    job = models.Job(host_id=host.id, ticket_id="CHG-1", status="running", current_stage_index=0)
    db.add(job)
    db.flush()
    db.add(models.JobStage(job_id=job.id, stage_index=0, name="patch", executor="agent", status="running"))
    db.commit()
    try:
        got = _find_ready_instruction(db, host)
        assert got.custom_script == "group patch"
        assert "gt-pkg" in [d["pkg_pattern"] for d in got.excludes]
    finally:
        job.status = "done"
        db.commit()


def test_rules_apply_to_every_machine_or_their_targets(client, logged_in, db, clean):
    a, _ = make_host(db, os_family="gt-os")
    b, _ = make_host(db, os_family="gt-other")
    c, _ = make_host(db, os_family="gt-other")
    logged_in("admin")
    g = client.post("/groups", json={"name": "gt-pilot", "host_ids": [b.id]}).json()

    def add(pkg, targets=None, **kw):
        r = client.post("/defs", json=dict({"pkg_pattern": pkg, "mode": "skip", "reason": "test",
                                            "targets": targets or []}, **kw))
        assert r.status_code == 200, r.text
        return r.json()

    add("gt-everyone")
    add("gt-os-rule", [{"kind": "os", "value": "gt-os"}])
    add("gt-legacy", os_family="gt-other")                          # the older field still works
    grp = add("gt-group-rule", [{"kind": "group", "value": str(g["id"])}])
    add("gt-mixed", [{"kind": "host", "value": str(c.id)}, {"kind": "os", "value": "gt-os"}])
    assert client.post("/defs", json={"pkg_pattern": "x", "mode": "skip", "reason": "r",
                                      "targets": [{"kind": "group", "value": "999999"}]}).status_code == 400
    db.expire_all()
    names = lambda h: sorted(r.pkg_pattern for r in groups.rules_for(db, h))  # noqa: E731
    assert names(a) == ["gt-everyone", "gt-mixed", "gt-os-rule"]
    assert names(b) == ["gt-everyone", "gt-group-rule", "gt-legacy"]
    assert names(c) == ["gt-everyone", "gt-legacy", "gt-mixed"]

    # what a rule applies to can be changed, and is in its history
    r = client.put(f"/defs/{grp['id']}/targets", json={"targets": [{"kind": "host", "value": str(a.id)}]})
    assert r.status_code == 200 and r.json()["targets"] == [{"kind": "host", "value": str(a.id)}]
    hist = client.get(f"/defs/{grp['id']}/history").json()
    assert "applies to machine" in hist[0]["change"] and "was group gt-pilot" in hist[0]["change"]
    db.expire_all()
    assert "gt-group-rule" in names(a) and "gt-group-rule" not in names(b)

    # a group a rule names can't be deleted from under it
    client.put(f"/defs/{grp['id']}/targets", json={"targets": [{"kind": "group", "value": str(g["id"])}]})
    r = client.delete(f"/groups/{g['id']}")
    assert r.status_code == 400 and "gt-group-rule" in r.json()["detail"]


def test_audit_lines_name_at_most_ten_machines():
    from app import audit

    assert audit.names(["a", "b"]) == "a, b"
    assert audit.names([f"m{i}" for i in range(25)]) == "m0, m1, m2, m3, m4, m5, m6, m7, m8, m9 and 15 more"
