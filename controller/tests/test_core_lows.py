"""
Smaller correctness fixes in the run engine and around it: removed
machines' ids and rules, group scripts vs OS families, snapshots from
other runs, the script "tested" flag, the snapshot's place in the
pipeline, and the fleet vulnerabilities page.
"""
from datetime import datetime, timedelta

from app import groups, jobs_engine, models, snapshot_retention
from conftest import make_host


def test_a_new_machine_never_gets_a_removed_ones_id(client, logged_in, db):
    """hosts.id isn't AUTOINCREMENT: the next machine took a removed top machine's id, and with
    it that machine's run history."""
    logged_in("admin")
    top = max(db.query(models.Host.id).all() or [(0,)])[0]
    gone, _ = make_host(db)
    gone_id = gone.id
    db.add(models.Job(host_id=gone_id, hostname=gone.hostname, ticket_id="", status="done"))
    db.commit()
    assert client.delete(f"/hosts/{gone_id}").status_code == 200
    token = client.post("/enroll/tokens", json={"hostname": f"new-{gone_id}"}).json()["token"]
    new_id = client.post("/agent/enroll", json={"token": token, "os_version": "1"}).json()["host_id"]
    assert new_id > gone_id > top


def test_removing_a_machine_takes_its_findings_and_leaves_its_rules_scoped(client, logged_in, db):
    """A rule with no targets applies to every machine: taking a removed machine out of a rule
    that named only it turned a one-machine rule into a fleet-wide one."""
    logged_in("admin")
    host, _ = make_host(db)
    bystander, _ = make_host(db)
    hid = host.id
    rule = client.post("/defs", json={"pkg_pattern": "core-low-pkg", "mode": "skip", "reason": "t",
                                      "targets": [{"kind": "host", "value": str(hid)}]}).json()
    shared = client.post("/defs", json={"pkg_pattern": "core-low-shared", "mode": "skip", "reason": "t",
                                        "targets": [{"kind": "host", "value": str(hid)},
                                                    {"kind": "host", "value": str(bystander.id)}]}).json()
    db.add(models.HostVuln(host_id=hid, cve="CVE-2026-1", package="p", installed="1", fixed="2",
                           severity="low", score="", summary="", url="", advisories="", source="distro"))
    db.commit()
    assert client.delete(f"/hosts/{hid}").status_code == 200
    db.expire_all()
    assert db.query(models.HostVuln).filter_by(host_id=hid).count() == 0
    history = db.query(models.DefHistory).filter_by(def_id=rule["id"]).all()
    assert any("removed from the fleet" in h.change for h in history)

    # Both rules still name the removed machine, so neither reaches further than it did.
    after = {d["id"]: d["targets"] for d in client.get("/defs").json()}
    assert after[rule["id"]] == [{"kind": "host", "value": str(hid)}]
    assert {"kind": "host", "value": str(hid)} in after[shared["id"]]
    applied = sorted(r.pkg_pattern for r in groups.rules_for(db, bystander) if r.pkg_pattern.startswith("core-low-"))
    assert applied == ["core-low-shared"]

    # ...and a machine enrolled later can't take the removed one's id and, with it, the rule.
    token = client.post("/enroll/tokens", json={"hostname": f"after-{hid}"}).json()["token"]
    new_id = client.post("/agent/enroll", json={"token": token, "os_version": "1"}).json()["host_id"]
    assert new_id > hid
    newcomer = db.get(models.Host, new_id)
    assert "core-low-pkg" not in [r.pkg_pattern for r in groups.rules_for(db, newcomer)]

    for created in (rule, shared):
        client.delete(f"/defs/{created['id']}")


def test_a_group_named_like_an_os_family_doesnt_hand_out_its_scripts(db):
    """An agent reports its own os_family; one that matches a group's name ran that group's
    scripts without being in the group."""
    group = models.MachineGroup(name="rocky42")
    db.add(group)
    db.add(models.OsScript(os_family="rocky42", stage_name="patch", content="#!/bin/sh\necho group\n"))
    db.commit()
    outsider, _ = make_host(db, os_family="rocky42")
    member, _ = make_host(db, os_family="rocky9")
    db.add(models.MachineGroupMember(group_id=group.id, host_id=member.id))
    db.commit()
    db.refresh(member)
    try:
        assert groups.script_for(db, outsider, "patch") is None
        assert groups.script_for(db, member, "patch").content.endswith("echo group\n")
    finally:
        db.query(models.MachineGroupMember).filter_by(group_id=group.id).delete()
        db.query(models.OsScript).filter_by(os_family="rocky42").delete()
        db.delete(group)
        db.commit()


def test_a_snapshot_from_no_run_on_this_machine_is_left_alone():
    now = datetime.utcnow()
    rows = snapshot_retention.decide([
        {"name": "kite-job1-1", "job_status": None, "kept": False, "taken_at": now - timedelta(days=90)},
        {"name": "kite-job2-1", "job_status": "done", "kept": False, "taken_at": now - timedelta(days=90)},
    ], {"enabled": True, "keep_count": 0, "keep_days": 30}, now)
    unknown, ours = rows[0], rows[1]
    assert not unknown["remove"] and "not from a run recorded" in unknown["reason"]
    assert ours["remove"]


def test_tested_is_set_only_for_the_script_that_ran(db):
    host, _ = make_host(db, os_family="rocky77")
    script = models.OsScript(os_family="rocky77", stage_name="preflight", content="#!/bin/sh\ntrue\n",
                             uploaded_at=datetime.utcnow())
    db.add(script)
    job = models.Job(host_id=host.id, hostname=host.hostname, ticket_id="", rollback_backend="none")
    db.add(job)
    db.commit()
    for i, (name, ex) in enumerate(models.STAGE_SEQUENCE):
        db.add(models.JobStage(job_id=job.id, stage_index=i, name=name, executor=ex))
    db.commit()
    db.refresh(job)
    try:
        jobs_engine.advance_job(db, job)                     # preflight starts
        script.uploaded_at = datetime.utcnow() + timedelta(seconds=5)   # replaced while it ran
        db.commit()
        jobs_engine.report_agent_stage(db, job, "preflight", "done", "ok")
        db.refresh(script)
        assert script.tested is False
    finally:
        db.delete(script)
        db.commit()


def test_the_snapshot_comes_before_anything_changes():
    """On apt, the excludes stage's pin installs the pinned version: it must come after the snapshot."""
    names = [n for n, _ in models.STAGE_SEQUENCE]
    assert names.index("snapshot") < names.index("excludes") < names.index("patch")
    assert names[0] == "preflight"


def test_fleet_vulnerabilities_are_ranked_and_paged_in_the_database(client, logged_in, db):
    a, _ = make_host(db)
    b, _ = make_host(db)
    rows = [(a, "CVE-2026-9001", "critical", "pkg-a"), (b, "CVE-2026-9001", "important", "pkg-a"),
            (a, "CVE-2026-9002", "moderate", "pkg-b"), (b, "CVE-2026-9003", "critical", "pkg-c")]
    for host, cve, sev, pkg in rows:
        db.add(models.HostVuln(host_id=host.id, cve=cve, package=pkg, installed="1", fixed="2", severity=sev,
                               score="9.0", summary=f"{cve} summary", url="", advisories="", source="distro"))
    db.commit()
    try:
        logged_in("viewer")
        got = client.get("/vulnerabilities?cve=2026-900").json()
        assert [i["cve"] for i in got["items"]] == ["CVE-2026-9001", "CVE-2026-9003", "CVE-2026-9002"]
        first = got["items"][0]
        assert first["severity"] == "critical" and first["host_count"] == 2 and len(first["hosts"]) == 2
        assert first["hosts"][0]["packages"] == [{"name": "pkg-a", "installed": "1", "fixed": "2"}]
        page = client.get("/vulnerabilities?cve=2026-900&limit=1").json()
        assert page["total"] == 3 and [i["cve"] for i in page["items"]] == ["CVE-2026-9001"]
        assert client.get("/vulnerabilities?cve=2026-900&severity=moderate").json()["total"] == 1
    finally:
        db.query(models.HostVuln).filter(models.HostVuln.cve.like("CVE-2026-900%")).delete(synchronize_session=False)
        db.commit()


def test_a_machine_has_at_most_one_active_run(db):
    """Two requests passing the "already active?" check at once could both start a run."""
    import pytest
    from sqlalchemy.exc import IntegrityError
    host, _ = make_host(db)
    db.add(models.Job(host_id=host.id, hostname=host.hostname, ticket_id="", status="running"))
    db.commit()
    db.add(models.Job(host_id=host.id, hostname=host.hostname, ticket_id="", status="queued"))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    db.add(models.Job(host_id=host.id, hostname=host.hostname, ticket_id="", status="done"))   # history is fine
    db.commit()
