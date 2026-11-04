"""
Cleaning up kite's Proxmox snapshots (app/snapshot_retention.py,
routers/snapshots.py). Proxmox is mocked at its client calls.
"""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from app import models, snapshot_retention
from conftest import make_host

NOW = datetime(2026, 10, 20, 12, 0)
POL = {"enabled": True, "keep_count": 2, "keep_days": 7}


def _row(job_id, days_ago, status="done", kept=False):
    return {"name": f"kite-job{job_id}-1", "job_id": job_id, "job_status": status, "kept": kept,
            "taken_at": NOW - timedelta(days=days_ago)}


def _plan(rows, pol=POL):
    return {r["job_id"]: (r["remove"], r["reason"]) for r in snapshot_retention.decide(rows, pol, NOW)}


# ---------- the rule ----------

def test_keeps_the_newest_two_and_nothing_past_a_week():
    plan = _plan([_row(1, 1), _row(2, 2), _row(3, 3), _row(4, 10)])
    assert [j for j, (rm, _) in plan.items() if not rm] == [1, 2]
    assert plan[3] == (True, "more than 2 newer ones")
    assert plan[4][0] is True


def test_age_alone_removes_even_the_newest():
    plan = _plan([_row(1, 9)])
    assert plan[1] == (True, "older than 7 days")


def test_failed_stopped_running_and_kept_are_never_removed_nor_counted():
    plan = _plan([_row(1, 1, "failed"), _row(2, 2, "running"), _row(3, 30, "cancelled"),
                  _row(4, 40, kept=True), _row(5, 3), _row(6, 4)])
    assert all(not plan[j][0] for j in (1, 2, 3, 4))
    assert "way back" in plan[1][1] and plan[4][1] == "marked Keep"
    assert not plan[5][0] and not plan[6][0]      # the two newest clean ones, protected ones don't use up the count


def test_zero_means_no_limit_and_off_means_keep_everything():
    assert not any(rm for rm, _ in _plan([_row(i, i) for i in range(1, 6)], dict(POL, keep_count=0, keep_days=0)).values())
    assert not any(rm for rm, _ in _plan([_row(1, 99)], dict(POL, enabled=False)).values())


# ---------- against Proxmox ----------

@pytest.fixture
def vm(db):
    host, _ = make_host(db)
    host.proxmox_vmid, host.proxmox_node = 4321, "pve"
    jobs = [models.Job(host_id=host.id, ticket_id="T", status=s) for s in ("done", "done", "done", "failed")]
    db.add_all(jobs)
    db.commit()
    epoch = lambda d: int((datetime.utcnow() - timedelta(days=d)).timestamp())  # noqa: E731
    snaps = [{"name": f"kite-job{j.id}-1", "snaptime": epoch(d)} for j, d in zip(jobs, (1, 2, 3, 4))]
    snaps += [{"name": "before-upgrade", "snaptime": epoch(50)}, {"name": "current"}]
    cfg = object()
    with patch("app.snapshot_retention.host_vm", return_value=(cfg, "pve")), \
         patch("app.proxmox.list_snapshots", return_value=[s for s in snaps if s["name"] != "current"]), \
         patch("app.proxmox.delete_snapshot") as deleted:
        yield {"host": host, "jobs": jobs, "deleted": deleted}
    db.query(models.Setting).filter(models.Setting.key.like("snapshot_%")).delete(synchronize_session=False)
    db.commit()


def test_cleanup_removes_only_its_own_extra_snapshots(db, vm):
    removed = snapshot_retention.clean_host(db, vm["host"])
    assert removed == [f"kite-job{vm['jobs'][2].id}-1"]            # third-newest clean one
    assert vm["deleted"].call_args.args[2] == removed[0]
    assert db.query(models.AuditLog).filter_by(action="snapshot_deleted").count() >= 1


def test_settings_change_the_rule(client, logged_in, db, vm):
    logged_in("admin")
    assert client.put("/settings/snapshot_keep_count", json={"value": "x"}).status_code == 400
    assert client.put("/settings/snapshot_keep_count", json={"value": "3"}).status_code == 200
    assert snapshot_retention.clean_host(db, vm["host"]) == []
    assert client.put("/settings/snapshot_cleanup", json={"value": "false"}).status_code == 200
    assert snapshot_retention.policy(db)["enabled"] is False


def test_the_machine_page_lists_keeps_and_removes(client, logged_in, db, vm):
    logged_in("operator")
    listed = client.get(f"/hosts/{vm['host'].id}/snapshots").json()
    assert [s["name"] for s in listed["snapshots"]] == [f"kite-job{j.id}-1" for j in vm["jobs"]]   # not before-upgrade
    third = f"kite-job{vm['jobs'][2].id}-1"
    assert client.post(f"/hosts/{vm['host'].id}/snapshots/{third}/keep", json={"keep": True}).status_code == 403
    logged_in("lead")
    assert client.post(f"/hosts/{vm['host'].id}/snapshots/{third}/keep", json={"keep": True}).status_code == 200
    assert snapshot_retention.clean_host(db, vm["host"]) == []          # kept now
    assert client.delete(f"/hosts/{vm['host'].id}/snapshots/before-upgrade").status_code == 400   # not ours
    assert client.delete(f"/hosts/{vm['host'].id}/snapshots/{third}").status_code == 200


def test_a_successful_run_triggers_cleanup_and_a_failed_one_does_not(db):
    from app import jobs_engine
    host, _ = make_host(db)
    other, _ = make_host(db)      # one active run per machine
    host.proxmox_vmid = other.proxmox_vmid = 99
    ok = models.Job(host_id=host.id, ticket_id="T", status="running")
    bad = models.Job(host_id=other.id, ticket_id="T", status="running")
    db.add_all([ok, bad])
    db.commit()
    db.add(models.JobStage(job_id=bad.id, name="patch", stage_index=0, executor="agent", status="failed"))
    db.commit()
    with patch("app.snapshot_retention.clean_after_run") as after:
        jobs_engine.advance_job(db, ok)       # no stages left: the run is done
        jobs_engine.advance_job(db, bad)
    assert ok.status == "done" and bad.status == "failed"
    after.assert_called_once_with(host.id)


# ---------- restoring a snapshot ----------

@pytest.fixture
def restorable(vm):
    with patch("app.proxmox.vm_status", return_value="running") as status, \
         patch("app.proxmox.rollback_snapshot", return_value="UPID:rollback") as rolled, \
         patch("app.proxmox.start_vm", return_value="UPID:start") as started, \
         patch("app.proxmox.wait_for_task", return_value=True) as waited:
        yield dict(vm, rolled=rolled, started=started, waited=waited, status=status)


def test_restoring_a_snapshot_is_admin_only_and_typed(client, logged_in, db, restorable):
    host, snap = restorable["host"], f"kite-job{restorable['jobs'][0].id}-1"
    url = f"/hosts/{host.id}/snapshots/{snap}/restore"
    logged_in("lead")
    assert client.post(url, json={"confirm": host.hostname}).status_code == 403
    logged_in("admin")
    r = client.post(url, json={"confirm": "wrong"})
    assert r.status_code == 400 and host.hostname in r.json()["detail"]
    assert client.post(f"/hosts/{host.id}/snapshots/before-upgrade/restore", json={"confirm": host.hostname}).status_code == 400
    r = client.post(f"/hosts/{host.id}/snapshots/kite-job999999-1/restore", json={"confirm": host.hostname})
    assert r.status_code == 409 and "isn't from a run recorded" in r.json()["detail"]   # no such run here
    restorable["rolled"].assert_not_called()

    r = client.post(url, json={"confirm": host.hostname})
    assert r.status_code == 200 and r.json() == {"ok": True, "state": "restored", "started": True, "note": ""}
    assert restorable["rolled"].call_args.args[1:] == (4321, snap, "pve")
    restorable["started"].assert_called_once()
    actions = [a for (a,) in db.query(models.AuditLog.action).filter(models.AuditLog.action.like("snapshot_restore%"))]
    assert "snapshot_restore_started" in actions and "snapshot_restored" in actions


def test_a_restore_leaves_a_stopped_vm_off_and_says_when_it_cant_start_one(client, logged_in, db, restorable):
    from app import proxmox

    host, snap = restorable["host"], f"kite-job{restorable['jobs'][0].id}-1"
    url = f"/hosts/{host.id}/snapshots/{snap}/restore"
    logged_in("admin")
    restorable["status"].return_value = "stopped"
    assert client.post(url, json={"confirm": host.hostname}).json()["started"] is False
    restorable["started"].assert_not_called()

    restorable["status"].return_value = "running"
    restorable["started"].side_effect = proxmox.ProxmoxError("Permission check failed (VM.PowerMgmt)")
    r = client.post(url, json={"confirm": host.hostname}).json()
    assert r["state"] == "restored" and r["started"] is False and "VM.PowerMgmt" in r["note"]

    restorable["waited"].return_value = False          # Proxmox still busy at the deadline
    assert client.post(url, json={"confirm": host.hostname}).json()["state"] == "restoring"


def test_no_restore_while_a_run_is_going(client, logged_in, db, restorable):
    host, snap = restorable["host"], f"kite-job{restorable['jobs'][0].id}-1"
    job = models.Job(host_id=host.id, ticket_id="T", status="running")
    db.add(job)
    db.commit()
    try:
        logged_in("admin")
        r = client.post(f"/hosts/{host.id}/snapshots/{snap}/restore", json={"confirm": host.hostname})
        assert r.status_code == 409
        restorable["rolled"].assert_not_called()
    finally:
        job.status = "done"
        db.commit()


def test_waiting_for_a_proxmox_task():
    from app import proxmox

    states = iter([{"status": "running"}, {"status": "stopped", "exitstatus": "OK"}])
    with patch("app.proxmox._task_status", side_effect=lambda *a: next(states)):
        assert proxmox.wait_for_task(proxmox.ProxmoxConfig(host="h"), "pve", "UPID:x", interval=0) is True
    with patch("app.proxmox._task_status", return_value={"status": "stopped", "exitstatus": "rollback failed: disk busy"}):
        with pytest.raises(proxmox.ProxmoxError, match="disk busy"):
            proxmox.wait_for_task(proxmox.ProxmoxConfig(host="h"), "pve", "UPID:x", interval=0)
    with patch("app.proxmox._task_status", return_value={"status": "running"}):
        assert proxmox.wait_for_task(proxmox.ProxmoxConfig(host="h"), "pve", "UPID:x", timeout=0, interval=0) is False


def test_the_machine_says_what_its_safety_net_is(client, logged_in, db):
    from app.settings_store import set_setting

    linked, _ = make_host(db)
    linked.proxmox_vmid = 777
    unlinked, _ = make_host(db)
    dnf, _ = make_host(db)
    dnf.rollback_backend = "dnf_history"
    db.commit()
    logged_in("viewer")
    nets = {h["id"]: h["safety_net"] for h in client.get("/hosts").json()}
    assert nets[linked.id] == "snapshot" and nets[unlinked.id] == "none" and nets[dnf.id] == "package_history"
    assert client.get(f"/hosts/{linked.id}").json()["safety_net"] == "snapshot"
    set_setting(db, "rollback_default_backend", "none")
    try:
        assert client.get(f"/hosts/{linked.id}").json()["safety_net"] == "none"
    finally:
        set_setting(db, "rollback_default_backend", "proxmox")
