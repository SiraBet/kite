"""
Patching several machines together (app/batches.py, routers/batches.py):
one at a time or in parallel, chosen by the person starting it.
Runs are driven by reporting their agent stages done, as in
test_job_engine.py; snapshots off and soak instant.
"""
from unittest.mock import patch

import pytest

from app import jobs_engine, models
from conftest import make_host

CHECKLIST = [{"item_index": 0, "item_text": "ok"}]


@pytest.fixture(autouse=True)
def _fast(db):
    from app.settings_store import set_setting
    set_setting(db, "require_ticket", "false")
    with patch("app.jobs_engine.settings") as s:
        s.soak_seconds = 0
        yield


def _hosts(db, n):
    out = []
    for _ in range(n):
        h, _ = make_host(db)
        h.rollback_backend = "none"
        out.append(h)
    db.commit()
    return out


def _start(client, hosts, rollout, **kw):
    return client.post("/batches", json=dict({"host_ids": [h.id for h in hosts], "rollout": rollout,
                                              "checklist": CHECKLIST}, **kw))


def _job(db, host):
    db.expire_all()
    return db.query(models.Job).filter(models.Job.host_id == host.id).order_by(models.Job.id.desc()).first()


def _finish(db, host, ok=True):
    """Report each agent stage of the host's current run; fail the first one when ok=False."""
    job = _job(db, host)
    for stage in sorted(job.stages, key=lambda s: s.stage_index):
        db.refresh(job)
        if job.status in ("done", "failed", "cancelled"):
            break
        if stage.executor == "agent" and stage.status == "running":
            job = jobs_engine.report_agent_stage(db, job, stage.name, "done" if ok else "failed", "")
            if not ok:
                break
    db.refresh(job)
    return job


def _view(client, batch_id):
    return client.get(f"/batches/{batch_id}").json()


def test_the_rollout_must_be_chosen(client, logged_in, db):
    logged_in("operator")
    a, b = _hosts(db, 2)
    assert client.post("/batches", json={"host_ids": [a.id, b.id], "checklist": CHECKLIST}).status_code == 422
    assert _start(client, [a, b], "sometime").status_code == 400
    assert _start(client, [a], "parallel").status_code == 400            # one machine isn't a batch


def test_viewers_cannot_start_a_batch(client, logged_in, db):
    logged_in("viewer")
    assert _start(client, _hosts(db, 2), "parallel").status_code == 403


def test_parallel_starts_every_machine_at_once(client, logged_in, db):
    logged_in("operator")
    hosts = _hosts(db, 3)
    batch = _start(client, hosts, "parallel").json()
    assert [h["state"] for h in batch["hosts"]] == ["running"] * 3
    _finish(db, hosts[0])
    _finish(db, hosts[1], ok=False)                                      # a failure doesn't stop the others
    assert _view(client, batch["id"])["status"] == "running"
    _finish(db, hosts[2])
    v = _view(client, batch["id"])
    assert v["status"] == "done" and v["counts"]["done"] == 2 and v["counts"]["failed"] == 1


def test_one_at_a_time_starts_the_next_only_when_the_previous_succeeds(client, logged_in, db):
    logged_in("operator")
    hosts = _hosts(db, 3)
    batch = _start(client, hosts, "one_at_a_time").json()
    assert [h["state"] for h in batch["hosts"]] == ["running", "waiting", "waiting"]
    _finish(db, hosts[0])
    assert [h["state"] for h in _view(client, batch["id"])["hosts"]] == ["done", "running", "waiting"]
    _finish(db, hosts[1])
    _finish(db, hosts[2])
    v = _view(client, batch["id"])
    assert v["status"] == "done" and v["counts"]["done"] == 3


def test_one_at_a_time_pauses_on_a_failure_until_someone_decides(client, logged_in, db):
    logged_in("operator")
    hosts = _hosts(db, 3)
    batch = _start(client, hosts, "one_at_a_time").json()
    _finish(db, hosts[0], ok=False)
    v = _view(client, batch["id"])
    assert v["status"] == "paused" and "failed" in v["paused_reason"]
    assert [h["state"] for h in v["hosts"]] == ["failed", "waiting", "waiting"]
    v = client.post(f"/batches/{batch['id']}/continue").json()
    assert v["status"] == "running" and v["hosts"][1]["state"] == "running"
    v = client.post(f"/batches/{batch['id']}/stop").json()
    assert v["status"] == "stopped"
    _finish(db, hosts[1])                                                # the one going finishes...
    v = _view(client, batch["id"])
    assert v["hosts"][2]["state"] == "not started" and v["status"] == "stopped"   # ...and nothing more starts


def test_a_machine_that_cant_start_on_its_turn_is_skipped(client, logged_in, db):
    logged_in("operator")
    hosts = _hosts(db, 3)
    batch = _start(client, hosts, "one_at_a_time").json()
    # meanwhile someone starts a run on the third machine by hand
    client.post("/runs", json={"host_id": hosts[2].id, "checklist": CHECKLIST})
    _finish(db, hosts[0])
    _finish(db, hosts[1])
    v = _view(client, batch["id"])
    assert v["hosts"][2]["state"] == "skipped" and "already has an active run" in v["hosts"][2]["skipped"]
    assert v["status"] == "done"


def test_every_machine_is_checked_before_anything_starts(client, logged_in, db):
    logged_in("operator")
    a, b = _hosts(db, 2)
    client.post("/runs", json={"host_id": b.id, "checklist": CHECKLIST})
    r = _start(client, [a, b], "parallel")
    assert r.status_code == 409 and "already has an active run" in r.text
    assert db.query(models.Job).filter(models.Job.host_id == a.id).count() == 0   # nothing started


def test_each_machine_gets_its_own_ordinary_run(client, logged_in, db):
    logged_in("operator")
    hosts = _hosts(db, 2)
    batch = _start(client, hosts, "parallel", severity_filter="security").json()
    for h in hosts:
        job = _job(db, h)
        assert job.batch_id == batch["id"] and job.severity_filter == "security"
        assert job.operator  # the person who started the batch
        assert db.query(models.ChecklistConfirmation).filter_by(job_id=job.id).count() == 1
