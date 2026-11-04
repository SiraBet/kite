from app import models, jobs_engine
from conftest import make_host


def _start_job_at_preflight(db, host):
    """Builds a job and advances it to the first agent stage (preflight)
    -- doesn't touch the snapshot stage at all, so no Proxmox mocking
    needed, same trick test_job_engine.py's simpler tests use."""
    job = models.Job(host_id=host.id, ticket_id="TEST-1", operator="tester", operator_role="admin")
    db.add(job)
    db.commit()
    db.refresh(job)
    for i, (name, executor) in enumerate(models.STAGE_SEQUENCE):
        db.add(models.JobStage(job_id=job.id, stage_index=i, name=name, executor=executor))
    db.commit()
    db.refresh(job)
    return jobs_engine.advance_job(db, job)


def test_add_def_defaults_to_all_os_families(client, logged_in):
    logged_in(role="admin", username="defs-admin-1")
    resp = client.post("/defs", json={"pkg_pattern": "fluent-bit", "mode": "skip", "reason": "known bug"})
    assert resp.status_code == 200
    assert resp.json()["targets"] == []                              # every machine


def test_add_def_can_be_scoped_to_one_os_family(client, logged_in):
    logged_in(role="admin", username="defs-admin-2")
    resp = client.post("/defs", json={"pkg_pattern": "fluent-bit", "mode": "skip",
                                       "reason": "rocky8-specific bug", "os_family": "rocky8"})
    assert resp.status_code == 200
    assert resp.json()["targets"] == [{"kind": "os", "value": "rocky8"}]


def test_scoped_def_only_reaches_matching_os_family(client, logged_in, db):
    logged_in(role="admin", username="defs-admin-3")
    client.post("/defs", json={"pkg_pattern": "rocky-only-pkg", "mode": "skip",
                                "reason": "scoped", "os_family": "rocky8"})
    client.post("/defs", json={"pkg_pattern": "ubuntu-only-pkg", "mode": "skip",
                                "reason": "scoped", "os_family": "ubuntu22"})
    client.post("/defs", json={"pkg_pattern": "global-pkg", "mode": "skip", "reason": "applies everywhere"})

    rocky_host, rocky_secret = make_host(db, os_family="rocky8")
    _start_job_at_preflight(db, rocky_host)

    resp = client.get(f"/agent/{rocky_host.id}/jobs/next", headers={"Authorization": f"Bearer {rocky_secret}"})
    assert resp.status_code == 200
    patterns = {e["pkg_pattern"] for e in resp.json()["excludes"]}
    assert "rocky-only-pkg" in patterns
    assert "global-pkg" in patterns
    assert "ubuntu-only-pkg" not in patterns


def test_unscoped_def_reaches_every_os_family(client, logged_in, db):
    logged_in(role="admin", username="defs-admin-4")
    client.post("/defs", json={"pkg_pattern": "everywhere-pkg", "mode": "skip", "reason": "no scope set"})

    ubuntu_host, ubuntu_secret = make_host(db, os_family="ubuntu22")
    _start_job_at_preflight(db, ubuntu_host)

    resp = client.get(f"/agent/{ubuntu_host.id}/jobs/next", headers={"Authorization": f"Bearer {ubuntu_secret}"})
    assert resp.status_code == 200
    patterns = {e["pkg_pattern"] for e in resp.json()["excludes"]}
    assert "everywhere-pkg" in patterns
