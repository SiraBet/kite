"""
Run scope: whether a run patches the guest's OS packages, updates the
containers on it, or both.

The two are independent surfaces — patching the guest leaves a stale
image running, and pulling an image does nothing for the kernel — so
they are selectable separately. The pipeline differs per scope, which is
what most of this file pins.
"""
from app import models
from conftest import make_host


def _container(client, host, secret, name, managed_by="compose", workdir="/srv/app", service=None):
    """Report one container as an agent would."""
    existing = []
    return client.post(
        f"/agent/{host.id}/inventory",
        json={"runtime": "docker", "containers": existing + [{
            "container_id": "abc", "name": name, "image": f"{name}:latest",
            "state": "running", "managed_by": managed_by,
            "compose_project": "app", "compose_service": service or name,
            "compose_working_dir": workdir if managed_by == "compose" else "",
            "pinned": False, "update_available": True,
        }]},
        headers={"Authorization": f"Bearer {secret}"},
    )


def _report_many(client, host, secret, entries):
    return client.post(
        f"/agent/{host.id}/inventory",
        json={"runtime": "docker", "containers": [{
            "container_id": "id" + str(i), "name": e["name"], "image": "img:latest",
            "state": "running", "managed_by": e.get("managed_by", "compose"),
            "compose_project": "app", "compose_service": e.get("service", e["name"]),
            "compose_working_dir": e.get("workdir", "/srv/app") if e.get("managed_by", "compose") == "compose" else "",
            "pinned": False, "update_available": True,
        } for i, e in enumerate(entries)]},
        headers={"Authorization": f"Bearer {secret}"},
    )


def _start(client, host, **kw):
    body = {"host_id": host.id, "checklist": [{"item_index": 0, "item_text": "ok"}]}
    body.update(kw)
    return client.post("/runs", json=body)


def _stage_names(job):
    return [s["name"] for s in job["stages"]]


# ---------- the pipeline per scope ----------

def test_default_scope_is_os_and_pipeline_is_unchanged(client, db, logged_in):
    """Existing behaviour must not shift for anyone who never asks for a
    scope — no container stage, same seven stages as before."""
    logged_in("admin")
    host, _ = make_host(db)
    job = _start(client, host).json()

    assert job["scope"] == "os"
    assert "containers" not in _stage_names(job)
    assert _stage_names(job) == ["preflight", "snapshot", "excludes", "patch",
                                 "reboot", "healthcheck", "soak"]


def test_containers_scope_drops_the_package_stages(client, db, logged_in):
    """
    A containers-only run must not offer excludes/patch/reboot. Nothing
    is being installed, so a reboot stage in particular would be
    meaningless — and a skipped stage reads as a failure.
    """
    logged_in("admin")
    host, secret = make_host(db)
    _container(client, host, secret, "web")

    job = _start(client, host, scope="containers").json()

    assert job["scope"] == "containers"
    assert _stage_names(job) == ["preflight", "snapshot", "containers", "healthcheck", "soak"]


def test_both_scope_runs_containers_after_reboot(client, db, logged_in):
    """Container lifecycle is independent of the guest's, so updating
    images before a reboot would just restart them moments later."""
    logged_in("admin")
    host, secret = make_host(db)
    _container(client, host, secret, "web")

    names = _stage_names(_start(client, host, scope="both").json())

    assert names.index("containers") > names.index("reboot")
    assert names.index("containers") < names.index("healthcheck")


def test_an_unknown_scope_is_rejected(client, db, logged_in):
    logged_in("admin")
    host, _ = make_host(db)
    assert _start(client, host, scope="everything").status_code == 400


# ---------- what may be selected ----------

def test_only_compose_managed_containers_can_be_selected(client, db, logged_in):
    """
    A standalone container's creation flags are recorded nowhere, and an
    orchestrated one belongs to its orchestrator — neither can be
    recreated safely, so neither may be selected.
    """
    logged_in("admin")
    host, secret = make_host(db)
    _report_many(client, host, secret, [
        {"name": "compose-web"},
        {"name": "loose-one", "managed_by": "standalone"},
        {"name": "k8s-pod", "managed_by": "kubernetes"},
    ])

    resp = _start(client, host, scope="containers", containers=["loose-one"])
    assert resp.status_code == 400
    assert "loose-one" in resp.text

    assert _start(client, host, scope="containers", containers=["compose-web"]).status_code == 200


def test_empty_selection_means_every_updatable_container(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    _report_many(client, host, secret, [
        {"name": "api"}, {"name": "worker"}, {"name": "loose", "managed_by": "standalone"},
    ])

    job = _start(client, host, scope="containers").json()

    stored = db.query(models.Job).filter(models.Job.id == job["id"]).one()
    assert sorted(stored.container_selection.splitlines()) == ["api", "worker"]


def test_a_container_run_on_a_host_with_none_is_refused(client, db, logged_in):
    """
    A run whose entire purpose is updating containers must not report
    success having updated nothing.
    """
    logged_in("admin")
    host, secret = make_host(db)
    _report_many(client, host, secret, [{"name": "loose", "managed_by": "standalone"}])

    resp = _start(client, host, scope="containers")
    assert resp.status_code == 409
    assert "no compose-managed containers" in resp.text


def test_selection_is_frozen_at_creation(client, db, logged_in):
    """A container started after the operator confirmed the checklist
    must not be swept into the run."""
    logged_in("admin")
    host, secret = make_host(db)
    _report_many(client, host, secret, [{"name": "api"}])
    created = _start(client, host, scope="containers").json()

    _report_many(client, host, secret, [{"name": "api"}, {"name": "appeared-later"}])

    stored = db.query(models.Job).filter(models.Job.id == created["id"]).one()
    assert stored.container_selection.splitlines() == ["api"]


# ---------- what the agent is told ----------

def test_agent_receives_the_compose_details_for_its_stage(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    host.rollback_backend = "none"   # so the snapshot stage resolves without Proxmox
    db.commit()
    _report_many(client, host, secret, [{"name": "api", "service": "api-svc", "workdir": "/srv/shop"}])
    job = _start(client, host, scope="containers").json()

    hdr = {"Authorization": f"Bearer {secret}"}
    # preflight, then snapshot resolves, leaving the containers stage ready.
    client.post(f"/agent/{host.id}/jobs/{job['id']}/stages/preflight/report",
                json={"status": "done", "output": ""}, headers=hdr)
    instruction = client.get(f"/agent/{host.id}/jobs/next", headers=hdr).json()

    assert instruction["stage_name"] == "containers"
    assert instruction["container_action"] == "update"
    assert instruction["containers"] == [{
        "name": "api", "image": "img:latest", "managed_by": "compose",
        "compose_project": "app", "compose_service": "api-svc",
        "compose_working_dir": "/srv/shop",
    }]


def test_non_container_stages_carry_no_container_payload(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    assert _start(client, host).status_code == 200

    hdr = {"Authorization": f"Bearer {secret}"}
    instruction = client.get(f"/agent/{host.id}/jobs/next", headers=hdr).json()

    assert instruction["stage_name"] == "preflight"
    assert instruction["containers"] == []


# ---------- schedules ----------

def _schedule(client, **kw):
    from datetime import datetime
    now = datetime.utcnow()
    body = {"name": "sched", "team": "", "day_of_week": now.weekday(), "hour": now.hour}
    body.update(kw)
    return client.post("/schedules", json=body)


def test_schedule_carries_a_scope(client, db, logged_in):
    logged_in("admin")
    resp = _schedule(client, name="containers weekly", scope="containers", containers=["api"])
    assert resp.status_code == 200
    assert resp.json()["scope"] == "containers"

    stored = db.query(models.Schedule).filter(models.Schedule.name == "containers weekly").one()
    assert stored.container_selection.splitlines() == ["api"]


def test_schedule_rejects_an_unknown_scope(client, logged_in):
    logged_in("admin")
    assert _schedule(client, name="bad", scope="nonsense").status_code == 400


def test_updating_a_schedules_container_list_is_persisted(client, db, logged_in):
    """`containers` is a list on the wire and a newline-separated column
    in the table — a plain setattr would silently drop it."""
    logged_in("admin")
    sid = _schedule(client, name="editme", scope="containers", containers=["api"]).json()["id"]

    assert client.patch(f"/schedules/{sid}", json={"containers": ["api", "worker"]}).status_code == 200

    db.expire_all()
    stored = db.query(models.Schedule).filter(models.Schedule.id == sid).one()
    assert stored.container_selection.splitlines() == ["api", "worker"]


def test_a_scheduled_container_run_uses_the_container_pipeline(client, db, logged_in):
    from app import scheduler
    logged_in("admin")
    host, secret = make_host(db, hostname="sched-container-host")
    host.team = "sched-team"
    host.rollback_backend = "none"
    db.commit()
    _report_many(client, host, secret, [{"name": "api"}])

    from datetime import datetime
    now = datetime.utcnow()
    db.add(models.Schedule(name="nightly containers", team="sched-team",
                            day_of_week=now.weekday(), hour=now.hour, enabled=True,
                            scope="containers"))
    db.commit()

    scheduler.run_scheduler_pass(db)

    job = (db.query(models.Job)
             .filter(models.Job.host_id == host.id)
             .order_by(models.Job.id.desc()).first())
    assert job is not None and job.scope == "containers"
    assert [s.name for s in sorted(job.stages, key=lambda x: x.stage_index)] == \
        ["preflight", "snapshot", "containers", "healthcheck", "soak"]
    assert job.container_selection.splitlines() == ["api"]


def test_a_container_schedule_skips_a_host_with_nothing_to_update(client, db, logged_in):
    """Better a logged skip than a run that completes having done
    nothing."""
    from app import scheduler
    logged_in("admin")
    host, _ = make_host(db, hostname="no-containers-host")
    host.team = "empty-team"
    db.commit()

    from datetime import datetime
    now = datetime.utcnow()
    db.add(models.Schedule(name="empty containers", team="empty-team",
                            day_of_week=now.weekday(), hour=now.hour, enabled=True,
                            scope="containers"))
    db.commit()

    scheduler.run_scheduler_pass(db)

    assert db.query(models.Job).filter(models.Job.host_id == host.id).count() == 0
    skipped = db.query(models.AuditLog).filter(models.AuditLog.action == "schedule_skipped").all()
    assert any("no compose-managed containers" in a.detail for a in skipped)


# ---------- pre-update capture and rollback ----------
#
# One capture per compose service, replaced by each update rather than
# accumulating. The capture is a tag on the image that was running, which
# is a complete rollback point for a compose service: the compose file
# supplies everything else, and volumes survive recreation.

def _report_with_capture(client, host, secret, name, rollback_available):
    return client.post(
        f"/agent/{host.id}/inventory",
        json={"runtime": "docker", "containers": [{
            "container_id": "abc", "name": name, "image": "img:latest", "state": "running",
            "managed_by": "compose", "compose_project": "app", "compose_service": name,
            "compose_working_dir": "/srv/app", "rollback_available": rollback_available,
            "pinned": False, "update_available": True,
        }]},
        headers={"Authorization": f"Bearer {secret}"},
    )


def test_a_completed_update_records_a_rollback_point(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    host.rollback_backend = "none"
    db.commit()
    _report_many(client, host, secret, [{"name": "api"}])
    job = _start(client, host, scope="containers").json()

    hdr = {"Authorization": f"Bearer {secret}"}
    for stage in ("preflight", "containers"):
        client.post(f"/agent/{host.id}/jobs/{job['id']}/stages/{stage}/report",
                    json={"status": "done", "output": "ok"}, headers=hdr)

    row = db.query(models.Container).filter(models.Container.host_id == host.id).one()
    assert row.rollback_available is True
    assert row.rollback_captured_at is not None


def test_a_rollback_run_does_not_move_the_capture(client, db, logged_in):
    """Restoring must not overwrite the capture with what it just
    replaced, or the next rollback would restore the broken version."""
    logged_in("admin")
    host, secret = make_host(db)
    host.rollback_backend = "none"
    db.commit()
    _report_with_capture(client, host, secret, "api", True)
    row = db.query(models.Container).filter(models.Container.host_id == host.id).one()
    row.rollback_captured_at = None
    db.commit()

    job = _start(client, host, scope="containers", container_action="rollback").json()
    hdr = {"Authorization": f"Bearer {secret}"}
    for stage in ("preflight", "containers"):
        client.post(f"/agent/{host.id}/jobs/{job['id']}/stages/{stage}/report",
                    json={"status": "done", "output": "restored"}, headers=hdr)

    db.expire_all()
    row = db.query(models.Container).filter(models.Container.host_id == host.id).one()
    assert row.rollback_captured_at is None, "a rollback must not re-stamp the capture"


def test_the_agent_is_told_to_roll_back(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    host.rollback_backend = "none"
    db.commit()
    _report_with_capture(client, host, secret, "api", True)
    job = _start(client, host, scope="containers", container_action="rollback").json()

    assert job["container_action"] == "rollback"
    hdr = {"Authorization": f"Bearer {secret}"}
    client.post(f"/agent/{host.id}/jobs/{job['id']}/stages/preflight/report",
                json={"status": "done", "output": ""}, headers=hdr)
    instruction = client.get(f"/agent/{host.id}/jobs/next", headers=hdr).json()

    assert instruction["stage_name"] == "containers"
    assert instruction["container_action"] == "rollback"


def test_rollback_is_refused_without_a_capture(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    _report_with_capture(client, host, secret, "never-updated", False)

    resp = _start(client, host, scope="containers", container_action="rollback")

    assert resp.status_code == 409
    assert "no container rollback points" in resp.text


def test_naming_a_service_with_no_capture_says_so(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    _report_with_capture(client, host, secret, "fresh", False)

    resp = _start(client, host, scope="containers",
                  container_action="rollback", containers=["fresh"])

    assert resp.status_code == 400
    assert "No rollback capture" in resp.text


def test_rollback_may_not_be_mixed_with_os_patching(client, db, logged_in):
    """An undo and a change in one run, under one audit entry, is not
    something an operator can reason about afterwards."""
    logged_in("admin")
    host, secret = make_host(db)
    _report_with_capture(client, host, secret, "api", True)

    resp = _start(client, host, scope="both", container_action="rollback")

    assert resp.status_code == 400
    assert "on its own" in resp.text


def test_an_unknown_container_action_is_rejected(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    _report_with_capture(client, host, secret, "api", True)
    assert _start(client, host, scope="containers",
                  container_action="delete").status_code == 400


def test_capture_state_survives_an_inventory_refresh(client, db, logged_in):
    """Inventory replaces rows wholesale, so the capture timestamp -- which
    only the controller knows -- has to be carried across."""
    logged_in("admin")
    host, secret = make_host(db)
    _report_with_capture(client, host, secret, "api", True)
    row = db.query(models.Container).filter(models.Container.host_id == host.id).one()
    from datetime import datetime
    stamped = datetime(2026, 3, 1, 12, 0)
    row.rollback_captured_at = stamped
    db.commit()

    _report_with_capture(client, host, secret, "api", True)

    db.expire_all()
    row = db.query(models.Container).filter(models.Container.host_id == host.id).one()
    assert row.rollback_captured_at == stamped


def test_a_capture_removed_on_the_host_stops_being_offered(client, db, logged_in):
    """`docker image prune` can take the capture away; the agent reports
    that, and the timestamp must not outlive it."""
    logged_in("admin")
    host, secret = make_host(db)
    _report_with_capture(client, host, secret, "api", True)
    row = db.query(models.Container).filter(models.Container.host_id == host.id).one()
    from datetime import datetime
    row.rollback_captured_at = datetime(2026, 3, 1, 12, 0)
    db.commit()

    _report_with_capture(client, host, secret, "api", False)

    db.expire_all()
    row = db.query(models.Container).filter(models.Container.host_id == host.id).one()
    assert row.rollback_available is False
    assert row.rollback_captured_at is None
