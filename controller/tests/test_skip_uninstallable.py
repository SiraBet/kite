"""
The "skip updates that can't be installed" policy: a setting that rides
along to the agent on the patch stage only, off by default.
"""
from app import models
from conftest import make_host


def _start(client, host):
    return client.post("/runs", json={"host_id": host.id, "checklist": [{"item_index": 0, "item_text": "ok"}]})


def _patch_instruction(client, db, logged_in):
    logged_in("admin")
    host, secret = make_host(db)
    host.rollback_backend = "none"
    db.commit()
    job = _start(client, host).json()
    hdr = {"Authorization": f"Bearer {secret}"}
    first = client.get(f"/agent/{host.id}/jobs/next", headers=hdr).json()
    for stage in ("preflight", "excludes"):
        client.post(f"/agent/{host.id}/jobs/{job['id']}/stages/{stage}/report",
                    json={"status": "done", "output": ""}, headers=hdr)
    return first, client.get(f"/agent/{host.id}/jobs/next", headers=hdr).json()


def _set(db, value):
    row = db.query(models.Setting).filter_by(key="patch_skip_uninstallable").first()
    if row:
        db.delete(row)
        db.commit()
    if value is not None:
        db.add(models.Setting(key="patch_skip_uninstallable", value=value))
        db.commit()


def test_off_by_default(client, db, logged_in):
    _set(db, None)
    first, patch = _patch_instruction(client, db, logged_in)
    assert patch["stage_name"] == "patch" and patch["skip_uninstallable"] is False
    assert client.get("/settings").status_code == 200
    assert {s["key"]: s["value"] for s in client.get("/settings").json()}["patch_skip_uninstallable"] == "false"


def test_on_it_reaches_the_patch_stage_only(client, db, logged_in):
    _set(db, "true")
    try:
        first, patch = _patch_instruction(client, db, logged_in)
        assert first["stage_name"] == "preflight" and first["skip_uninstallable"] is False
        assert patch["stage_name"] == "patch" and patch["skip_uninstallable"] is True
    finally:
        _set(db, None)


def test_only_true_or_false_and_admin_only(client, db, logged_in):
    logged_in("admin")
    assert client.put("/settings/patch_skip_uninstallable", json={"value": "yes"}).status_code == 400
    assert client.put("/settings/patch_skip_uninstallable", json={"value": "true"}).status_code == 200
    _set(db, None)
    logged_in("lead")
    assert client.put("/settings/patch_skip_uninstallable", json={"value": "true"}).status_code == 403
