import io


def _upload(client, family, stage, content, filename="script.sh"):
    return client.post(
        f"/os-scripts/{family}/{stage}/upload",
        files={"file": (filename, io.BytesIO(content.encode()), "text/x-sh")},
    )


def test_upload_requires_admin(client, logged_in):
    logged_in(role="lead", username="scripts-lead")
    resp = _upload(client, "rocky9", "preflight", "#!/bin/bash\necho hi\n")
    assert resp.status_code == 403


def test_upload_rejects_non_scriptable_stage(client, logged_in):
    logged_in(role="admin", username="scripts-admin-1")
    resp = _upload(client, "rocky9", "reboot", "#!/bin/bash\nreboot now\n")
    assert resp.status_code == 400


def test_second_upload_replaces_not_stacks(client, logged_in):
    logged_in(role="admin", username="scripts-admin-2")

    first = _upload(client, "rocky9", "patch", "#!/bin/bash\necho v1\n", filename="v1.sh")
    assert first.status_code == 200
    assert first.json()["tested"] is False

    second = _upload(client, "rocky9", "patch", "#!/bin/bash\necho v2\n", filename="v2.sh")
    assert second.status_code == 200

    live = client.get("/os-scripts/family/rocky9").json()
    patch_scripts = [s for s in live if s["stage_name"] == "patch"]
    assert len(patch_scripts) == 1, "must never stack more than one live script per (os_family, stage)"
    assert patch_scripts[0]["filename"] == "v2.sh"

    history = client.get("/os-scripts/rocky9/patch/history").json()
    assert len(history) == 1
    assert history[0]["filename"] == "v1.sh"
    assert history[0]["note"] == "replaced"


def test_download_returns_exact_uploaded_content(client, logged_in):
    logged_in(role="admin", username="scripts-admin-3")
    content = "#!/bin/bash\necho exact-match-check\n"
    _upload(client, "rhel9", "excludes", content, filename="excludes.sh")

    resp = client.get("/os-scripts/rhel9/excludes/download")
    assert resp.status_code == 200
    assert resp.text == content


def test_delete_moves_to_history_and_reverts_to_builtin(client, logged_in):
    logged_in(role="admin", username="scripts-admin-4")
    _upload(client, "win2022", "preflight", "Write-Output 'hi'\n", filename="preflight.ps1")

    resp = client.delete("/os-scripts/win2022/preflight")
    assert resp.status_code == 200

    live = client.get("/os-scripts/family/win2022").json()
    assert all(s["stage_name"] != "preflight" for s in live)

    history = client.get("/os-scripts/win2022/preflight/history").json()
    assert history[0]["note"] == "deleted"


def test_delete_requires_admin(client, logged_in):
    logged_in(role="admin", username="scripts-admin-5")
    _upload(client, "rocky8", "patch", "#!/bin/bash\necho hi\n")

    logged_in(role="operator", username="scripts-operator")
    resp = client.delete("/os-scripts/rocky8/patch")
    assert resp.status_code == 403
