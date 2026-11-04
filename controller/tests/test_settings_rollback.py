from app import models, crypto
from conftest import make_host


def test_generic_put_rejects_secret_key(client, logged_in):
    logged_in(role="admin", username="rb-admin-1")
    resp = client.put("/settings/rollback_proxmox_token_secret_enc", json={"value": "sneaky"})
    assert resp.status_code == 400


def test_generic_put_rejects_the_unencrypted_alias_name_too(client, logged_in):
    logged_in(role="admin", username="rb-admin-2")
    resp = client.put("/settings/rollback_proxmox_token_secret", json={"value": "sneaky"})
    assert resp.status_code == 400


def test_dedicated_secret_endpoint_requires_admin(client, logged_in):
    logged_in(role="lead", username="rb-lead-1")
    resp = client.put("/settings/rollback-proxmox-secret", json={"value": "my-token"})
    assert resp.status_code == 403


def test_dedicated_secret_endpoint_stores_encrypted_and_never_echoes_it(client, logged_in, db):
    logged_in(role="admin", username="rb-admin-3")
    resp = client.put("/settings/rollback-proxmox-secret", json={"value": "my-real-proxmox-token"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "set": True}

    row = db.query(models.Setting).filter(models.Setting.key == "rollback_proxmox_token_secret_enc").first()
    assert row.value != "my-real-proxmox-token"  # stored encrypted, not plaintext
    assert crypto.decrypt(row.value) == "my-real-proxmox-token"

    listing = client.get("/settings").json()
    settings_dict = {s["key"]: s["value"] for s in listing}
    assert settings_dict["rollback_proxmox_token_secret_set"] == "true"
    assert "rollback_proxmox_token_secret_enc" not in settings_dict  # ciphertext never listed generically
    assert "my-real-proxmox-token" not in str(listing)


def test_dedicated_secret_endpoint_clears_with_empty_value(client, logged_in):
    logged_in(role="admin", username="rb-admin-4")
    client.put("/settings/rollback-proxmox-secret", json={"value": "something"})
    resp = client.put("/settings/rollback-proxmox-secret", json={"value": ""})
    assert resp.json() == {"ok": True, "set": False}
    settings_dict = {s["key"]: s["value"] for s in client.get("/settings").json()}
    assert settings_dict["rollback_proxmox_token_secret_set"] == "false"


def test_host_rollback_backend_patch_validates_choice(client, logged_in, db):
    logged_in(role="admin", username="rb-admin-5")
    host, _ = make_host(db)

    bad = client.patch(f"/hosts/{host.id}", json={"rollback_backend": "not-a-real-backend"})
    assert bad.status_code == 400

    good = client.patch(f"/hosts/{host.id}", json={"rollback_backend": "dnf_history"})
    assert good.status_code == 200
    assert good.json()["rollback_backend"] == "dnf_history"

    cleared = client.patch(f"/hosts/{host.id}", json={"rollback_backend": ""})
    assert cleared.status_code == 200
    assert cleared.json()["rollback_backend"] in ("", None)
