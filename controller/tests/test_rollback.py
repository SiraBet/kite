from unittest.mock import patch

import pytest

from app import models, crypto, rollback
from app.proxmox import ProxmoxConfig
from app.rollback.config import resolve_proxmox_config
from conftest import make_host


# ---------- crypto ----------

def test_encrypt_decrypt_roundtrip():
    ciphertext = crypto.encrypt("super-secret-token")
    assert ciphertext != "super-secret-token"
    assert crypto.decrypt(ciphertext) == "super-secret-token"


def test_encrypt_empty_string_stays_empty():
    assert crypto.encrypt("") == ""
    assert crypto.decrypt("") == ""


def test_decrypt_garbage_raises_clear_error():
    with pytest.raises(ValueError, match="KITE_SECRET_KEY"):
        crypto.decrypt("not-a-real-fernet-token")


# ---------- backend resolution ----------

def test_resolve_backend_name_defaults_to_proxmox(db):
    host, _ = make_host(db)
    assert rollback.resolve_backend_name(db, host) == "proxmox"


def test_resolve_backend_name_host_override_wins(db):
    host, _ = make_host(db)
    host.rollback_backend = "dnf_history"
    db.commit()
    assert rollback.resolve_backend_name(db, host) == "dnf_history"


def test_resolve_backend_name_reads_global_default_setting(db):
    host, _ = make_host(db)
    db.add(models.Setting(key="rollback_default_backend", value="none"))
    db.commit()
    assert rollback.resolve_backend_name(db, host) == "none"


def test_stage_executor_for_backend():
    assert rollback.stage_executor_for("proxmox") == "controller"
    assert rollback.stage_executor_for("none") == "controller"
    assert rollback.stage_executor_for("dnf_history") == "agent"


# ---------- run_controller_snapshot ----------

def test_run_controller_snapshot_none_backend_skips_cleanly(db):
    host, _ = make_host(db)
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="none")
    db.add(job)
    db.commit()
    db.refresh(job)

    output = rollback.run_controller_snapshot(db, job, "none")
    assert "skipped" in output
    assert db.query(models.AuditLog).filter(models.AuditLog.action == "snapshot_skipped",
                                            models.AuditLog.detail.like(f"%job {job.id},%")).count() == 1


def test_run_controller_snapshot_proxmox_without_vmid_raises(db):
    host, _ = make_host(db)
    host.proxmox_vmid = None
    db.commit()
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="proxmox")
    db.add(job)
    db.commit()
    db.refresh(job)

    with pytest.raises(RuntimeError, match="no proxmox_vmid"):
        rollback.run_controller_snapshot(db, job, "proxmox")


def test_run_controller_snapshot_proxmox_calls_create_snapshot(db, legacy_proxmox):
    host, _ = make_host(db)
    host.proxmox_vmid = 101
    db.commit()
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="proxmox")
    db.add(job)
    db.commit()
    db.refresh(job)

    with patch("app.proxmox.create_snapshot", return_value={"data": "UPID:fake"}) as mock_snap, \
         patch("app.proxmox.resolve_vm_node", return_value="pve1"):
        output = rollback.run_controller_snapshot(db, job, "proxmox")
    assert output.startswith("Taking snapshot 'kite-job") and "of VM 101" in output
    assert output.endswith("Proxmox task UPID:fake")
    assert mock_snap.call_count == 1


def test_run_controller_snapshot_rejects_agent_side_backend(db):
    host, _ = make_host(db)
    job = models.Job(host_id=host.id, ticket_id="T-1", rollback_backend="dnf_history")
    db.add(job)
    db.commit()
    db.refresh(job)

    with pytest.raises(RuntimeError, match="not a controller-side"):
        rollback.run_controller_snapshot(db, job, "dnf_history")


# ---------- resolve_proxmox_config: DB overrides env, falls back per-field ----------

def test_resolve_proxmox_config_falls_back_to_env_when_db_unset(db):
    with patch("app.rollback.config.settings") as mock_settings:
        mock_settings.proxmox_host = "10.0.0.5"
        mock_settings.proxmox_node = "pve1"
        mock_settings.proxmox_token_id = "kite@pve!snap"
        mock_settings.proxmox_token_secret = "env-secret"
        mock_settings.proxmox_verify_ssl = False
        cfg = resolve_proxmox_config(db)
    assert cfg == ProxmoxConfig(host="10.0.0.5", node="pve1", token_id="kite@pve!snap",
                                 token_secret="env-secret", verify_ssl=False)


def test_resolve_proxmox_config_db_values_take_priority(db):
    db.add(models.Setting(key="rollback_proxmox_host", value="10.0.0.99"))
    db.add(models.Setting(key="rollback_proxmox_node", value="pve-ui"))
    db.add(models.Setting(key="rollback_proxmox_token_id", value="kite@pve!ui"))
    db.add(models.Setting(key="rollback_proxmox_verify_ssl", value="true"))
    db.add(models.Setting(key="rollback_proxmox_token_secret_enc", value=crypto.encrypt("ui-secret")))
    db.commit()

    with patch("app.rollback.config.settings") as mock_settings:
        mock_settings.proxmox_host = "10.0.0.5"  # should be ignored -- DB wins
        mock_settings.proxmox_node = "pve1"
        mock_settings.proxmox_token_id = "kite@pve!snap"
        mock_settings.proxmox_token_secret = "env-secret"
        mock_settings.proxmox_verify_ssl = False
        cfg = resolve_proxmox_config(db)

    assert cfg == ProxmoxConfig(host="10.0.0.99", node="pve-ui", token_id="kite@pve!ui",
                                 token_secret="ui-secret", verify_ssl=True)


# ---------- end-to-end through POST /runs: does the frozen backend
# actually flip the snapshot stage's executor at job creation? ----------

def _start_run(client, host_id):
    return client.post("/runs", json={
        "host_id": host_id,
        "checklist": [{"item_index": 0, "item_text": "confirmed"}],
    })


def test_create_run_freezes_dnf_history_backend_as_agent_stage(client, logged_in, db):
    from app.settings_store import set_setting
    set_setting(db, "require_ticket", "false")  # upsert -- other tests in this file may have already set this key
    logged_in(role="admin", username="run-rb-admin-1")
    host, _ = make_host(db)
    host.rollback_backend = "dnf_history"
    db.commit()

    resp = _start_run(client, host.id)
    assert resp.status_code == 200
    body = resp.json()
    assert body["rollback_backend"] == "dnf_history"
    snapshot_stage = next(s for s in body["stages"] if s["name"] == "snapshot")
    assert snapshot_stage["executor"] == "agent"


def test_create_run_defaults_to_proxmox_as_controller_stage(client, logged_in, db):
    from app.settings_store import set_setting
    set_setting(db, "require_ticket", "false")  # upsert -- other tests in this file may have already set this key
    set_setting(db, "rollback_default_backend", "proxmox")  # explicit, not relying on the DEFAULTS fallback -- an earlier test in this file sets this key too
    logged_in(role="admin", username="run-rb-admin-2")
    host, _ = make_host(db)  # no override -> falls back to the global default (proxmox)

    with patch("app.proxmox.create_snapshot", side_effect=RuntimeError("no vmid, snapshot stage should fail not hang")):
        resp = _start_run(client, host.id)
    assert resp.status_code == 200
    body = resp.json()
    assert body["rollback_backend"] == "proxmox"
    snapshot_stage = next(s for s in body["stages"] if s["name"] == "snapshot")
    assert snapshot_stage["executor"] == "controller"
