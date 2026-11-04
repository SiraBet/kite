from app import models
from app.bootstrap import bootstrap_checklist, _DEFAULT_CHECKLIST_ITEMS


def test_bootstrap_seeds_default_items_once(db):
    bootstrap_checklist(db)
    items = db.query(models.ChecklistItem).order_by(models.ChecklistItem.id).all()
    assert [i.text for i in items] == _DEFAULT_CHECKLIST_ITEMS

    bootstrap_checklist(db)  # must not double-seed on a second call
    assert db.query(models.ChecklistItem).count() == len(_DEFAULT_CHECKLIST_ITEMS)


def test_list_checklist_items_requires_login(client):
    resp = client.get("/checklist-items")
    assert resp.status_code == 401


def test_add_checklist_item_requires_admin(client, logged_in):
    logged_in(role="lead", username="cl-lead-1")
    resp = client.post("/checklist-items", json={"text": "New item"})
    assert resp.status_code == 403


def test_add_and_list_checklist_item(client, logged_in):
    logged_in(role="admin", username="cl-admin-1")
    resp = client.post("/checklist-items", json={"text": "Rollback plan documented"})
    assert resp.status_code == 200
    assert resp.json()["text"] == "Rollback plan documented"

    listing = client.get("/checklist-items").json()
    assert any(i["text"] == "Rollback plan documented" for i in listing)


def test_add_checklist_item_rejects_blank_text(client, logged_in):
    logged_in(role="admin", username="cl-admin-2")
    resp = client.post("/checklist-items", json={"text": "   "})
    assert resp.status_code == 400


def test_delete_checklist_item(client, logged_in, db):
    logged_in(role="admin", username="cl-admin-3")
    created = client.post("/checklist-items", json={"text": "Temporary item"}).json()
    resp = client.delete(f"/checklist-items/{created['id']}")
    assert resp.status_code == 200
    assert db.query(models.ChecklistItem).filter(models.ChecklistItem.id == created["id"]).first() is None


def test_cannot_delete_the_last_checklist_item(client, logged_in, db):
    logged_in(role="admin", username="cl-admin-4")
    # Clear out anything else this test file's fixtures may have added,
    # then add exactly one, so deleting it is unambiguously "the last one".
    db.query(models.ChecklistItem).delete()
    db.commit()
    only = client.post("/checklist-items", json={"text": "Only item"}).json()

    resp = client.delete(f"/checklist-items/{only['id']}")
    assert resp.status_code == 400
    assert db.query(models.ChecklistItem).count() == 1
