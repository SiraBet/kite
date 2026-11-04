
from sqlalchemy.orm import Session

from . import models
from .security import cli_safe_token, hash_password

# The 4 items that used to be hardcoded in the frontend, seeded verbatim
# so upgrading to admin-editable checklist doesn't silently
# start every run with an empty (trivially "fully confirmed") checklist.
_DEFAULT_CHECKLIST_ITEMS = [
    "KVM snapshot capability verified for this host",
    "Services-to-check list is current for this role",
    "No conflicting change scheduled on the node pair",
    "Maintenance window confirmed with app owner",
]


def bootstrap_checklist(db: Session):
    if db.query(models.ChecklistItem).count() > 0:
        return
    for text in _DEFAULT_CHECKLIST_ITEMS:
        db.add(models.ChecklistItem(text=text, created_by="system"))
    db.commit()


def bootstrap_admin(db: Session):
    """
    If there are no users at all (fresh install), create one admin account
    with a random password and print it loudly — same pattern as the
    auto-generated enrollment secret. Unlike that secret, this DOES persist
    (it's a real account in the DB), so it survives restarts; change the
    password after first login rather than relying on this forever.
    """
    if db.query(models.User).count() > 0:
        return

    password = cli_safe_token(12)
    user = models.User(
        username="admin",
        password_hash=hash_password(password),
        role="admin",
        display_name="Admin",
        must_change_password=True,   # printed in a log; the first sign-in replaces it
    )
    db.add(user)
    db.commit()

    # Deliberately one distinctive, greppable marker line: on the Docker
    # path this log is the only place the password appears, and telling
    # someone to "look through the startup output" is not an install
    # step. `docker compose logs controller | grep -A4 ADMIN` finds it.
    print("=" * 72)
    print("kite: ADMIN LOGIN — first-run account created")
    print("    username: admin")
    print(f"    password: {password}")
    print("Shown once and never again. Signing in with it asks you to")
    print("choose your own password straight away.")
    print("=" * 72)
