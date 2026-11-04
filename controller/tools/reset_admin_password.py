#!/usr/bin/env python3
"""
Reset a local account's password from the host, without being logged in.

The first-run admin password is printed to the startup log exactly once
and stored only as a hash. That's the right design, but it has a sharp
edge that showed up immediately in real use: on the Docker path,
`docker compose up -d --build` replaces the container, and the old
container's logs go with it. The account is still there — the password
is simply unrecoverable, and there is no way back in.

    docker compose exec controller python tools/reset_admin_password.py
    sudo -u kite /opt/kite-controller/venv/bin/python \\
        /opt/kite-controller/tools/reset_admin_password.py

This is not a privilege-escalation hole: it requires the ability to run
code as the service user, which is already total control over the
database this would modify. Same reasoning as `passwd` on a box you
already have root on.

Every existing session for the account is invalidated, and the reset is
written to the audit log with actor 'system (cli)' — visibly not a
logged-in admin, on purpose, never disguised as one.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import audit, models  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.security import cli_safe_token, hash_password  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--username", default="admin", help="account to reset (default: admin)")
    parser.add_argument("--password", help="set this password instead of generating one")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.username == args.username).first()
        if not user:
            existing = [u.username for u in db.query(models.User).all()]
            print(f"No account named '{args.username}'. Accounts: {', '.join(existing) or '(none)'}")
            return 1
        if user.auth_source != "local":
            print(f"'{args.username}' is managed by your LDAP directory — reset it there, not here.")
            return 1

        if args.password and len(args.password) < 12:
            print("Password must be at least 12 characters (same rule the API enforces).")
            return 1
        password = args.password or cli_safe_token(12)

        user.password_hash = hash_password(password)
        # A password reset is exactly when any existing session should
        # stop working — same reasoning as the API's own reset endpoint.
        db.query(models.Session).filter(models.Session.user_id == user.id).delete()
        db.commit()
        audit.log(db, actor="system (cli)", role="admin", action="password_reset",
                  detail=f"{user.username} — reset from the host CLI, existing sessions invalidated",
                  tone="warning")

        print(f"Password for '{user.username}' has been reset to:\n\n    {password}\n")
        print("Shown once. Sign in and change it from the console's account menu.")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
