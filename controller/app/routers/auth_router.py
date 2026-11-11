import secrets

from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session as DbSession

from .. import models, schemas, audit, ldap_auth
from ..db import get_db
from ..auth import (get_current_user, create_session, find_user, use_secure_cookie,
                    SESSION_COOKIE_NAME, SESSION_TTL_HOURS)
from ..security import verify_password, hash_password, hash_secret, PasswordHasherBusy
from ..rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["auth"])

# Never a real, verifiable password hash (see security.py's format:
# "salt$digest") — a user provisioned via LDAP always re-authenticates
# against the directory, never against a cached local copy, so this
# value only needs to be a hash that verify_password can never match.
LDAP_MANAGED_SENTINEL = "!ldap-managed!"

# Hashed once at import time, never matched against anything real — its
# only job is to give the "no local account" branch a PBKDF2 computation
# to burn, so its latency looks like the real verify_password() call on
# the "wrong password for a real account" branch. Without this, a
# nonexistent (or LDAP-only) username returns near-instantly while a real
# local username with a wrong password takes ~100ms, letting an attacker
# enumerate valid usernames purely from response timing (LDAP disabled is
# the default — see ldap_auth.authenticate's fast-path return in that case).
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(16))


@router.post("/login", response_model=schemas.MeOut)
@limiter.limit("5/minute")
def login(request: Request, payload: schemas.LoginRequest, response: Response, db: DbSession = Depends(get_db)):
    try:
        return _login(request, payload, response, db)
    except PasswordHasherBusy:
        # Every failed login (real or bogus username) burns a full
        # PBKDF2 hash by design (see _DUMMY_PASSWORD_HASH below) — a
        # flood spread across many source IPs, each individually under
        # the per-IP rate limit, can still exhaust available hashing
        # capacity. Fail fast and honestly here rather than let the
        # request (and the threadpool slot it holds) queue indefinitely
        # toward a client-side timeout — see security.py's
        # PasswordHasherBusy docstring for the load-test finding behind this.
        raise HTTPException(503, "Server is busy — try again in a moment") from None


def _login(request: Request, payload: schemas.LoginRequest, response: Response, db: DbSession):
    username = payload.username.strip()
    user = find_user(db, username)

    if user and user.auth_source == "local":
        if not verify_password(payload.password, user.password_hash):
            # Same error for "no such user" and "wrong password" — don't leak which one.
            raise HTTPException(401, "Invalid username or password")
    else:
        # No local account with this username (or one that's already
        # LDAP-sourced) — try the directory. Covers both "first-ever
        # login for this LDAP user" and "an existing LDAP user logging in
        # again", since neither case has (or should trust) a local
        # password to check.
        if not ldap_auth.authenticate(db, username, payload.password):
            verify_password(payload.password, _DUMMY_PASSWORD_HASH)  # burn the same time a real check would take
            raise HTTPException(401, "Invalid username or password")
        if not user:
            # Stored in lower case, so every spelling of the name the
            # directory accepts lands on this one account (auth.find_user).
            user = models.User(
                username=username.lower(),
                password_hash=LDAP_MANAGED_SENTINEL,
                role=ldap_auth.ldap_config(db)["default_role"],
                display_name=username,
                auth_source="ldap",
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            audit.log(db, actor="system", role="controller", action="user_provisioned",
                      detail=f"{user.username} ({user.role}) via LDAP", tone="success")

    token = create_session(db, user)
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        httponly=True, samesite="lax", secure=use_secure_cookie(request),
        max_age=SESSION_TTL_HOURS * 3600,
    )
    audit.log(db, actor=user.username, role=user.role, action="login", detail="")
    return _me(user)


@router.post("/logout")
def logout(request: Request, response: Response, db: DbSession = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        sess = db.query(models.Session).filter(models.Session.token == hash_secret(token)).first()
        if sess:
            db.delete(sess)
            db.commit()
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"ok": True}


@router.get("/me", response_model=schemas.MeOut)
def me(user: models.User = Depends(get_current_user)):
    return _me(user)


def _me(user: models.User) -> schemas.MeOut:
    return schemas.MeOut(username=user.username, role=user.role, display_name=user.display_name,
                         must_change_password=bool(user.must_change_password))


@router.post("/change-password")
def change_password(request: Request, payload: schemas.ChangePasswordRequest, db: DbSession = Depends(get_db),
                     user: models.User = Depends(get_current_user)):
    try:
        return _change_password(request, payload, db, user)
    except PasswordHasherBusy:
        raise HTTPException(503, "Server is busy — try again in a moment") from None


def _change_password(request: Request, payload: schemas.ChangePasswordRequest, db: DbSession, user: models.User):
    if user.auth_source != "local":
        raise HTTPException(400, "This account's password is managed by your LDAP directory, not kite")
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(401, "Current password is incorrect")
    if len(payload.new_password) < 12:
        raise HTTPException(400, "New password must be at least 12 characters")
    if payload.new_password == payload.current_password:
        raise HTTPException(400, "Choose a password different from the current one")
    was_temporary = bool(user.must_change_password)
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    # Same reasoning as users.py's admin-driven reset_password: a
    # password change is exactly when a leaked/stolen session (shared
    # machine, a proxy log, shoulder-surfed cookie) should stop working.
    # Without this, someone who already has a copy of this user's
    # session cookie keeps full access even after the real user reacts
    # to a suspected compromise by changing their password. Keeps the
    # session making this request alive (a password change shouldn't
    # log out the person who just typed it correctly).
    current_token = request.cookies.get(SESSION_COOKIE_NAME)
    db.query(models.Session).filter(
        models.Session.user_id == user.id, models.Session.token != hash_secret(current_token or "")
    ).delete()
    # API tokens too, for the same reason and as an admin's reset already
    # does: a token is this account's credential for up to a year, and
    # someone changing their password because it may have leaked expects
    # everything issued under it to stop working.
    revoked = db.query(models.ApiToken).filter(models.ApiToken.user_id == user.id).delete()
    db.commit()
    notes = ["replaced a temporary password"] if was_temporary else []
    if revoked:
        notes.append(f"{revoked} API token{'' if revoked == 1 else 's'} revoked")
    audit.log(db, actor=user.username, role=user.role, action="password_changed", detail="; ".join(notes))
    return {"ok": True, "api_tokens_revoked": revoked}
