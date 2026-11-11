from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session as DbSession

from . import models
from .db import get_db
from .security import generate_session_token, hash_secret

SESSION_COOKIE_NAME = "kite_session"
SESSION_TTL_HOURS = 12

# Role tiers — enforced here, not only in JavaScript. "at_least" lets a
# route require e.g. lead-or-admin.
#
# 'viewer' is read-only: auditors, a wall display, anyone who should see
# the fleet but never change it. Ranked below operator so every existing
# require_role() check already excludes it, and refused on every write in
# get_current_user -- several write routes (starting a run, cancelling
# one) are open to any authenticated user, so rank alone wouldn't stop it.
ROLE_RANK = {"viewer": -1, "operator": 0, "lead": 1, "admin": 2}
VIEWER_ROLE = "viewer"

# Every API token starts with this, so a leaked one is recognisable in a
# log or a secret scanner, and so get_current_user can tell one apart
# from anything else that might arrive in an Authorization header.
API_TOKEN_PREFIX = "kite_"
# Methods a read-scoped token may use. Every state change in this API is
# a POST/PUT/PATCH/DELETE, so refusing those here enforces read-only once
# for every route, rather than trusting each route to remember.
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}
# The writes a viewer may still make: things about their own account, not
# about the fleet. Prefix match, so /tokens/{id} is covered too.
_VIEWER_WRITABLE_PATHS = ("/auth/change-password", "/tokens")
# last_used_at is a "is this token still in use?" signal for whoever is
# reviewing the token list, not an access log -- so it is written at most
# this often, rather than turning every read into a database write.
TOKEN_LAST_USED_RESOLUTION = timedelta(minutes=1)


def find_user(db: DbSession, username: str):
    """
    The account a typed username belongs to: the exact one if there is
    one, otherwise the one that differs only by case.

    Directories match names without regard to case, so "Alice" and
    "alice" are one person to LDAP. If they were two accounts here, a
    role change or removal made to one could be sidestepped by signing in
    as the other and being provisioned afresh. The exact match is tried
    first so that accounts created before this rule, which may differ
    only by case, each stay reachable under their own name.
    """
    username = (username or "").strip()
    if not username:
        return None
    exact = db.query(models.User).filter(models.User.username == username).first()
    if exact:
        return exact
    return (db.query(models.User)
            .filter(func.lower(models.User.username) == username.lower())
            .order_by(models.User.id).first())


def create_session(db: DbSession, user: models.User) -> str:
    token = generate_session_token()
    # Only a digest is stored (security.hash_secret): a copy of the
    # database -- a backup, a stolen file -- holds no session a browser
    # could replay. The cookie carries the token itself.
    db.add(models.Session(
        token=hash_secret(token), user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS),
    ))
    db.commit()
    return token


def use_secure_cookie(request: Request) -> bool:
    """
    Whether to set the session cookie's Secure flag (browser only ever
    sends it back over HTTPS). Derived from the request rather than
    configured, because both documented install paths put Caddy in front
    of uvicorn: the app itself always sees plain HTTP on 127.0.0.1, and
    X-Forwarded-Proto is what Caddy sets to report the real scheme. That
    makes this correct with zero configuration for a real deployment,
    while a plain-HTTP local dev run still gets a usable cookie.

    Trusting a client-settable header is fine in this one direction —
    spoofing it can only make the cookie MORE restrictive, never less,
    and Caddy overwrites the header on every proxied request anyway.
    """
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def purge_expired_sessions(db: DbSession) -> int:
    """
    Sessions are otherwise only deleted when their own token is presented
    again after expiry (see get_current_user) — one that's simply never
    used again stays in the table forever. Called from the background
    monitor pass; returns how many rows were removed.
    """
    removed = db.query(models.Session).filter(models.Session.expires_at < datetime.utcnow()).delete()
    db.commit()
    return removed


def _token_user(request: Request, db: DbSession, raw: str) -> models.User:
    row = db.query(models.ApiToken).filter(models.ApiToken.token_hash == hash_secret(raw)).first()
    if not row or not row.user:
        raise HTTPException(401, "Invalid API token")
    now = datetime.utcnow()
    if row.expires_at < now:
        raise HTTPException(401, "API token expired")
    if row.scope == models.API_TOKEN_SCOPE_READ and request.method not in _READ_METHODS:
        raise HTTPException(403, "This API token is read-only")
    if not row.last_used_at or now - row.last_used_at > TOKEN_LAST_USED_RESOLUTION:
        row.last_used_at = now
        db.commit()
    request.state.api_token_id = row.id
    return row.user


def get_current_user(request: Request, db: DbSession = Depends(get_db)) -> models.User:
    """
    The browser console authenticates with the session cookie; anything
    else (the MCP server, scripts) sends `Authorization: Bearer kite_...`.
    A bearer header wins if both are present, so a request is always
    judged by exactly one credential.
    """
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer "):
        raw = authorization.removeprefix("Bearer ").strip()
        if not raw.startswith(API_TOKEN_PREFIX):
            raise HTTPException(401, "Invalid API token")
        user = _token_user(request, db, raw)
        _refuse_until_password_changed(request, user)
        return user

    user = _session_user(request, db)
    _refuse_until_password_changed(request, user)
    if (user.role == VIEWER_ROLE and request.method not in _READ_METHODS
            and not request.url.path.startswith(_VIEWER_WRITABLE_PATHS)):
        raise HTTPException(403, "Read-only account — this action needs operator or higher")
    return user


# All a user with a password someone else chose may do: see who they are,
# choose their own password, or sign out.
_PASSWORD_CHANGE_PATHS = ("/auth/me", "/auth/change-password", "/auth/logout")
PASSWORD_CHANGE_REQUIRED = "password_change_required"


def _refuse_until_password_changed(request: Request, user: models.User):
    if getattr(user, "must_change_password", False) and request.url.path not in _PASSWORD_CHANGE_PATHS:
        raise HTTPException(403, PASSWORD_CHANGE_REQUIRED)


def _session_user(request: Request, db: DbSession) -> models.User:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(401, "Not logged in")
    sess = db.query(models.Session).filter(models.Session.token == hash_secret(token)).first()
    if not sess:
        raise HTTPException(401, "Invalid session")
    if sess.expires_at < datetime.utcnow():
        db.delete(sess)
        db.commit()
        raise HTTPException(401, "Session expired")
    return sess.user


def require_session_user(request: Request, user: models.User = Depends(get_current_user)) -> models.User:
    """
    For the few routes an API token must never reach even read-only --
    token management itself. Listing or minting tokens with a token
    would let one leaked credential discover or outlive the others.
    """
    if getattr(request.state, "api_token_id", None) is not None:
        raise HTTPException(403, "This action needs a console login, not an API token")
    return user


def require_role(min_role: str):
    """
    Dependency factory: require_role("admin") only lets admins through;
    require_role("lead") lets lead or admin through. Use as a route
    dependency: `user: models.User = Depends(require_role("admin"))`.
    """
    def checker(user: models.User = Depends(get_current_user)) -> models.User:
        if ROLE_RANK.get(user.role, -1) < ROLE_RANK.get(min_role, 99):
            raise HTTPException(403, f"Requires {min_role} role or higher (you're {user.role})")
        return user
    return checker
