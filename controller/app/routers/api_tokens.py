"""
API tokens: bearer credentials for the local MCP server and scripts.

Managed only from a console session (require_session_user), never with
a token: a leaked token must not be able to list the others, mint a
replacement for itself, or outlive its own revocation.

Any role may hold tokens for itself, since a token can never see more
than its owner can. Admins can additionally list and revoke everyone's,
which is the incident-response case.
"""
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..auth import API_TOKEN_PREFIX, require_session_user
from ..db import get_db
from ..security import cli_safe_token, hash_secret

router = APIRouter(prefix="/tokens", tags=["tokens"])

# How much of the token is kept in clear to tell tokens apart in a list:
# the "kite_" marker plus four random characters -- enough to recognise,
# nowhere near enough to guess from.
_DISPLAY_PREFIX_LEN = len(API_TOKEN_PREFIX) + 4


def _out(row: models.ApiToken, **extra) -> dict:
    return dict(
        id=row.id, name=row.name, prefix=row.prefix, scope=row.scope,
        username=row.user.username if row.user else "",
        created_at=row.created_at, expires_at=row.expires_at, last_used_at=row.last_used_at,
        expired=row.expires_at < datetime.utcnow(), **extra,
    )


@router.get("", response_model=List[schemas.ApiTokenOut])
def list_tokens(all: bool = False, db: Session = Depends(get_db),
                user: models.User = Depends(require_session_user)):
    """Your own tokens; `?all=true` lists everyone's, admin only."""
    q = db.query(models.ApiToken)
    if all:
        if user.role != "admin":
            raise HTTPException(403, "Only admins can list every user's tokens")
    else:
        q = q.filter(models.ApiToken.user_id == user.id)
    return [_out(row) for row in q.order_by(models.ApiToken.id.desc()).all()]


@router.post("", response_model=schemas.ApiTokenCreated)
def create_token(payload: schemas.ApiTokenCreate, db: Session = Depends(get_db),
                 user: models.User = Depends(require_session_user)):
    if payload.scope not in models.API_TOKEN_SCOPES:
        raise HTTPException(400, f"scope must be one of {models.API_TOKEN_SCOPES}")
    raw = API_TOKEN_PREFIX + cli_safe_token(32)
    row = models.ApiToken(
        name=payload.name, token_hash=hash_secret(raw), prefix=raw[:_DISPLAY_PREFIX_LEN],
        user_id=user.id, scope=payload.scope,
        expires_at=datetime.utcnow() + timedelta(days=payload.expires_in_days),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.log(db, actor=user.username, role=user.role, action="api_token_created",
              detail=f"'{row.name}' ({row.prefix}…, {row.scope}, expires {row.expires_at:%Y-%m-%d})")
    return _out(row, token=raw)


@router.delete("/{token_id}")
def revoke_token(token_id: int, db: Session = Depends(get_db),
                 user: models.User = Depends(require_session_user)):
    row = db.query(models.ApiToken).filter(models.ApiToken.id == token_id).first()
    # 404 rather than 403 for someone else's token, so a non-admin can't
    # probe which ids exist.
    if not row or (row.user_id != user.id and user.role != "admin"):
        raise HTTPException(404, "Token not found")
    owner = row.user.username if row.user else "?"
    db.delete(row)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="api_token_revoked",
              detail=f"'{row.name}' ({row.prefix}…) owned by {owner}", tone="warning")
    return {"ok": True}
