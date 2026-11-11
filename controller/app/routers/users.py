from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..db import get_db
from ..auth import find_user, require_role, ROLE_RANK
from ..security import cli_safe_token, hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=List[schemas.UserOut])
def list_users(db: Session = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    return db.query(models.User).order_by(models.User.username).all()


@router.post("", response_model=schemas.UserOut)
def create_user(payload: schemas.UserCreate, db: Session = Depends(get_db),
                 user: models.User = Depends(require_role("admin"))):
    if payload.role not in ROLE_RANK:
        raise HTTPException(400, f"role must be one of {list(ROLE_RANK)}")
    if len(payload.password) < 12:
        raise HTTPException(400, "Password must be at least 12 characters")
    username = payload.username.strip()
    if not username:
        raise HTTPException(400, "Username can't be blank")
    # Also refused when it differs from an existing name only by case:
    # sign-in treats those as the same account (auth.find_user).
    taken = find_user(db, username)
    if taken:
        raise HTTPException(409, f"Username '{taken.username}' already exists")

    new_user = models.User(
        username=username, password_hash=hash_password(payload.password),
        role=payload.role, display_name=payload.display_name or username,
        must_change_password=payload.must_change_password,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    audit.log(db, actor=user.username, role=user.role, action="user_created",
              detail=f"{username} ({payload.role})"
                     + (", must choose their own password at first sign-in" if payload.must_change_password else ""))
    return new_user


@router.post("/{user_id}/reset-password", response_model=schemas.PasswordResetOut)
def reset_password(user_id: int, payload: Optional[schemas.PasswordResetIn] = None, db: Session = Depends(get_db),
                   user: models.User = Depends(require_role("admin"))):
    """
    Replaces 'another admin deletes and recreates the account' — keeps
    the user's id, role, and audit history intact, sets a temporary
    password (the admin's, or a generated one, shown once here) and kills
    every existing session for that account, so this also works as "get
    a compromised/locked-out account back under control," not just "I
    forgot my password." The temporary password only gets them signed in:
    they must choose their own before doing anything else.
    """
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if target.auth_source != "local":
        raise HTTPException(400, "This account's password is managed by your LDAP directory — nothing to reset here")
    typed = (payload.temporary_password if payload else "") or ""
    if typed and len(typed) < 12:
        raise HTTPException(400, "A temporary password must be at least 12 characters (or leave it blank to generate one)")
    new_password = typed or cli_safe_token(12)
    target.password_hash = hash_password(new_password)
    target.must_change_password = True
    db.query(models.Session).filter(models.Session.user_id == user_id).delete()
    # API tokens too: this is the "account is compromised" lever, and a
    # token is a credential like any session -- one left working would
    # make the reset look complete while it wasn't.
    db.query(models.ApiToken).filter(models.ApiToken.user_id == user_id).delete()
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="password_reset",
              detail=f"{target.username} — reset by {user.username} to a temporary password, existing sessions and API tokens invalidated",
              tone="warning")
    return schemas.PasswordResetOut(username=target.username, new_password=new_password)


@router.patch("/{user_id}", response_model=schemas.UserOut)
def patch_user(user_id: int, payload: schemas.UserPatch, db: Session = Depends(get_db),
                user: models.User = Depends(require_role("admin"))):
    """
    Role/display-name edits only — password is its own endpoint (or the
    LDAP directory, for auth_source='ldap' users; see reset_password
    above). Mainly for LDAP accounts: one provisioned just-in-time
    always starts at ldap_default_role, and this is how an admin
    promotes or demotes it afterwards without deleting the account and
    losing its audit history.
    """
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    fields = payload.model_dump(exclude_unset=True)
    if "role" in fields and fields["role"] not in ROLE_RANK:
        raise HTTPException(400, f"role must be one of {list(ROLE_RANK)}")
    if target.id == user.id and fields.get("role", "admin") != "admin":
        # The one change that can leave no admin at all (whoever makes it
        # is one): nobody left to manage users, settings or connections.
        raise HTTPException(400, "Can't change your own role away from admin; another admin can")
    for field, value in fields.items():
        setattr(target, field, value)
    db.commit()
    db.refresh(target)
    audit.log(db, actor=user.username, role=user.role, action="user_updated",
              detail=f"{target.username}: {fields}")
    return target


@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), user: models.User = Depends(require_role("admin"))):
    if user_id == user.id:
        raise HTTPException(400, "Can't delete your own account while logged in as it")
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    db.query(models.Session).filter(models.Session.user_id == user_id).delete()
    db.query(models.ApiToken).filter(models.ApiToken.user_id == user_id).delete()
    db.delete(target)
    db.commit()
    audit.log(db, actor=user.username, role=user.role, action="user_removed", detail=target.username, tone="danger")
    return {"ok": True}
