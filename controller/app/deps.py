from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session

from . import models
from .db import get_db
from .security import verify_secret


def get_current_agent_host(
    host_id: int,
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> models.Host:
    """
    Agent endpoints are path-scoped to a host id and authenticated with
    'Authorization: Bearer <agent_secret>' — the secret issued once at
    enrollment. Each host's credential only proves that host's identity.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header")
    secret = authorization.removeprefix("Bearer ").strip()

    host = db.query(models.Host).filter(models.Host.id == host_id).first()
    if not host or not host.agent_secret_hash:
        raise HTTPException(401, "Unknown host or not enrolled")
    if not verify_secret(secret, host.agent_secret_hash):
        raise HTTPException(401, "Invalid agent credential")
    return host
