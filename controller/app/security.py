import hashlib
import hmac
import os
import secrets
import threading


def cli_safe_token(nbytes: int) -> str:
    """
    A urlsafe token that never starts with '-'.

    Every secret this project generates reaches a command line:
    `enroll.py --secret <value>`, the install one-liner on the Fleet
    page, the `.env` line the startup banner prints. `token_urlsafe`
    draws from A-Za-z0-9-_, so roughly 1 token in 32 begins with a
    hyphen, and argparse reads that as the start of the next flag —
    the call fails with "argument --secret: expected one argument".

    Rejecting those draws is simpler than quoting correctly in every
    consumer, and costs one extra draw 3% of the time. Entropy is
    unaffected: this selects uniformly among tokens that don't start
    with '-' rather than rewriting the token it drew.
    """
    while True:
        token = secrets.token_urlsafe(nbytes)
        if not token.startswith("-"):
            return token


def generate_secret() -> str:
    """One-time agent credential, shown to the caller exactly once at enrollment."""
    return cli_safe_token(32)


def hash_secret(secret: str) -> str:
    """
    Plain unsalted SHA-256, deliberately — not the PBKDF2 treatment user
    passwords get below. The input here is never human-chosen: it's the
    256 bits of `secrets.token_urlsafe(32)` from generate_secret(). Key
    stretching exists to make guessing a low-entropy secret expensive,
    and there is no dictionary to run against a full-entropy random
    token, so the stretching would buy nothing. It would cost something
    real, though: this runs on every single agent API call (see
    deps.py), so a fleet's steady-state poll traffic would be paying
    ~280ms of CPU per request — the exact load-shedding problem
    documented under _PBKDF2_CONCURRENCY below, but on the hot path.

    Salting is likewise pointless for the same reason (no cross-account
    rainbow-table risk on unique random tokens), and each hash is
    per-host anyway.
    """
    return hashlib.sha256(secret.encode()).hexdigest()


def verify_secret(secret: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), hashed)


def generate_enrollment_token() -> str:
    return cli_safe_token(24)


# ---------- Passwords ----------
# PBKDF2-HMAC-SHA256 via stdlib hashlib — no extra dependency (bcrypt/argon2
# would be marginally stronger but aren't worth a new requirement for a
# lab-scale user table). 200k iterations is a reasonable modern minimum.
_PBKDF2_ITERATIONS = 200_000

# PBKDF2 at this iteration count is deliberately CPU-expensive — that's
# the point for one login at a time, but it is also an availability
# risk: auth_router.py burns a full PBKDF2 hash even for a username
# that doesn't exist (deliberately, to keep login timing uniform), so
# every failed login costs the same CPU as a real one. A
# flood spread across many source IPs (each individually under the
# per-IP rate limit, so that limiter is doing nothing wrong) saturates
# CPU with concurrent hashing: under a 300-concurrent-login flood most
# requests time out, and unrelated cheap requests like /health degrade
# with them, since sync routes share one process's threadpool.
#
# A plain "cap concurrency to N" semaphore does not fix this. It only
# changes how the work is scheduled, not how much there is, so a flood
# larger than N still queues past any client-side timeout — measured at
# ~85% of requests still timing out. What works is bounding the WAIT
# rather than the work: fail fast with a clear "too busy" signal once no
# hashing slot frees up quickly, instead of leaving a request (and the
# threadpool slot it holds) queued indefinitely.
_PBKDF2_CONCURRENCY = threading.Semaphore(max(2, os.cpu_count() or 2))
# A single hash costs roughly 280ms on typical hardware, and the acquire
# timeout has to stay close to that rather than being a generous
# multiple of it: with a fixed-size threadpool shared across every
# request (Starlette/AnyIO's default sync-route pool, ~40 workers), a
# timeout much longer than one hash leaves blocked threads occupying
# pool slots doing nothing, starving the pool faster than it drains and
# defeating the point of failing fast. Measured under a
# 300-concurrent-login flood: 2s left ~82% of requests timing out
# client-side, 0.5s ~30%, 0.2s none (93% clean 503s, the rest served in
# time).
_PBKDF2_ACQUIRE_TIMEOUT_SEC = 0.2


class PasswordHasherBusy(Exception):
    """
    No PBKDF2 slot freed up within _PBKDF2_ACQUIRE_TIMEOUT_SEC. Callers
    on a request path (login, password change/reset) should catch this
    and return a fast, honest 503 rather than let the request hang.
    """


def _pbkdf2(password: str, salt: bytes) -> bytes:
    if not _PBKDF2_CONCURRENCY.acquire(timeout=_PBKDF2_ACQUIRE_TIMEOUT_SEC):
        raise PasswordHasherBusy()
    try:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    finally:
        _PBKDF2_CONCURRENCY.release()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = _pbkdf2(password, bytes.fromhex(salt))
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest_hex = stored.split("$", 1)
    except ValueError:
        return False
    digest = _pbkdf2(password, bytes.fromhex(salt))
    return hmac.compare_digest(digest.hex(), digest_hex)


def generate_session_token() -> str:
    # Cookie value, never a CLI argument — but kept consistent so there
    # is one token generator in this file, not two with different rules.
    return cli_safe_token(32)
