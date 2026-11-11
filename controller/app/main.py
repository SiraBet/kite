import asyncio
import hmac
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from .db import init_db, SessionLocal
from .config import settings
from .bootstrap import bootstrap_admin, bootstrap_checklist
from .logging_config import setup_logging, logger
from .rate_limit import limiter
from . import (agent_releases, db_backups, jobs_engine, repo_signing, monitoring, network_inventory, proxmox_connections, scheduler,
               snapshot_retention, vulnerabilities)
from .routers import (enroll, agent, hosts, tickets, defs, runs, audit_router, os_scripts, auth_router,
                       settings as settings_router, users, checklist, schedules, dashboard, downloads,
                       api_tokens, infrastructure, agent_updates, snapshots, batches, groups, backups,
                       vulnerabilities as vulnerabilities_router)

setup_logging()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_FILE = PROJECT_ROOT / "frontend" / "kite.html"
REPO_DIR = agent_releases.REPO_DIR   # KITE_REPO_DIR, see app/agent_releases.py

BACKGROUND_LOOPS = {
    "monitor_task": monitoring.monitor_loop,
    "scheduler_task": scheduler.scheduler_loop,
    # Finishes soak stages whose wait has elapsed. Without this running,
    # a job that reaches soak never completes — see jobs_engine.py.
    "deferred_task": jobs_engine.deferred_loop,
    # Re-reads Proxmox bridges and guest NICs; see app/network_inventory.py.
    "network_task": network_inventory.network_loop,
    # Removes kite's old Proxmox snapshots; see app/snapshot_retention.py.
    "snapshot_task": snapshot_retention.retention_loop,
    # Downloads and refreshes vulnerability data when enabled; see app/vulnerabilities.py.
    "vuln_task": vulnerabilities.refresh_loop,
    # A daily, compressed copy of the database, the oldest pruned; see app/db_backups.py.
    "backup_task": db_backups.backup_loop,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        bootstrap_admin(db)
        bootstrap_checklist(db)
        # The single pre-existing Proxmox connection becomes the first of
        # the list, once. See app/proxmox_connections.py.
        adopted = proxmox_connections.adopt_legacy_connection(db)
        if adopted:
            logger.info("proxmox_connection_adopted name=%s", adopted.name)
    finally:
        db.close()
    if agent_releases.SEED_DIR:
        try:
            for what in agent_releases.seed_agents(Path(agent_releases.SEED_DIR)):
                logger.info("agent_seeded %s", what)
        except OSError as e:
            logger.warning("agent seeding failed: %s", e)
    # Sign whatever agent RPMs aren't yet (first start makes the key). An
    # install without the tools keeps an unsigned repo and says so.
    if any(agent_releases.REPO_DIR.glob("*.rpm")):
        try:
            result = repo_signing.sign_repo(agent_releases.REPO_DIR)
            if result["signed"]:
                logger.info("agent_repo_signed key=%s rpms=%s", result["key"], ",".join(result["signed"]))
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            logger.warning("agent repo left unsigned: %s", e)
    logger.info("kite-controller startup complete")

    tasks = {name: asyncio.create_task(loop()) for name, loop in BACKGROUND_LOOPS.items()}
    for name, task in tasks.items():
        setattr(app.state, name, task)
    try:
        yield
    finally:
        for task in tasks.values():
            task.cancel()


app = FastAPI(
    title="kite-controller", version="1.0.0", lifespan=lifespan,
    # Unauthenticated by nature, so only served when asked for (KITE_API_DOCS).
    docs_url="/docs" if settings.api_docs else None,
    redoc_url="/redoc" if settings.api_docs else None,
    openapi_url="/openapi.json" if settings.api_docs else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security response headers, applied to every response. The console is
# same-origin and loads only its own assets under /ui, so a tight policy
# costs nothing here.
#
# script-src has to keep 'unsafe-inline': the console drives its UI
# through inline on*= handlers, which CSP cannot allow via nonce/hash —
# only via 'unsafe-inline'. So CSP is not the primary XSS control here
# (output escaping and input validation are); it is defense in depth. The
# other directives still bite hard on a hypothetical injected script:
# connect-src 'self' blocks exfiltration to an attacker origin, object-src
# 'none' kills plugin vectors, base-uri 'none' stops <base> hijacking of
# every relative URL, and frame-ancestors 'none' blocks clickjacking.
# fonts.googleapis.com / fonts.gstatic.com are allowed because the
# console's HTML links the IBM Plex web fonts from there; nothing else
# off-origin is permitted. (An air-gapped deployment could self-host
# those and drop these two — the page already ships system-font
# fallbacks, so it degrades cleanly rather than breaking.)
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "img-src 'self' data:; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    # Honored by browsers only over HTTPS, ignored over plain HTTP — safe
    # to always send, and it takes effect the moment TLS is terminated in
    # front (the documented Caddy deployment).
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    # The console's own files: check with us on every load. Without this a
    # browser may keep running the previous release's JavaScript after an
    # upgrade, against the new API, until someone thinks to hard-refresh.
    # Unchanged files still cost only a 304 (StaticFiles sends ETags).
    if request.url.path == "/" or request.url.path.startswith("/ui/"):
        response.headers.setdefault("Cache-Control", "no-cache")
    return response

_ALLOWED_ORIGINS = {o.strip().lower().rstrip("/") for o in settings.cors_origins.split(",") if o.strip()}


@app.middleware("http")
async def same_origin_writes(request, call_next):
    """
    Refuse a state-changing request that a browser says came from another
    site.

    The session cookie is SameSite=Lax, which keeps other *sites* from
    riding it but treats every port and sibling service on the same host
    name as the same site. Uploading a stage script is an ordinary form
    post whose result runs as root across the fleet, so "something else
    served from this host name" is not a boundary to leave to the cookie.

    A browser attaches Origin to every cross-origin request and to every
    same-origin one that isn't a GET or HEAD; it has to match the host the
    request was sent to (or an origin listed in CORS_ORIGINS). Requests
    with no Origin are not browsers making a cross-site call -- agents,
    the MCP server, curl, the ticket webhook -- and are judged by their
    own credentials as before.
    """
    origin = request.headers.get("origin")
    if origin is not None and request.method not in ("GET", "HEAD", "OPTIONS"):
        sent_from = urlsplit(origin).netloc.lower()
        # A proxy that rewrites Host reports the name the browser used in
        # X-Forwarded-Host. A page on another site can't set that header
        # on a form post, and a scripted request that tries is stopped by
        # the browser's preflight, so honouring it opens nothing.
        sent_to = {request.headers.get("host", "").lower(),
                   request.headers.get("x-forwarded-host", "").split(",")[0].strip().lower()}
        allowed = "*" in _ALLOWED_ORIGINS or origin.lower().rstrip("/") in _ALLOWED_ORIGINS
        if not allowed and (not sent_from or sent_from not in sent_to):
            return JSONResponse({"detail": "This request came from another site and was refused."}, status_code=403)
    return await call_next(request)


app.include_router(enroll.router)
app.include_router(agent.router)
app.include_router(hosts.router)
app.include_router(tickets.router)
app.include_router(defs.router)
app.include_router(runs.router)
app.include_router(audit_router.router)
app.include_router(os_scripts.router)
app.include_router(auth_router.router)
app.include_router(settings_router.router)
app.include_router(users.router)
app.include_router(checklist.router)
app.include_router(schedules.router)
app.include_router(dashboard.router)
app.include_router(downloads.router)
app.include_router(api_tokens.router)
app.include_router(infrastructure.router)
app.include_router(agent_updates.router)
app.include_router(groups.router)
app.include_router(backups.router)
app.include_router(snapshots.router)
app.include_router(batches.router)
app.include_router(vulnerabilities_router.router)

REPO_DIR.mkdir(exist_ok=True)
app.mount("/repo", StaticFiles(directory=str(REPO_DIR)), name="repo")

# The console's CSS and JS. index() below still serves the HTML shell at
# "/", and that shell references everything else under /ui — see
# frontend/kite.html's load-order comment.
app.mount("/ui", StaticFiles(directory=str(FRONTEND_FILE.parent)), name="ui")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/metrics")
def metrics(authorization: str = Header(default="")):
    """
    Prometheus exposition format. Open by default — standard for a scrape
    endpoint (every Prometheus exporter works this way; access control is
    a network/firewall concern first). Only aggregate counts are exposed
    here, never hostnames or any other host-identifying detail — see
    app/monitoring.py for exactly what's in it.

    Where the network can't be relied on for that, KITE_METRICS_TOKEN
    makes this require a bearer token: the counts still describe the
    fleet's patch state, and every scrape recomputes them from the
    database.
    """
    if settings.metrics_token:
        expected = f"Bearer {settings.metrics_token}"
        if not hmac.compare_digest(authorization.encode(), expected.encode()):
            raise HTTPException(401, "Metrics need a bearer token (KITE_METRICS_TOKEN)",
                                headers={"WWW-Authenticate": "Bearer"})
    db = SessionLocal()
    try:
        body = monitoring.render_metrics(db)
    finally:
        db.close()
    return Response(content=body, media_type=CONTENT_TYPE_LATEST)


@app.get("/")
def index():
    return FileResponse(FRONTEND_FILE)
