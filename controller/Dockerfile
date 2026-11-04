# 3.9 to match the non-Docker install target (RHEL/Rocky 8 and 9), so
# both paths run the same interpreter and neither can drift into syntax
# the other can't parse. See ROADMAP.md's note on 3.9 being past
# upstream EOL and what that costs.
# The agents this controller hands out are built here too, from the
# repository beside controller/ (docker-compose.yml passes it in as the
# `repo` build context), so a fresh install can enroll machines straight
# away and `docker compose up --build` after an upgrade serves the new
# agents. Built with:  docker compose build   (or, by hand:
#   docker build --build-context repo=.. -t kite-controller .)

# Windows agent and its installer: cross-compiled, no CGO.
FROM golang:1.23 AS windows-agent
COPY --from=repo agent-windows/ /src/agent-windows/
RUN OUT=/out/dist bash /src/agent-windows/build.sh

# Linux agent: the RPM for RHEL-family hosts (built on EL8, which every
# supported release can install) and the Debian/Ubuntu bundle.
FROM rockylinux/rockylinux:8 AS linux-agent
RUN dnf install -y rpm-build createrepo_c tar gzip >/dev/null && dnf clean all
COPY --from=repo agent-linux/ /src/agent-linux/
RUN OUT=/out/repo bash /src/agent-linux/packaging/build.sh \
    && createrepo_c /out/repo >/dev/null \
    && bash /src/agent-linux/packaging/bundle.sh /out/dist

FROM python:3.9-slim

# The controller signs its agent repo on start (app/repo_signing.py).
RUN apt-get update && apt-get install -y --no-install-recommends gnupg rpm createrepo-c \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY frontend/ ./frontend/
# Served at /download/mcp-server for the API-token setup command.
COPY tools/kite_mcp.py tools/reset_admin_password.py ./tools/
# Required at runtime, not just for development: app/db.py runs
# `alembic upgrade head` on every startup, so a container without these
# cannot start at all.
COPY alembic.ini ./
COPY migrations/ ./migrations/

# Persistent state (DB + dnf repo) is expected to live under a mounted
# volume at /app/data — see docker-compose.yml. Both paths are plain
# env vars the app already reads (KITE_DB in app/db.py,
# KITE_REPO_DIR in app/main.py), nothing Docker-specific about them.
RUN mkdir -p /app/data/repo /app/data/dist
ENV KITE_DB=/app/data/kite.db
ENV KITE_REPO_DIR=/app/data/repo
# Where the Windows installer and the Debian/Ubuntu bundle are served from.
ENV KITE_DIST_DIR=/app/data/dist
# The agents built above. On every start the controller copies any newer
# than what the volume holds into the two directories above (see
# app/agent_releases.py seed_agents).
COPY --from=windows-agent /out/dist/ /app/agents/dist/
COPY --from=linux-agent /out/ /app/agents/
ENV KITE_AGENT_SEED_DIR=/app/agents

# Runs unprivileged — the container needs no root capability at all
# (it binds 8000, not a privileged port, and Caddy is the only public
# listener). The data volume has to be owned by this user before the
# drop, or the app can't create its own SQLite file on first start.
# A fixed, high uid rather than --system: the number is what a bind-mount
# on the host has to match, so it should be predictable and stable. (Not
# --system, which warns that 10001 is above SYS_UID_MAX.)
RUN useradd --uid 10001 --create-home --home-dir /home/kite --shell /usr/sbin/nologin kite \
    && chown -R kite:kite /app
USER kite

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
