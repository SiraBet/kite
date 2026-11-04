#!/usr/bin/env bash
# Installs and starts the kite controller. Run as root, from inside
# the unzipped kite-controller/ directory, on a fresh Rocky 8/9 VM.
#
#   sudo ./controller-install.sh
#
# Idempotent-ish: safe to re-run if something fails partway — it won't
# clobber an existing .env, and re-running just re-syncs files/deps.
set -euo pipefail

INSTALL_DIR=/opt/kite-controller
SERVICE_USER=kite
PORT=8000
HTTPS_PORT=443

# Optional: a real DNS name for automatic, browser-trusted Let's Encrypt
# certificates. Pass  --domain kite.example.com  (or set
# KITE_DOMAIN). Leave it unset for the zero-config default — Caddy's
# own local CA issues a self-signed cert that works by IP or name with no
# DNS at all (browsers and agents then skip verification; see the notes
# printed at the end).
DOMAIN="${KITE_DOMAIN:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2;;
    --domain=*) DOMAIN="${1#*=}"; shift;;
    -h|--help) echo "Usage: sudo ./controller-install.sh [--domain kite.example.com]"; exit 0;;
    *) echo "Unknown argument: $1 (try --help)" >&2; exit 1;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo ./controller-install.sh)." >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$HERE/app/main.py" ]]; then
  echo "Run this from inside the unzipped kite-controller/ directory." >&2
  exit 1
fi

echo "== Installing OS packages =="
# gnupg2 / rpm-sign / createrepo_c: the controller signs its agent repo (app/repo_signing.py)
dnf install -y python3 python3-pip firewalld gnupg2 rpm-sign createrepo_c >/dev/null

# The controller needs Python 3.9+. EL9's python3 is 3.9; EL8's is 3.6,
# so there a newer one is installed beside it from AppStream.
python_ok() { "$1" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; }
PYTHON=""
for candidate in python3.12 python3.11 python3.9 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && python_ok "$candidate"; then
    PYTHON="$(command -v "$candidate")"; break
  fi
done
if [[ -z "$PYTHON" ]]; then
  for pkg in python3.11 python3.12 python39; do
    if dnf install -y "$pkg" >/dev/null 2>&1; then
      for candidate in python3.12 python3.11 python3.9; do
        if command -v "$candidate" >/dev/null 2>&1 && python_ok "$candidate"; then
          PYTHON="$(command -v "$candidate")"; break 2
        fi
      done
    fi
  done
fi
if [[ -z "$PYTHON" ]]; then
  echo "kite needs Python 3.9 or newer, and none could be installed (tried python3.11, python3.12, python39)." >&2
  exit 1
fi
echo "  using $("$PYTHON" --version 2>&1) ($PYTHON)"

echo "== Installing Caddy (TLS reverse proxy) =="
if ! command -v caddy >/dev/null 2>&1; then
  dnf install -y 'dnf-command(copr)' >/dev/null
  dnf copr enable -y @caddy/caddy >/dev/null
  dnf install -y caddy >/dev/null
fi

echo "== Creating service user =="
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$INSTALL_DIR" --shell /sbin/nologin "$SERVICE_USER"
fi

echo "== Copying project files =="
mkdir -p "$INSTALL_DIR"
# Dotfiles too (.env.example etc). Never what a controller makes for
# itself at run time -- when run from a checkout that has been used
# (tests, a dev server), those are that checkout's, and copied over an
# installed controller they would replace its database, secrets and
# repo signing key.
tar -C "$HERE" -cf - \
    --exclude='./.env' --exclude='*.db' --exclude='*.db-wal' --exclude='*.db-shm' --exclude='*.db-journal' \
    --exclude='./secret_key' --exclude='./enroll_secret' --exclude='./signing' --exclude='./backups' \
    --exclude='./venv' --exclude='__pycache__' --exclude='./.pytest_cache' --exclude='./.ruff_cache' . \
  | tar -C "$INSTALL_DIR" -xf -

# Make sure the controller can hand out every agent, so hosts pull them
# from THIS controller and never from GitHub. A release tarball already
# ships them prebuilt in dist/ and repo/. A source checkout — where
# agent-windows/ and agent-linux/ sit beside controller/ — builds and
# stages them here, and on every later run (an upgrade) rebuilds any
# whose version changed, so enrolled agents can update themselves to it.
echo "== Agents the controller will serve =="
SRC_ROOT="$(cd "$HERE/.." && pwd)"
mkdir -p "$INSTALL_DIR/dist" "$INSTALL_DIR/repo"
LINUX_VER="$(grep -oP '^AGENT_VERSION = "\K[^"]+' "$SRC_ROOT/agent-linux/agent.py" 2>/dev/null || true)"
WIN_VER="$(grep -oP 'AgentVersion = "\K[^"]+' "$SRC_ROOT/agent-windows/internal/agent/agent.go" 2>/dev/null || true)"

# Debian/Ubuntu: a source bundle, no compiler needed.
if [[ -n "$LINUX_VER" ]]; then
  have="$(tar -xzOf "$INSTALL_DIR/dist/kite-agent-linux.tar.gz" agent-linux/agent.py 2>/dev/null \
          | grep -oP '^AGENT_VERSION = "\K[^"]+' || true)"
  if [[ "$have" == "$LINUX_VER" ]]; then
    echo "  Debian/Ubuntu: $have, current"
  elif bash "$SRC_ROOT/agent-linux/packaging/bundle.sh" "$INSTALL_DIR/dist" >/dev/null 2>&1; then
    echo "  Debian/Ubuntu: bundled $LINUX_VER${have:+ (was $have)}"
  else
    echo "  Debian/Ubuntu: could not bundle"
  fi
fi

# RHEL/Rocky: the RPM + dnf metadata. Cheap to build on this (Rocky) box.
if [[ -n "$LINUX_VER" ]]; then
  if ls "$INSTALL_DIR"/repo/kite-agent-"$LINUX_VER"-*.rpm >/dev/null 2>&1; then
    echo "  RHEL/Rocky: $LINUX_VER, current"
  else
    dnf install -y rpm-build createrepo_c >/dev/null 2>&1 || true
    if command -v rpmbuild >/dev/null 2>&1 \
       && OUT="$INSTALL_DIR/repo" bash "$SRC_ROOT/agent-linux/packaging/build.sh" >/dev/null 2>&1; then
      command -v createrepo_c >/dev/null 2>&1 && createrepo_c --update "$INSTALL_DIR/repo" >/dev/null 2>&1 || true
      echo "  RHEL/Rocky: RPM $LINUX_VER built and published to /repo"
    else
      echo "  RHEL/Rocky: RPM not built (needs rpm-build) — or use a release tarball"
    fi
  fi
fi

# Windows: cross-compiled with Go. Built when Go is already present; not
# installed automatically (it is a large dependency most controllers do
# not otherwise need — a release tarball ships the .exe prebuilt).
if [[ -n "$WIN_VER" ]]; then
  have="$(cat "$INSTALL_DIR/dist/kite-agent.exe.version" 2>/dev/null || true)"
  if [[ "$have" == "$WIN_VER" ]]; then
    echo "  Windows: $have, current"
  elif command -v go >/dev/null 2>&1 \
       && OUT="$INSTALL_DIR/dist" bash "$SRC_ROOT/agent-windows/build.sh" >/dev/null 2>&1; then
    echo "  Windows: agent $WIN_VER built${have:+ (was $have)}"
  else
    echo "  Windows: not built (needs Go 1.23+)${have:+ — still serving $have, source is $WIN_VER} — install Go and re-run, or use a release tarball"
  fi
fi

echo "== Python environment =="
# A venv made by an earlier install with too old a Python is replaced.
if [[ -d "$INSTALL_DIR/venv" ]] && ! python_ok "$INSTALL_DIR/venv/bin/python"; then
  echo "  replacing the existing venv: its Python is older than 3.9"
  rm -rf "$INSTALL_DIR/venv"
fi
if [[ ! -d "$INSTALL_DIR/venv" ]]; then
  "$PYTHON" -m venv "$INSTALL_DIR/venv"
fi
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

echo "== Config =="
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
  cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
  echo "  wrote fresh .env from .env.example — PROXMOX_* left blank, fill in"
  echo "  when you're ready to enable real snapshots (see README)."
  echo "  KITE_ENROLL_SECRET left blank on purpose — the controller"
  echo "  auto-generates one at startup if unset; pin one in .env once"
  echo "  you're actually onboarding hosts (see the banner it prints)."
else
  echo "  .env already exists — leaving it alone."
fi

echo "== Ownership =="
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
# Secrets and the database (password hashes, the encrypted Proxmox token,
# agent credentials) are the service's alone. The unit's UMask covers
# what it creates from now on; this covers what already exists.
chmod 600 "$INSTALL_DIR/.env" 2>/dev/null || true
chmod 600 "$INSTALL_DIR"/*.db "$INSTALL_DIR"/*.db-wal "$INSTALL_DIR"/*.db-shm 2>/dev/null || true

echo "== systemd service =="
UNIT=/etc/systemd/system/kite-controller.service
DROPIN_DIR=/etc/systemd/system/kite-controller.service.d
# The unit is replaced on every run so upgrades reach it. Credentials
# turned on by uncommenting LoadCredential= in it are kept: moved to a
# drop-in, which is where local changes belong (systemctl edit).
if [[ -f "$UNIT" ]] && grep -q '^LoadCredential=' "$UNIT" && [[ ! -f "$DROPIN_DIR/credentials.conf" ]]; then
  mkdir -p "$DROPIN_DIR"
  { echo "[Service]"; grep '^LoadCredential=' "$UNIT"; } > "$DROPIN_DIR/credentials.conf"
  echo "  kept your LoadCredential= lines in $DROPIN_DIR/credentials.conf"
fi
cp "$INSTALL_DIR/kite-controller.service" "$UNIT"
systemctl daemon-reload
systemctl enable kite-controller >/dev/null
# `restart`, not `enable --now`. On a fresh install the service isn't
# running yet, so this simply starts it. On an upgrade the service is
# already active, and `systemctl start` on an active unit is a no-op:
# the upgrade would appear to succeed while the old code kept running
# from memory, however many new files had just been copied to disk.
systemctl restart kite-controller

echo "== TLS reverse proxy (Caddy) =="
if [[ -n "$DOMAIN" ]]; then
  # A real domain was given — write a Caddyfile that fetches and renews a
  # browser-trusted Let's Encrypt certificate automatically. Regenerated
  # on every run so re-running with a new --domain takes effect (and so
  # switching away from the self-signed default actually replaces it).
  echo "  configuring automatic Let's Encrypt TLS for ${DOMAIN}"
  echo "  (this host must be reachable from the internet on 80 and 443,"
  echo "   and ${DOMAIN} must already resolve to it)"
  cat > /etc/caddy/Caddyfile <<EOF
# Generated by controller-install.sh --domain ${DOMAIN}
# Caddy obtains and renews a browser-trusted Let's Encrypt certificate
# automatically, and redirects http://${DOMAIN} -> https itself.
${DOMAIN} {
	reverse_proxy 127.0.0.1:${PORT}
}
EOF
elif [[ ! -f /etc/caddy/Caddyfile ]] || ! grep -q "127.0.0.1:${PORT}" /etc/caddy/Caddyfile 2>/dev/null; then
  cp "$INSTALL_DIR/Caddyfile" /etc/caddy/Caddyfile
else
  echo "  /etc/caddy/Caddyfile already configured for this controller — leaving it alone"
  echo "  (re-run with --domain kite.example.com to switch to trusted Let's Encrypt TLS)"
fi
systemctl enable --now caddy >/dev/null
systemctl reload caddy 2>/dev/null || systemctl restart caddy

echo "== Firewall =="
systemctl enable --now firewalld >/dev/null 2>&1 || true
# uvicorn binds 127.0.0.1 only (see kite-controller.service), so port
# 8000 is never exposed and doesn't need closing — Caddy on 443 is the
# only public listener. With a real domain, 80 is opened too: Let's
# Encrypt's HTTP-01 challenge needs it, and Caddy then redirects 80 -> 443.
if [[ -n "$DOMAIN" ]]; then
  firewall-cmd --permanent --add-port=80/tcp >/dev/null
fi
firewall-cmd --permanent --add-port=${HTTPS_PORT}/tcp >/dev/null
firewall-cmd --reload >/dev/null

echo "== Waiting for it to come up =="
# Poll the backend directly: it always answers plain HTTP on loopback,
# whether TLS out front is the self-signed default or a real-domain cert
# (for which "localhost" wouldn't match anyway).
for i in $(seq 1 20); do
  if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/health" 2>/dev/null; then
    break
  fi
  sleep 0.5
done

echo
echo "== Done =="
curl -sf "http://127.0.0.1:${PORT}/health" && echo

# Whether this install can actually hand out agents yet. A release
# tarball ships both already built; a plain source checkout ships
# neither (they are build artifacts, not committed) and the console will
# say so on the Enroll tabs.
echo "== Agents =="
if [[ -f "$INSTALL_DIR/dist/kite-agent-setup.exe" ]]; then
  echo "  Windows: ready — console → Enroll → Windows serves the installer"
else
  echo "  Windows: not in this build. Install from a release tarball, or run"
  echo "           agent-windows/build.sh (needs Go 1.23+) to build it here."
fi
if compgen -G "$INSTALL_DIR/repo/*.rpm" >/dev/null; then
  signed="unsigned (agents use gpgcheck=0)"
  [[ -f "$INSTALL_DIR/repo/RPM-GPG-KEY-kite" ]] && signed="signed (import /repo/RPM-GPG-KEY-kite, gpgcheck=1)"
  echo "  Linux:   ready — dnf repo at /repo, $signed"
else
  echo "  Linux:   not in this build. Install from a release tarball, or run"
  echo "           agent-linux/packaging/build.sh (needs rpmbuild) to build it here."
fi

if [[ -n "$DOMAIN" ]]; then
  echo "Console: https://${DOMAIN}/"
  echo "  (browser-trusted Let's Encrypt certificate — no warnings, no -k needed."
  echo "  The first request can take a few seconds while Caddy fetches the cert.)"
  echo "Repo (for agent installs): https://${DOMAIN}/repo"
else
  IP=$(hostname -I | awk '{print $1}')
  echo "Console: https://${IP}/"
  echo "  (self-signed cert by default — your browser will warn on first visit;"
  echo "  that's expected, not broken. Re-run with --domain to switch to a"
  echo "  browser-trusted Let's Encrypt certificate.)"
  echo "Repo (for agent installs): https://${IP}/repo"
  echo "  (agents check the controller's own CA, after checking its fingerprint:"
  echo "  console → Add machine shows it — see README.md's 'certificate authority')"
fi
echo
echo "Check the startup log for your login credentials and enrollment secret"
echo "(both are auto-generated and printed once, on first startup):"
echo "  journalctl -u kite-controller -n 60 --no-pager | grep -B1 -A5 'KITE_ENROLL_SECRET\|ADMIN LOGIN'"
