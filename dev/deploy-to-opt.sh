#!/bin/bash
# DEVELOPER shortcut — NOT the install path. Deploys the current checkout
# to the systemd install at /opt and exposes it on plain-HTTP
# 0.0.0.0:8000 (no Caddy, no TLS) so an agent on another machine can
# reach it while iterating. Enrollment secrets and agent credentials
# cross the network in the clear on this path.
#
#   sudo dev/deploy-to-opt.sh        (from the repo root)
#
# For a real install use controller/controller-install.sh instead: it
# puts Caddy in front with TLS on 443 (self-signed by default, or
# --domain for Let's Encrypt) and binds uvicorn to localhost. See
# controller/INSTALL.md.
#
# Leaves alone: the database, .env, and repo/ (your agent RPM).
# Schema migrations run automatically on startup and take a timestamped
# copy of the database first.
set -euo pipefail

# This script lives in dev/, so the checkout root is one level up.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/controller"
DST=/opt/kite-controller
USER=kite

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
[[ -f "$SRC/app/main.py" ]] || { echo "Cannot find controller/ in $REPO_ROOT -- run this from a checkout" >&2; exit 1; }

echo "== Stopping the service =="
systemctl stop kite-controller || true

echo "== Backing up the database (independent of the automatic one) =="
if [[ -f "$DST/kite.db" ]]; then
  sudo -u "$USER" python3 -c "
import sqlite3, datetime
src = sqlite3.connect('$DST/kite.db')
name = '$DST/kite.manual-backup-%s.db' % datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
dst = sqlite3.connect(name); src.backup(dst); dst.close(); src.close()
print('   ->', name)"
fi

echo "== Building the Windows agent =="
# Built here so the console can hand it out -- a controller with no
# binary in dist/ tells you it has not been built, which is accurate but
# a step you would rather not have to take. Skipped without complaint if
# Go is not installed: everything else still deploys.
AGENT_SRC="$REPO_ROOT/agent-windows"
# sudo resets PATH, so a Go installed under a user's home is not on it
# here even though it was when the checkout was built. Look in the usual
# places, then fall back to whatever build.sh already produced.
GO_PATH="$PATH:/usr/local/go/bin:${SUDO_USER:+/home/$SUDO_USER/go-toolchain/bin}"
if PATH="$GO_PATH" command -v go >/dev/null 2>&1; then
  PATH="$GO_PATH" bash "$AGENT_SRC/build.sh" || echo "   build failed -- deploying whatever is already in dist/"
elif [[ -f "$SRC/dist/kite-agent.exe" ]]; then
  echo "   go not found; deploying the existing build in controller/dist/"
else
  echo "   go not found and nothing built; the console will say so and show the build command"
fi

echo "== Copying code =="
for item in app frontend migrations tools alembic.ini requirements.txt pytest.ini; do
  rm -rf "${DST:?}/$item"
  cp -r "$SRC/$item" "$DST/$item"
done
if [[ -d "$SRC/dist" ]]; then
  rm -rf "${DST:?}/dist"
  cp -r "$SRC/dist" "$DST/dist"
fi
find "$DST" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
chown -R "$USER:$USER" "$DST"

echo "== Python dependencies =="
"$DST/venv/bin/pip" install --quiet --upgrade pip
"$DST/venv/bin/pip" install --quiet -r "$DST/requirements.txt"

echo "== Listening on all interfaces (drop-in, shipped unit untouched) =="
mkdir -p /etc/systemd/system/kite-controller.service.d
cat > /etc/systemd/system/kite-controller.service.d/override.conf <<'EOF'
# Plain HTTP on every interface, so an agent on another machine can
# reach the controller without Caddy in front. There is no TLS on this
# path: enrollment secrets and agent credentials cross the network in
# the clear. Fine on a trusted lab network; put Caddy in front (443)
# before this leaves one.
[Service]
ExecStart=
ExecStart=/opt/kite-controller/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
EOF
systemctl daemon-reload

echo "== Firewall =="
firewall-cmd --permanent --add-port=8000/tcp >/dev/null 2>&1 || true
firewall-cmd --reload >/dev/null 2>&1 || true

echo "== Starting =="
systemctl start kite-controller
for _ in $(seq 1 30); do
  curl -sf -o /dev/null http://127.0.0.1:8000/health && break
  sleep 1
done

echo
echo "== Result =="
echo "  ⚠  PLAIN HTTP on :8000 — no TLS on this dev path. Traffic (including"
echo "     enrollment secrets and agent credentials) is unencrypted. Use"
echo "     controller/controller-install.sh for a real, TLS-terminated install."
systemctl is-active kite-controller | sed 's/^/  service: /'
ss -ltn | grep ':8000' | sed 's/^/  listening: /'
curl -s http://127.0.0.1:8000/health | sed 's/^/  health: /'; echo
echo "  migrations:"
journalctl -u kite-controller --since "2 min ago" --no-pager \
  | grep -E "alembic|schema_migration_pending" | tail -4 | sed 's/^/    /' || echo "    (none — already current)"
IP=$(hostname -I | awk '{print $1}')
echo
echo "  Console:    http://$IP:8000/"
echo "  Agents use: http://$IP:8000"
if [[ -f "$DST/dist/kite-agent.exe" ]]; then
  echo "  Windows agent: http://$IP:8000/download/agent/windows"
else
  echo "  Windows agent: not built -- run agent-windows/build.sh and re-run this script"
fi
