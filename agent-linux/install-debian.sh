#!/usr/bin/env bash
set -euo pipefail

# Debian/Ubuntu counterpart to install.sh (RHEL-family) -- same agent.py/
# enroll.py, same systemd unit, only the OS-package dependencies differ.
# agent.py itself detects apt vs dnf at runtime (see detect_package_manager
# in agent.py) and dispatches to the right stage handlers on its own.

INSTALL_DIR=/opt/kite-agent
CONF_DIR=/etc/kite
STATE_DIR=/var/lib/kite

if [[ $EUID -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

echo "== Installing OS packages =="
export DEBIAN_FRONTEND=noninteractive
apt-get update
# python3-requests from the distro repo, not pip -- newer Debian/Ubuntu
# (PEP 668, "externally managed environment") refuses a plain `pip3
# install` outside a venv by default, and there's no reason to fight that
# for one dependency this widely packaged.
apt-get install -y python3 python3-requests

echo "== Installing agent files =="
mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$STATE_DIR"
cp agent.py enroll.py "$INSTALL_DIR"/
cp kite-agent.service /etc/systemd/system/kite-agent.service
chmod 700 "$CONF_DIR" "$STATE_DIR"
systemctl daemon-reload

echo
echo "== Done. Next steps =="
echo "With the controller's default self-signed cert, add the console's"
echo "--ca-fingerprint <sha256> to enroll.py below (Enroll tab): it checks"
echo "the controller's CA and pins it. Not needed with a public certificate."
echo "Enroll with a per-host token (tightest scope):"
echo "  1. In the controller's console: Fleet → Add machine issues the token (and shows the full command)"
echo "  2. python3 $INSTALL_DIR/enroll.py --controller https://<control-vm> --token <token> --vmid <proxmox-vmid>"
echo ""
echo "...or with the controller's shared enrollment secret (recommended — one secret,"
echo "reusable across every host, see the controller's INSTALL.md):"
echo "  python3 $INSTALL_DIR/enroll.py --controller https://<control-vm> \\"
echo "    --secret <shared-secret> --hostname $(hostname) --team <team>"
echo ""
echo "Then: systemctl enable --now kite-agent && journalctl -u kite-agent -f"
