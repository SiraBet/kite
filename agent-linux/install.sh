#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR=/opt/kite-agent
CONF_DIR=/etc/kite
STATE_DIR=/var/lib/kite

if [[ $EUID -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

echo "== Installing OS packages =="
dnf install -y python3 python3-pip dnf-utils

# Package name for the versionlock plugin differs across Rocky 8 / Rocky 9
# repo layouts — try both known names.
if ! dnf install -y python3-dnf-plugin-versionlock 2>/dev/null; then
  if ! dnf install -y python3-dnf-plugins-extras-versionlock 2>/dev/null; then
    echo "WARNING: could not install a versionlock plugin package under either known name."
    echo "Check 'dnf list available | grep versionlock' on this host — pin"
    echo "definitions will fail at the 'excludes' stage until this works."
  fi
fi

pip3 install --quiet requests

echo "== Installing agent files =="
mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$STATE_DIR"
cp agent.py enroll.py "$INSTALL_DIR"/
cp kite-agent.service /etc/systemd/system/kite-agent.service
chmod 700 "$CONF_DIR" "$STATE_DIR"
systemctl daemon-reload

echo
echo "== Done. Next steps =="
echo "With the controller's default self-signed cert, add the console's"
echo "--ca-fingerprint <sha256> to enroll.py below (Add machine): it checks"
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
