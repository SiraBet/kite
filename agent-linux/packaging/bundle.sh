#!/usr/bin/env bash
# Packs the agent as the Debian/Ubuntu bundle the controller hands out
# (dist/kite-agent-linux.tar.gz, fetched by the Ubuntu enrol
# command). Only what a host runs: no tests, caches or build output.
#
#   bash packaging/bundle.sh /path/to/dist
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$(dirname "$HERE")")"   # the directory holding agent-linux/
DEST="${1:?usage: bundle.sh <dist dir>}"
mkdir -p "$DEST"
tar -C "$ROOT" -czf "$DEST/kite-agent-linux.tar.gz" \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' --exclude='.ruff_cache' \
  --exclude='agent-linux/tests' --exclude='agent-linux/packaging/rpmbuild' --exclude='agent-linux/packaging/out' \
  --exclude='agent-linux/requirements-dev.txt' --exclude='agent-linux/pytest.ini' \
  agent-linux
echo "$DEST/kite-agent-linux.tar.gz"
