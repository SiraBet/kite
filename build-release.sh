#!/usr/bin/env bash
#
# Build a complete, self-contained kite-controller release: the
# controller plus BOTH agents already built and ready to hand out, so a
# user's install finishes with working Windows and Linux agents and no
# build step (no Go, no rpmbuild) on their controller.
#
#   VERSION=0.2.0 ./build-release.sh
#   ./build-release.sh v0.2.0            # leading v is stripped
#
# Produces, under ./release-dist/ :
#   kite-controller-<ver>.tar.gz            the thing users download
#   kite-controller-<ver>.tar.gz.sha256
#   kite-agent.exe / kite-agent-setup.exe (+ .sha256)   raw Windows assets
#   kite-agent-<rpmver>.noarch.rpm           raw Linux asset
#
# The tarball contains controller/ with dist/ (Windows binaries) and
# repo/ (the RPM + createrepo metadata) already populated. Unzip it and
# run controller/controller-install.sh — that's the whole install.
#
# The RPM is not signed here: every controller makes its own signing key
# on first start and signs its repo with it (controller/app/repo_signing.py),
# and agents trust that controller's key. A release-wide key would be
# one more secret to guard, and agents would have no use for it.
#
# Tools: go >=1.23, rpmbuild, createrepo_c. This is the single source of
# truth the release workflow runs; a maintainer can also run it locally
# on a Rocky host with those tools.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VERSION="${VERSION:-${1:-}}"
VERSION="${VERSION#v}"
if [[ -z "$VERSION" ]]; then
  echo "VERSION is required (e.g. VERSION=0.2.0 $0, or $0 v0.2.0)" >&2
  exit 1
fi

OUT="$HERE/release-dist"
STAGE_NAME="kite-controller-$VERSION"
STAGE="$OUT/$STAGE_NAME"
TARBALL="$OUT/$STAGE_NAME.tar.gz"

need() { command -v "$1" >/dev/null 2>&1 || { echo "required tool not found: $1" >&2; exit 1; }; }
need go; need rpmbuild; need createrepo_c; need tar

rm -rf "$OUT"
mkdir -p "$OUT" "$STAGE/dist" "$STAGE/repo"

# ---- controller tree (no dev/runtime cruft, no live secrets/data) ----
echo "== Assembling controller tree =="
cp -r "$HERE/controller/." "$STAGE/"
# Never ship a live database, real .env, generated secrets, caches, or a
# stale prebuilt tree — the release must carry only what we build below.
rm -rf "$STAGE/dist" "$STAGE/repo"
mkdir -p "$STAGE/dist" "$STAGE/repo"
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -f "$STAGE"/.env "$STAGE"/*.db "$STAGE"/*.db-* "$STAGE"/secret_key "$STAGE"/enroll_secret \
      "$STAGE"/controller-ca.crt 2>/dev/null || true
# The repo signing key and the database backups of whoever built this.
rm -rf "$STAGE/signing" "$STAGE/backups" "$STAGE/venv" "$STAGE/.pytest_cache" "$STAGE/.ruff_cache"

# ---- Windows agent (+ installer) ----
echo "== Building Windows agent =="
OUT="$STAGE/dist" bash "$HERE/agent-windows/build.sh"

# ---- Debian/Ubuntu agent bundle ----
# No compiled binary — the controller hands out the source bundle and the
# Ubuntu/Debian enrol command fetches it (see routers/downloads.py), so a
# host installs without cloning the repository.
echo "== Bundling the Debian/Ubuntu agent =="
bash "$HERE/agent-linux/packaging/bundle.sh" "$STAGE/dist"

# ---- Linux agent RPM ----
echo "== Building Linux agent RPM =="
OUT="$STAGE/repo" bash "$HERE/agent-linux/packaging/build.sh"
compgen -G "$STAGE/repo/*.rpm" >/dev/null || { echo "RPM build produced no .rpm" >&2; exit 1; }

# ---- Repo metadata ----
# Unsigned: the controller signs its repo with its own key on first start.
createrepo_c --update "$STAGE/repo" >/dev/null

# ---- Package + checksums ----
echo "== Packaging =="
tar -C "$OUT" -czf "$TARBALL" "$STAGE_NAME"
( cd "$OUT" && sha256sum "$STAGE_NAME.tar.gz" > "$STAGE_NAME.tar.gz.sha256" )
# Raw assets for direct download / hand-placement, each checksummed.
cp "$STAGE"/dist/kite-agent.exe "$STAGE"/dist/kite-agent-setup.exe "$STAGE"/dist/*.sha256 "$OUT/"
for r in "$STAGE"/repo/*.rpm; do
  cp "$r" "$OUT/"
  ( cd "$OUT" && sha256sum "$(basename "$r")" > "$(basename "$r").sha256" )
done

echo
echo "== Done — release-dist/ =="
ls -1 "$OUT"
echo
echo "RPM repo: unsigned here; each controller signs it with its own key on first start"
echo "Tarball: $TARBALL"
