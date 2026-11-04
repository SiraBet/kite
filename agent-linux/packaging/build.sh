#!/usr/bin/env bash
# Builds the kite-agent RPM. Needs rpm-build (`dnf install -y
# rpm-build`); any RHEL-family host will do.
#
#   bash packaging/build.sh                 # RPM lands in packaging/out/
#   OUT=/some/dir bash packaging/build.sh   # ...or there
#
# Built in a throwaway directory, never inside this checkout: a build run
# once as root used to leave a root-owned rpmbuild/ tree here that broke
# every later build as a normal user, and an old RPM left in it could be
# picked up as the new one.
#
# One RPM for every RHEL-family release: no dist tag (.el9) in the name,
# and an xz payload rather than the zstd that EL9's rpmbuild defaults to,
# which EL8's rpm can't read.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../agent-linux/packaging
PARENT="$(dirname "$HERE")"                              # .../agent-linux
OUT="${OUT:-$HERE/out}"
TOPDIR="$(mktemp -d)"
trap 'rm -rf "$TOPDIR"' EXIT

mkdir -p "$TOPDIR"/{SPECS,SOURCES,BUILD,RPMS,SRPMS,BUILDROOT} "$OUT"
cp "$HERE/kite-agent.spec" "$TOPDIR/SPECS/"
cp "$PARENT/agent.py" "$PARENT/enroll.py" "$PARENT/kite-agent.service" "$TOPDIR/SOURCES/"

if ! rpmbuild --define "_topdir $TOPDIR" --define "dist %{nil}" --define "_binary_payload w2.xzdio" \
     -bb "$TOPDIR/SPECS/kite-agent.spec" >"$TOPDIR/build.log" 2>&1; then
  cat "$TOPDIR/build.log" >&2
  exit 1
fi

built=()
for rpm in "$TOPDIR"/RPMS/*/*.rpm; do
  cp "$rpm" "$OUT/"
  built+=("$OUT/$(basename "$rpm")")
done

# Signing here is optional: the controller signs every RPM in its repo
# itself (controller/app/repo_signing.py). This only applies when
# ~/.rpmmacros names a key of your own.
if [ -f "$HOME/.rpmmacros" ] && grep -q "^%_gpg_name" "$HOME/.rpmmacros"; then
  echo "== Signing =="
  rpm --addsign "${built[@]}"
else
  echo "Not signed here — the controller signs it when it's in its repo."
fi
printf '%s\n' "${built[@]}"
