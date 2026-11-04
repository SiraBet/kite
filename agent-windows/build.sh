#!/usr/bin/env bash
#
# Build the Windows agent and its installer, and place them where the
# controller serves them.
#
# Cross-compiles from any platform Go runs on -- there is no cgo in
# either binary, so a Linux controller produces the Windows programs it
# hands out without a Windows machine anywhere in the loop.
#
#   ./build.sh              -> ../controller/dist/
#   OUT=/tmp ./build.sh     -> /tmp/
set -euo pipefail

cd "$(dirname "$0")"
OUT="${OUT:-../controller/dist}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# Built from a throwaway copy, never inside this checkout: the installer
# embeds the agent from internal/installer/payload/, and a build run once
# as root used to leave a root-owned payload there that broke every later
# build as a normal user.
SRC="$(pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -r "$SRC/." "$WORK/"
rm -f "$WORK"/internal/installer/payload/*.gz
cd "$WORK"

if ! command -v go >/dev/null 2>&1; then
    echo "go is not installed. The controller serves whatever binaries are in" >&2
    echo "$OUT; build them on any machine with Go 1.23+ and copy them there." >&2
    exit 1
fi

version="$(grep -oP 'AgentVersion = "\K[^"]+' internal/agent/agent.go)"

# The .syso files beside each main package carry the application
# manifests -- Common Controls 6 (without which the windows fall back to
# a Windows-95 look), per-monitor DPI, and the installer's request for
# elevation -- and the kite icon (assets/kite.ico). They are committed
# rather than generated here so a build needs nothing but Go; regenerate
# after editing a .manifest or the icon with, for each of kite-agent and
# kite-setup:
#
#   go install github.com/akavel/rsrc@v0.10.2
#   rsrc -manifest cmd/kite-agent/kite-agent.manifest -ico assets/kite.ico \
#        -arch amd64 -o cmd/kite-agent/rsrc_windows_amd64.syso
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
# -trimpath keeps build-machine paths out of the binary; -s -w drops the
# symbol and DWARF tables. -H windowsgui links for the GUI subsystem so a
# double-click opens a window with no console flashing up behind it --
# the CLI still prints, see internal/console.
LDFLAGS="-s -w -H windowsgui"

echo "building kite-agent ${version} for windows/amd64"
go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/kite-agent.exe" ./cmd/kite-agent

# The installer carries the agent inside it, so the agent has to exist
# and be compressed before the installer is compiled. Getting this order
# wrong would silently ship an installer holding the previous build.
echo "packing the agent into the installer"
mkdir -p internal/installer/payload
gzip -9 -c "$OUT/kite-agent.exe" > internal/installer/payload/kite-agent.exe.gz

echo "building kite-agent-setup ${version} for windows/amd64"
go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/kite-agent-setup.exe" ./cmd/kite-setup

# Checksums beside the binaries, so someone copying one onto a host by
# hand can confirm it arrived intact. The controller serves these too.
( cd "$OUT" && sha256sum kite-agent.exe > kite-agent.exe.sha256 \
             && sha256sum kite-agent-setup.exe > kite-agent-setup.exe.sha256 )
# The version beside the agent, so the controller knows which build it
# serves -- what Windows agents updating themselves from the console ask for.
echo "$version" > "$OUT/kite-agent.exe.version"

for f in kite-agent.exe kite-agent-setup.exe; do
    printf 'wrote %s (%s)\n' "$OUT/$f" "$(du -h "$OUT/$f" | cut -f1)"
done
