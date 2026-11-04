#!/bin/bash
# 'preflight' stage script — Rocky Linux 8 (os_family: rocky8).
#
# Derived from ../rhel-family/preflight.sh, with the checks that actually
# differ on EL8 split out into the "EL8-specific" block below. If you run a
# mixed EL8 estate (rhel8, alma8, ol8, centos8) the same content works —
# upload it once per exact os_family string.
#
# Only genuinely blocking conditions exit non-zero. Everything else is a
# warning that still lets the job proceed to 'excludes'/'patch', because a
# maintenance window spent on a host that was never going to patch is the
# thing this stage exists to prevent.
#
# Tunables (set via a systemd drop-in on the agent unit, e.g.
# /etc/systemd/system/kite-agent.service.d/override.conf):
#   KITE_MIN_ROOT_FREE_MB (default 1024)
#   KITE_MIN_BOOT_FREE_MB (default 200)   - #1 cause of a kernel install
#                                               failing half way through
#   KITE_MIN_VAR_FREE_MB  (default 1024)  - dnf cache + logs live here
#
# Contract: exit 0 = stage done, anything else = stage failed. Combined
# stdout+stderr is captured (last 4000 chars) as the stage output, so keep
# what you print terse. Env: KITE_JOB_ID, KITE_HOSTNAME,
# KITE_STAGE, KITE_EXCLUDES, KITE_PINS.

set -uo pipefail

EXPECTED_EL_MAJOR=8
NEEDS_RESTARTING_PKG="dnf-utils"   # EL9 moved this into dnf-plugins-core

MIN_ROOT_FREE_MB="${KITE_MIN_ROOT_FREE_MB:-1024}"
MIN_BOOT_FREE_MB="${KITE_MIN_BOOT_FREE_MB:-200}"
MIN_VAR_FREE_MB="${KITE_MIN_VAR_FREE_MB:-1024}"

fail=0
notes=()
note()     { notes+=("$1"); echo "$1"; }
blocking() { notes+=("BLOCKING: $1"); echo "BLOCKING: $1"; fail=1; }

echo "== preflight (rocky8): ${KITE_HOSTNAME:-unknown} (job ${KITE_JOB_ID:-?}) =="

# --- must be root (the agent always is; a hand-run copy might not be) ---
[ "$(id -u)" -ne 0 ] && blocking "not running as root"

# ---------------------------------------------------------------- EL8-specific
# Guard against a mis-tagged os_family. kite picks this script purely by
# the host's reported os_family string, so a host mislabelled rocky8 while
# actually running EL9 would silently get the wrong assumptions below.
el_major=""
if [ -r /etc/os-release ]; then
    el_major=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID%%.*}")
fi
if [ -n "$el_major" ] && [ "$el_major" != "$EXPECTED_EL_MAJOR" ]; then
    blocking "host reports EL${el_major} but is tagged os_family=rocky8 — fix the host's os_family before patching"
else
    note "EL major version: ${el_major:-unknown} (expected $EXPECTED_EL_MAJOR)"
fi

# 8.10 is the final minor release of the EL8 stream (maintenance support to
# 2029-05-31). Anything below it is missing a whole minor's worth of fixes.
minor=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID#*.}")
if [ -n "${minor:-}" ] && [ "${minor:-0}" -lt 10 ] 2>/dev/null; then
    note "running 8.${minor} — 8.10 is the final EL8 minor; this host is behind a minor release, expect a large transaction"
fi
# ------------------------------------------------------------ end EL8-specific

# --- disk space: /, /boot, /var ---
check_free_mb() {
    local path="$1" min="$2" label="$3" avail
    [ -d "$path" ] || { note "skip disk check for $label ($path absent)"; return; }
    avail=$(df --output=avail -BM "$path" 2>/dev/null | tail -1 | tr -dc '0-9')
    [ -z "$avail" ] && { note "could not read free space for $label"; return; }
    if [ "$avail" -lt "$min" ]; then
        blocking "$label has only ${avail}MB free, need ${min}MB"
    else
        note "$label: ${avail}MB free (min ${min}MB) - ok"
    fi
}
check_free_mb "/"     "$MIN_ROOT_FREE_MB" "/"
check_free_mb "/boot" "$MIN_BOOT_FREE_MB" "/boot"
check_free_mb "/var"  "$MIN_VAR_FREE_MB"  "/var"

# --- is the package manager already busy? ---
if pgrep -x dnf >/dev/null 2>&1 || pgrep -x yum >/dev/null 2>&1 || pgrep -x microdnf >/dev/null 2>&1; then
    blocking "another dnf/yum process is already running on this host"
fi
if pgrep -x packagekitd >/dev/null 2>&1; then
    note "PackageKit is running and can grab the rpm lock mid-transaction — consider masking packagekit on servers"
fi
if [ -f /var/lib/rpm/.rpm.lock ] && fuser /var/lib/rpm/.rpm.lock >/dev/null 2>&1; then
    blocking "rpm db lock is held by another process"
fi

command -v dnf >/dev/null 2>&1 || blocking "dnf not found on PATH - not a dnf-based host?"

# --- was a previous transaction left half-finished? ---
if command -v dnf >/dev/null 2>&1; then
    last_tx=$(dnf history list 2>/dev/null | awk 'NR==4{print $NF}')
    case "$last_tx" in
        Aborted|Failed) note "last dnf transaction ended '$last_tx' - proceeding, but worth a look" ;;
    esac
fi

# --- repo metadata reachable ---
mc_out=$(dnf -C check-update 2>&1); mc_rc=$?
# rc=100 means updates ARE available, which is success, not failure.
if [ $mc_rc -ne 0 ] && [ $mc_rc -ne 100 ]; then
    blocking "dnf check-update failed (rc=$mc_rc): $(echo "$mc_out" | tail -3 | tr '\n' ' ')"
fi

# --- unregistered RHEL hosts have no repos to pull from ---
if command -v subscription-manager >/dev/null 2>&1; then
    subscription-manager status >/dev/null 2>&1 || \
        note "subscription-manager present but host is not registered/entitled - dnf may have no repos"
fi

# --- how much work is 'patch' about to do ---
if command -v dnf >/dev/null 2>&1; then
    update_count=$(dnf -C check-update 2>/dev/null | grep -cE '^\S+\.(x86_64|noarch|i686|aarch64)\s')
    note "packages with updates available: ${update_count:-0}"
    sec=$(dnf -C updateinfo summary 2>/dev/null | grep -iE 'security|critical|important' | tr '\n' ' ')
    [ -n "$sec" ] && note "security summary: $sec"
fi

# --- reboot already outstanding before we start? ---
if command -v needs-restarting >/dev/null 2>&1; then
    needs-restarting -r >/dev/null 2>&1 || \
        note "host already needs a reboot from a prior change - the 'reboot' stage will handle it"
else
    note "needs-restarting not installed (dnf install -y $NEEDS_RESTARTING_PKG) - cannot tell if a reboot is already pending"
fi

echo "== preflight summary =="
printf '%s\n' "${notes[@]}"
if [ "$fail" -ne 0 ]; then
    echo "preflight FAILED - see BLOCKING lines above"
    exit 1
fi
echo "preflight OK"
exit 0
