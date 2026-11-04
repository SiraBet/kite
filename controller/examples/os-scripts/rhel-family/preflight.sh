#!/bin/bash
# 'preflight' stage script for the RHEL/dnf family — RHEL, Rocky,
# AlmaLinux, Oracle Linux, CentOS Stream (8/9). Upload the same content
# under each os_family key you actually see hosts report (e.g. rocky8,
# rocky9, rhel8, rhel9, alma8, alma9, ol8, ol9) — one row per exact
# os_family string is required, the content can be identical.
#
# Goal: catch anything that would waste a maintenance window on a host
# that was doomed to fail before dnf ever ran, and surface a clear
# go/no-go summary in the Progress screen/audit log. Only genuinely
# blocking conditions exit non-zero; everything else is a warning that
# still lets the job proceed to 'excludes'/'patch'.
#
# Threshold env vars (set via a systemd drop-in on the agent unit if you
# want to tune per-fleet, e.g. /etc/systemd/system/kite-agent.service.d/
# override.conf — Environment=KITE_MIN_BOOT_FREE_MB=300):
#   KITE_MIN_ROOT_FREE_MB (default 1024)
#   KITE_MIN_BOOT_FREE_MB (default 200)   - the #1 cause of a kernel
#                                                install failing partway
#   KITE_MIN_VAR_FREE_MB  (default 1024)  - dnf cache + logs live here
#
# See patch.sh for the full KITE_* env var contract.

set -uo pipefail

MIN_ROOT_FREE_MB="${KITE_MIN_ROOT_FREE_MB:-1024}"
MIN_BOOT_FREE_MB="${KITE_MIN_BOOT_FREE_MB:-200}"
MIN_VAR_FREE_MB="${KITE_MIN_VAR_FREE_MB:-1024}"

fail=0
notes=()
note() { notes+=("$1"); echo "$1"; }
blocking() { notes+=("BLOCKING: $1"); echo "BLOCKING: $1"; fail=1; }

echo "== preflight: $KITE_HOSTNAME (job $KITE_JOB_ID) =="

# --- must be root (agent always runs as root, but a manually-run copy of
# this script for testing might not be) ---
if [ "$(id -u)" -ne 0 ]; then
  blocking "not running as root"
fi

# --- disk space: root, /boot, /var ---
check_free_mb() {
  local path="$1" min="$2" label="$3"
  if [ ! -d "$path" ]; then
    note "skip disk check for $label ($path not present as its own mount, folded into another check)"
    return
  fi
  local avail
  avail=$(df --output=avail -BM "$path" 2>/dev/null | tail -1 | tr -dc '0-9')
  if [ -z "$avail" ]; then
    note "could not read free space for $label ($path)"
    return
  fi
  if [ "$avail" -lt "$min" ]; then
    blocking "$label has only ${avail}MB free, need ${min}MB (df: $path)"
  else
    note "$label: ${avail}MB free (min ${min}MB) - ok"
  fi
}
check_free_mb "/" "$MIN_ROOT_FREE_MB" "/"
check_free_mb "/boot" "$MIN_BOOT_FREE_MB" "/boot"
check_free_mb "/var" "$MIN_VAR_FREE_MB" "/var"

# --- is dnf/rpm already busy with someone else's transaction? ---
if pgrep -x dnf >/dev/null 2>&1 || pgrep -x yum >/dev/null 2>&1 || pgrep -x microdnf >/dev/null 2>&1; then
  blocking "another dnf/yum process is already running on this host"
fi
if [ -f /var/lib/rpm/.rpm.lock ] && fuser /var/lib/rpm/.rpm.lock >/dev/null 2>&1; then
  blocking "rpm db lock is held by another process"
fi

# --- was a previous transaction left half-finished? ---
if command -v dnf >/dev/null 2>&1; then
  last_tx=$(dnf history list 2>/dev/null | awk 'NR==4{print $NF}')
  if [ "$last_tx" = "Aborted" ] || [ "$last_tx" = "Failed" ]; then
    note "last dnf transaction did not complete cleanly (status: $last_tx) - proceeding, but worth a look"
  fi
else
  blocking "dnf not found on PATH - not a dnf-based host?"
fi

# --- repo metadata reachable at all ---
echo "checking repo metadata is reachable..."
mc_out=$(dnf -C check-update 2>&1)
mc_rc=$?
# dnf check-update returns 100 when updates ARE available - that's fine,
# not a failure. Anything else non-zero means dnf itself couldn't run.
if [ $mc_rc -ne 0 ] && [ $mc_rc -ne 100 ]; then
  blocking "dnf check-update failed unexpectedly (rc=$mc_rc): $(echo "$mc_out" | tail -5 | tr '\n' ' ')"
fi

# --- RHEL only: flag an unregistered/unentitled host early rather than
# letting 'patch' discover it with a confusing repo error ---
if command -v subscription-manager >/dev/null 2>&1; then
  if ! subscription-manager status >/dev/null 2>&1; then
    note "subscription-manager present but host is not registered/entitled - dnf update may have no repos to pull from"
  fi
fi

# --- how much work is 'patch' actually about to do ---
echo "pending update summary:"
if command -v dnf >/dev/null 2>&1; then
  update_count=$(dnf -C check-update 2>/dev/null | grep -cE '^\S+\.(x86_64|noarch|i686|aarch64)\s')
  note "packages with updates available: ${update_count:-0}"
  sec_summary=$(dnf -C updateinfo summary 2>/dev/null | grep -iE 'security|critical|important' || true)
  [ -n "$sec_summary" ] && note "security update summary: $(echo "$sec_summary" | tr '\n' ' ')"
fi

# --- is a reboot already outstanding from before this job even starts ---
if command -v needs-restarting >/dev/null 2>&1; then
  if ! needs-restarting -r >/dev/null 2>&1; then
    note "host already has a reboot outstanding from before this job (unrelated prior change) - the 'reboot' stage will handle it after patching"
  fi
fi

echo "== preflight summary =="
printf '%s\n' "${notes[@]}"

if [ "$fail" -ne 0 ]; then
  echo "preflight FAILED - see BLOCKING lines above"
  exit 1
fi
echo "preflight OK"
exit 0
