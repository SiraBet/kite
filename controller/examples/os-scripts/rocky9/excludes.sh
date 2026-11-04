#!/bin/bash
# 'excludes' stage script — Rocky Linux 9 (os_family: rocky9).
#
# Identical in logic to ../rhel-family/excludes.sh — pin/versionlock handling
# does not differ between EL8 and EL9, so this is deliberately the same
# content, kept as its own file only because kite stores one script per
# (os_family, stage) pair and each must be uploaded independently.
#
# Applies pin-mode entries via dnf versionlock. Skip-mode entries need no
# action here — they're applied as --exclude flags at patch time (patch.sh).
#
# Reconciles full pin state on every run instead of only ever adding locks:
# installs the versionlock plugin if missing, tracks which lock specs *this
# script* added in STATE_FILE, and removes ones no longer in KITE_PINS
# (e.g. the rule was deleted in the UI) — otherwise pins only accumulate and
# nothing ever un-pins. A versionlock entry not in STATE_FILE (added by hand
# outside kite) is left alone.
#
# See patch.sh for the full KITE_* env var contract.

set -uo pipefail

STATE_DIR="/var/lib/kite"
STATE_FILE="$STATE_DIR/versionlock_managed.list"
mkdir -p "$STATE_DIR"

echo "== excludes: $KITE_HOSTNAME (job $KITE_JOB_ID) =="

if [ -z "${KITE_PINS:-}" ] && [ ! -s "$STATE_FILE" ]; then
  echo "no pin-mode entries to apply, and nothing previously pinned by kite"
  exit 0
fi

# --- make sure the versionlock plugin is actually available ---
if ! dnf versionlock list >/dev/null 2>&1; then
  echo "dnf-versionlock plugin not found - installing..."
  if ! dnf install -y 'dnf-command(versionlock)' >/tmp/kite-versionlock-install.log 2>&1; then
    echo "failed to install versionlock plugin:"
    tail -20 /tmp/kite-versionlock-install.log
    exit 1
  fi
fi

# --- compute desired lock specs from KITE_PINS ---
declare -A desired
for entry in ${KITE_PINS:-}; do
  pattern="${entry%%=*}"
  version="${entry##*=}"
  base="${pattern%\**}"
  if [ -z "$base" ] || [ -z "$version" ]; then
    echo "skipping malformed pin entry: '$entry'"
    continue
  fi
  lock_spec="${base}-${version}*"
  desired["$lock_spec"]=1
done

# --- previously-managed specs (what WE locked last time we ran) ---
declare -A previous
if [ -f "$STATE_FILE" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && previous["$line"]=1
  done < "$STATE_FILE"
fi

fail=0

# --- add anything newly desired ---
for spec in "${!desired[@]}"; do
  echo "pinning: dnf versionlock add \"$spec\""
  if ! dnf versionlock add "$spec" >/tmp/kite-versionlock-add.log 2>&1; then
    echo "failed to pin $spec:"
    tail -10 /tmp/kite-versionlock-add.log
    fail=1
  fi
done

# --- remove anything we managed before but is no longer desired ---
for spec in "${!previous[@]}"; do
  if [ -z "${desired[$spec]:-}" ]; then
    echo "un-pinning (no longer in exclude list): dnf versionlock delete \"$spec\""
    if ! dnf versionlock delete "$spec" >/tmp/kite-versionlock-del.log 2>&1; then
      echo "failed to remove stale lock $spec (non-fatal - may already be gone):"
      tail -10 /tmp/kite-versionlock-del.log
    fi
  fi
done

# --- log skip-mode entries for visibility (applied at patch time, not here) ---
skip_count=0
for pattern in ${KITE_EXCLUDES:-}; do
  echo "skip-mode (applied via --exclude at patch time): $pattern"
  skip_count=$((skip_count + 1))
done
echo "skip-mode entries: $skip_count, pin-mode entries: ${#desired[@]}"

# --- persist the new managed set for next run's reconciliation ---
: > "$STATE_FILE"
for spec in "${!desired[@]}"; do
  echo "$spec" >> "$STATE_FILE"
done

if [ "$fail" -ne 0 ]; then
  echo "excludes FAILED - at least one pin could not be applied"
  exit 1
fi
echo "excludes OK"
exit 0
