#!/bin/bash
# 'patch' stage script for the RHEL/dnf family — RHEL, Rocky, AlmaLinux,
# Oracle Linux, CentOS Stream (8/9).
#
# Refreshes repo metadata first, with retries, so a transient repo blip
# doesn't immediately fail the whole run. Retries the update itself only
# on a detected lock-contention error (e.g. dnf-automatic briefly
# holding the rpm db) — real dependency/GPG/repo errors are not retried,
# so they fail fast and visibly instead of masking the real problem
# behind 3x the wait. Never reboots — that's the separate, non-
# scriptable 'reboot' stage the agent handles itself after this stage
# reports done.
#
# Available env vars (set by the agent before running this):
#   KITE_JOB_ID    - the run's job id
#   KITE_HOSTNAME  - this host's hostname
#   KITE_STAGE     - always "patch" for this script
#   KITE_EXCLUDES  - space-separated skip-mode package patterns
#   KITE_PINS      - space-separated "pattern=version" pin-mode entries
#                        (already applied via dnf versionlock in the
#                        'excludes' stage — dnf will already refuse to
#                        touch them, --exclude below is belt-and-suspenders)
#
# Contract: exit 0 = stage succeeded, any other exit code = stage failed.
# Combined stdout+stderr is captured (last 4000 chars) and shown in the
# Progress screen/audit log. The agent enforces a hard 3600s timeout on
# this script regardless of anything set here.

set -uo pipefail

METADATA_MAX_ATTEMPTS=3
METADATA_RETRY_SECONDS=15
UPDATE_MAX_ATTEMPTS=3
UPDATE_RETRY_SECONDS=20

running_kernel="$(uname -r)"
echo "== patch: $KITE_HOSTNAME (job $KITE_JOB_ID) =="
echo "running kernel: $running_kernel"
echo "excludes: [${KITE_EXCLUDES:-none}]"
df -h / 2>/dev/null | tail -1 | awk '{print "disk free before: " $4 " (" $5 " used)"}'

EXCLUDE_FLAGS=()
for pattern in ${KITE_EXCLUDES:-}; do
  EXCLUDE_FLAGS+=("--exclude=$pattern")
done

is_lock_contention() {
  echo "$1" | grep -qiE "could not acquire lock|another copy of dnf is running|already locked"
}

# --- refresh metadata first, with retries. Best-effort: if it still
# fails after retries, don't hard-fail the stage here - let the real
# `dnf update` attempt below surface whatever the actual problem is,
# with a clearer error than a bare makecache failure would give. ---
echo "refreshing repo metadata..."
attempt=1
while [ "$attempt" -le "$METADATA_MAX_ATTEMPTS" ]; do
  mc_out=$(dnf makecache --refresh 2>&1)
  mc_rc=$?
  if [ "$mc_rc" -eq 0 ]; then
    break
  fi
  echo "metadata refresh attempt $attempt/$METADATA_MAX_ATTEMPTS failed (rc=$mc_rc):"
  echo "$mc_out" | tail -5
  if [ "$attempt" -eq "$METADATA_MAX_ATTEMPTS" ]; then
    echo "proceeding to update anyway - dnf will refresh what it needs"
  else
    sleep "$METADATA_RETRY_SECONDS"
  fi
  attempt=$((attempt + 1))
done

# --- the actual update, retried only on lock contention ---
attempt=1
update_out=""
update_rc=1
while [ "$attempt" -le "$UPDATE_MAX_ATTEMPTS" ]; do
  echo "dnf update attempt $attempt/$UPDATE_MAX_ATTEMPTS: dnf update -y ${EXCLUDE_FLAGS[*]}"
  update_out=$(dnf update -y "${EXCLUDE_FLAGS[@]}" 2>&1)
  update_rc=$?
  if [ "$update_rc" -eq 0 ]; then
    break
  fi
  if is_lock_contention "$update_out" && [ "$attempt" -lt "$UPDATE_MAX_ATTEMPTS" ]; then
    echo "rpm/dnf lock contention detected (rc=$update_rc) - retrying in ${UPDATE_RETRY_SECONDS}s"
    sleep "$UPDATE_RETRY_SECONDS"
    attempt=$((attempt + 1))
    continue
  fi
  # Real failure (dependency problem, GPG error, out of space, etc.) -
  # don't retry, fail fast with the actual error visible.
  break
done

if [ "$update_rc" -ne 0 ]; then
  echo "dnf update FAILED (rc=$update_rc)"
  echo "$update_out" | tail -60
  exit "$update_rc"
fi

# --- concise success summary instead of the full transaction log ---
echo "== patch summary =="
echo "$update_out" | grep -A5 -E '^Transaction Summary$' || echo "$update_out" | tail -10
df -h / 2>/dev/null | tail -1 | awk '{print "disk free after: " $4 " (" $5 " used)"}'

installed_kernel_pkg=$(rpm -q --last kernel 2>/dev/null | head -1 | awk '{print $1}')
if [ -n "$installed_kernel_pkg" ] && [[ "$installed_kernel_pkg" != *"$running_kernel"* ]]; then
  echo "note: a new kernel was installed ($installed_kernel_pkg) - running kernel is still $running_kernel, reboot stage will pick this up"
fi

# --- best-effort cache cleanup, never fails the stage ---
dnf clean packages >/dev/null 2>&1 || true

echo "patch OK"
exit 0
