#!/bin/bash
# 'patch' stage script — Rocky Linux 8 (os_family: rocky8).
#
# Replaces the agent's built-in dnf handler. Installs updates, honouring
# both the run's exclude rules and — as far as the agent lets it — the
# severity scope the operator picked in the Run wizard.
#
#   SEVERITY SCOPE
#   The agent exports the run's severity selection as KITE_SEVERITY, so
#   "Security only" / "Critical + Important" from the Run wizard is applied
#   here exactly as the built-in handler would apply it.
#   Older agents (before KITE_SEVERITY existed) did not send it. If the
#   variable is missing this script will not guess: it prints a loud WARNING
#   and falls back to KITE_SEVERITY_DEFAULT (default "all"). Set
#   KITE_SEVERITY_DEFAULT=security via a systemd drop-in if you would
#   rather an old agent stay narrow than patch everything. Silently
#   installing more than the operator asked for is the failure mode this
#   block exists to prevent.
#
# Env contract:
#   KITE_JOB_ID    - the run's job id
#   KITE_HOSTNAME  - this host's hostname
#   KITE_STAGE     - always "patch" for this script
#   KITE_EXCLUDES  - space-separated skip-mode package patterns
#   KITE_PINS      - space-separated "pattern=version" pin-mode entries
#                        (applied in excludes.sh via versionlock; listed here
#                        for visibility only)
#   KITE_SEVERITY  - NOT set by the agent today; see the block above
#
# Contract: exit 0 = stage done, anything else = failed. Combined stdout+
# stderr is captured (last 4000 chars) as the stage output.

set -uo pipefail

RETRIES="${KITE_DNF_RETRIES:-2}"
SEVERITY_DEFAULT="${KITE_SEVERITY_DEFAULT:-all}"

echo "== patch (rocky8): ${KITE_HOSTNAME:-unknown} (job ${KITE_JOB_ID:-?}) =="
echo "excludes: [${KITE_EXCLUDES:-none}]"
echo "pins:     [${KITE_PINS:-none}]  (applied in the excludes stage)"

# --- resolve the severity scope -------------------------------------------
severity="${KITE_SEVERITY:-}"
if [ -z "$severity" ]; then
    severity="$SEVERITY_DEFAULT"
    echo "WARNING: this agent did not send KITE_SEVERITY (pre-severity agent?),"
    echo "WARNING: so the Run wizard's severity scope is NOT being applied."
    echo "WARNING: falling back to KITE_SEVERITY_DEFAULT='${severity}'."
else
    echo "severity scope from controller: '${severity}'"
fi

cmd=(dnf update -y)
case "$(echo "$severity" | tr '[:upper:]' '[:lower:]')" in
    ""|all)
        echo "scope: every available update"
        ;;
    security)
        cmd+=(--security)
        echo "scope: security advisories only"
        ;;
    *)
        # A severity list, e.g. "Critical,Important". --security scopes to
        # advisories; --sec-severity then narrows to those levels. Without
        # --security, dnf ignores --sec-severity entirely.
        cmd+=(--security)
        levels_applied=""
        IFS=',' read -ra _levels <<< "$severity"
        for lvl in "${_levels[@]}"; do
            lvl="$(echo "$lvl" | tr -d '[:space:]')"
            [ -z "$lvl" ] && continue
            # dnf expects Critical/Important/Moderate/Low, capitalised.
            lvl="$(echo "${lvl:0:1}" | tr '[:lower:]' '[:upper:]')$(echo "${lvl:1}" | tr '[:upper:]' '[:lower:]')"
            cmd+=("--sec-severity=${lvl}")
            levels_applied="${levels_applied}${lvl} "
        done
        echo "scope: security advisories rated: ${levels_applied:-<none parsed>}"
        ;;
esac

# --- skip-mode excludes are applied here, at patch time --------------------
for pattern in ${KITE_EXCLUDES:-}; do
    cmd+=("--exclude=${pattern}")
done

echo "running: ${cmd[*]}"

# --- run, with a retry for transient repo/network failures -----------------
attempt=1
rc=1
while [ "$attempt" -le "$((RETRIES + 1))" ]; do
    out=$("${cmd[@]}" 2>&1); rc=$?
    if [ $rc -eq 0 ]; then
        break
    fi
    if echo "$out" | grep -qiE 'timeout|Could not resolve|Connection refused|Temporary failure|curl error|Failed to download'; then
        echo "attempt ${attempt} failed with what looks like a transient repo error; retrying..."
        attempt=$((attempt + 1))
        sleep 10
        continue
    fi
    break   # a real failure — do not burn the window retrying it
done

echo "$out" | tail -60
echo "dnf exit code: $rc (after ${attempt} attempt(s))"

if [ $rc -ne 0 ]; then
    echo "patch FAILED"
    exit 1
fi

# --- what actually changed, for the audit log ------------------------------
installed=$(echo "$out" | grep -cE '^\s*(Upgraded|Installed|Updating|Installing)\s')
echo "transaction completed; changed-package lines seen: ${installed:-0}"
if command -v needs-restarting >/dev/null 2>&1; then
    needs-restarting -r >/dev/null 2>&1 \
        && echo "no reboot required" \
        || echo "reboot required - the 'reboot' stage will handle it"
fi

echo "patch OK"
exit 0
