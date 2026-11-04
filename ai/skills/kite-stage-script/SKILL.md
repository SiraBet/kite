---
name: kite-stage-script
description: Write or review a kite per-OS stage script (preflight, excludes, or patch) for a specific OS family — Rocky/RHEL/Alma 8-9, Debian/Ubuntu, Windows Server, or anything else a host reports. Use when someone asks for a stage script, a pre-flight check, a custom patch step, an os_family override, or says their distro needs something the built-in agent handler doesn't do.
---

# Writing a kite stage script

kite runs a fixed pipeline per job. Three of its stages can be replaced
per OS family by a script you upload: **`preflight`**, **`excludes`**, and
**`patch`**. The agent then runs your script *instead of* its built-in
handler for that stage on hosts in that family.

Your job here is to produce a script that is correct for the OS in front of
you and honest about what it cannot do. Read this whole file before writing
one — most of the ways these go wrong are contract violations, not bugs in
the shell.

## The contract (identical on Linux and Windows)

| | |
|---|---|
| Interpreter | Linux: `/bin/bash <script>` (the shebang is not consulted). Windows: `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <script>` |
| Runs as | root / SYSTEM — same as everything else the agent does |
| Success | **exit 0 = stage done. Any other exit code = stage failed**, which fails the run |
| Output | combined stdout+stderr, **last 4000 characters** kept and shown in the Progress screen and audit log. Keep it terse; don't cat whole logs |
| Timeout | 1 hour, then the stage is failed |
| Written to | Linux `/var/lib/kite/stage_scripts/<stage>.sh`, Windows `<InstallDir>\stage_scripts\<stage>.ps1` |

### Environment variables

Data arrives through the environment, never templated into the script text —
so one uploaded script keeps working as rules change.

| Variable | Meaning |
|---|---|
| `KITE_JOB_ID` | the run's job id |
| `KITE_HOSTNAME` | this host's hostname |
| `KITE_STAGE` | `preflight` \| `excludes` \| `patch` |
| `KITE_EXCLUDES` | space-separated skip-mode package patterns |
| `KITE_PINS` | space-separated `pattern=version` pin-mode entries |
| `KITE_SEVERITY` | the run's severity scope (see below) |

Older agents don't send it.

## The rule that matters most: never widen the operator's scope

`KITE_SEVERITY` is what the operator chose in the Run wizard:

- `""` or `all` — every available update
- `security` — security advisories only
- a list like `Critical,Important` — those severity levels only

A `patch` script that ignores this installs **more than was asked for**, on a
production host, in a maintenance window sized for something smaller. That is
the worst failure mode this feature has, and it is silent.

So a `patch` script must either apply the scope or say loudly that it can't:

```bash
severity="${KITE_SEVERITY:-}"
if [ -z "$severity" ]; then
  severity="${KITE_SEVERITY_DEFAULT:-all}"
  echo "WARNING: no KITE_SEVERITY from this agent; applying '${severity}'"
fi
```

Never silently default to "everything" without printing that you did.

## Which stage to write

**`preflight`** — the safest and most useful to customise, and where most
value is. Catch anything that would waste a maintenance window on a host that
was doomed before the package manager ran: no disk on `/boot`, another
package manager already holding the lock, repos unreachable, host not
entitled. Only genuinely blocking conditions should exit non-zero; everything
else is a warning that still lets the run proceed.

**`excludes`** — applies pin-mode entries (e.g. `dnf versionlock`). If you
override it, reconcile *full* state each run: remove locks that are no longer
in `KITE_PINS`, or pins accumulate and nothing ever un-pins. Leave locks
you didn't add alone.

**`patch`** — the riskiest to override, because you now own severity scoping
and exclude application. Prefer leaving it built-in unless the OS genuinely
needs something else. If you do write one, re-read the scope rule above.

**`reboot` is deliberately NOT scriptable.** The built-in handler persists
state to disk before rebooting so the agent can resume and report after the
host comes back. A script that reboots the host has no way to hook into that
and would leave the job stuck at `reboot: running` forever. If someone asks
for a reboot script, explain this rather than writing one.

## How to work

1. **Identify the exact `os_family`** the host reports (Fleet page, or the
   host's detail panel — "Family key"). kite matches scripts by that
   string. `rocky9` and `rhel9` are different keys even though the script
   content may be identical; one row per exact string is required.
2. **Start from the closest template** in `controller/examples/os-scripts/`:
   `rhel-family/`, `rocky8/`, `rocky9/`, `windows-family/`. Don't write from
   scratch if one of these is close — they already handle retries, pin-state
   reconciliation and the severity block correctly.
3. **Read `reference/os-notes.md`** in this folder for the per-family gotchas
   (EL8 vs EL9 differences, apt's lack of severity metadata, Windows Update
   quirks) before assuming a command behaves the same everywhere.
4. **Check syntax before handing it over**: `bash -n script.sh`. For
   PowerShell, at minimum keep it `-NonInteractive`-safe — no prompts, no
   `Read-Host`, no assumption of a console.
5. **Say what you could not do.** If the OS can't express something the user
   asked for (apt has no per-advisory severity; Windows Update can't pin a
   version), put that in the script's output and tell the user — don't
   emulate it badly and don't stay quiet.

## Uploading it

Console → **Per-system scripts** → pick the family → upload for the stage.
A new upload replaces the live script for that (family, stage) and the
previous one moves to history; they never stack. **Uploads start "untested"**
and flip to tested automatically the first time they complete successfully on
a real host.

## Testing without a live run

You can exercise command construction locally by putting a stub earlier on
`PATH` — this is how the shipped templates were checked:

```bash
mkdir -p /tmp/stub && printf '#!/bin/bash\necho "ARGS: $*"\n' > /tmp/stub/dnf
chmod +x /tmp/stub/dnf
PATH=/tmp/stub:$PATH KITE_SEVERITY='Critical,Important' \
  KITE_EXCLUDES='kernel*' KITE_HOSTNAME=h1 KITE_JOB_ID=1 \
  bash patch.sh
```

The agent also has a dry-run mode that reports what it *would* run without
running it.

## Don't

- Don't invent capabilities the platform lacks to satisfy a request.
- Don't print secrets, tokens, or full package lists — output is stored in the
  audit log and capped at 4000 characters.
- Don't reboot from a script (see `reboot` above).
- Don't assume the host has internet beyond its configured repos.
