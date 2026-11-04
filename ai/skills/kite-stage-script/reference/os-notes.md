# Per-family notes for stage scripts

What actually differs between the platforms kite targets. Read the row
for the OS in front of you before assuming a command behaves the same way it
does elsewhere.

## RHEL family (RHEL, Rocky, Alma, Oracle, CentOS Stream)

Shared:

- `dnf check-update` returns **100** when updates are available. That is
  success, not failure. Only treat anything else non-zero as an error.
- Severity is real here: `dnf update --security --sec-severity=Critical`.
  Levels are `Critical`, `Important`, `Moderate`, `Low` — capitalised.
  Without `--security`, `--sec-severity` is ignored entirely.
- Skip-mode excludes apply at patch time as `--exclude=<pattern>`; pins apply
  in the excludes stage via `dnf versionlock add "<base>-<version>*"`.
- `/boot` is the disk that actually fills. A kernel install that runs out of
  space there fails partway and is the single most common preventable
  failure. Check it separately from `/`.
- PackageKit can grab the rpm lock mid-transaction on installs that have it
  running; worth flagging in preflight on servers.

### EL8 vs EL9

| | EL8 | EL9 |
|---|---|---|
| `needs-restarting` ships in | `dnf-utils` | `dnf-plugins-core` |
| Crypto policy | permissive enough for SHA-1 repo metadata | **DEFAULT rejects SHA-1-signed repo metadata** |
| Final minor | 8.10 (maintenance to 2029-05-31) | still receiving minors |

The EL9 crypto policy is the one that generates confused bug reports: a
third-party repo that works fine on EL8 fails on EL9 with an opaque
`repomd.xml` GPG signature error. `update-crypto-policies --show` returning
`DEFAULT` is the tell. `LEGACY` loosens it, at a real cost — say so rather
than recommending it casually.

## Debian family (Debian, Ubuntu)

- **apt publishes no per-advisory severity.** A security update is
  identifiable by its origin suite (`*-security`), but "Critical only" cannot
  be expressed. A severity list here can only degrade to security-only, and
  the script must *say* it degraded rather than quietly patching more or less
  than was asked.
- No `--exclude`-at-patch-time equivalent. Exclusion happens earlier via
  `apt-mark hold`; `apt-get upgrade` then skips held packages on its own.
- `apt-mark` takes **exact installed package names — no globs**. A pattern
  with a `*` from a shared cross-platform rule simply matches nothing. Report
  that; don't let it look like it applied.
- Always run non-interactively: `DEBIAN_FRONTEND=noninteractive` plus
  `-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold`,
  or a config prompt will hang the stage until the one-hour timeout.

## Windows (Server 2016/2019/2022/2025, Windows 10/11)

- Runs under `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy
  Bypass`. Nothing interactive: no `Read-Host`, no prompts, no assumption of
  a console or a logged-in user.
- `$ErrorActionPreference` defaults matter. A non-terminating error will not
  set a failing exit code on its own — end the script with an explicit
  `exit 0` / `exit 1` reflecting what actually happened.
- **Windows Update cannot pin a package to a version.** Skip and pin are
  therefore treated identically: both keep that title or KB out of what the
  patch stage installs. Pretending to support pinning is worse than saying it
  isn't supported.
- Severity: Windows publishes `MsrcSeverity`, so a severity list *can* be
  honoured — unlike apt.
- Server 2016 has no `winget`; don't assume third-party app coverage there.
- Check for an already-pending reboot before starting: a host that needs one
  from a prior change will behave differently through the patch stage.

## Anything else

kite matches scripts purely by the `os_family` string the host reports,
so an OS nobody has taught it about still works — the agent's built-in
handlers just may not. If you're writing for a family with no template
(Flatcar, SUSE, Alpine…):

- Confirm what the package manager actually is before writing commands.
- Start from `rhel-family/preflight.sh` for structure (note/blocking helpers,
  summary at the end) even if every command changes.
- Be explicit in the output about what the platform cannot express, rather
  than approximating it.
