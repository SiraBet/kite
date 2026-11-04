# kite Windows agent

Two programs, both single self-contained executables the controller
builds and hands out:

| Binary | What it is |
|---|---|
| `kite-agent-setup.exe` | The installer. Carries the agent inside it. |
| `kite-agent.exe` | The agent itself: a Windows service, and a status window. |

Windows has no package repository to install an agent from, so the
console hands out the installer directly — the same shape as the Wazuh
or Qualys agent.

## Installing

**From the console.** Fleet → Windows → generate a token, and you get a
download built for that host: the controller URL and the token are
appended to the file itself, so every field is already filled in. Copy
it to the host, run it as Administrator, done. Nothing to type, so
nothing to mistype.

That file carries a live enrollment token. It is single-use and expires,
but treat it as a credential until it has been used.

**Generic download.** `Download installer` on the same panel gives an
unconfigured copy that asks for the controller URL and token when it
runs. Use this when the same file is going to several hosts.

**Silent.** For software distribution:

```
kite-agent-setup.exe /S /controller=https://kite.lab /token=<token>
```

`/secret=<secret>` works in place of `/token` when enrolling with the
controller's shared enrollment secret. Also accepted: `/hostname=`,
`/team=`, `/role=`, `/dir=`, `/ca-fingerprint=`, `/insecure`, `/poll-interval=`. The silent
path runs the same code as the wizard, so an unattended install cannot
drift from an interactive one.

Removing it: `kite-agent-setup.exe /uninstall [/S]`, or the entry in
Settings → Apps. Add `/purge` to also delete this host's credential and
the log of what it patched; without it those are left in place, because
an upgrade should not destroy them.

If the controller uses the self-signed certificate `controller-install.sh`
sets up by default, pass `/ca-fingerprint=<sha256>` with the fingerprint
the console's Add machine panel shows (the installer the console hands
out for a token already carries it): the agent downloads the
controller's root CA, checks it against the fingerprint, and from then
on trusts that root alone for the controller. *Skip TLS verification*
(`/insecure`) turns the checks off instead; an agent installed that way
switches itself to the controller's CA on its next start. Either
affects only this agent's own HTTP client; nothing else on the host
changes.

## The status window

Double-clicking `kite-agent.exe`, or the Start menu entry, opens a
native window showing what the agent is doing and the recent log — so
somebody standing at a machine that is not getting patched can see why
without opening a log file.

It reports and nothing else. There is no "patch now" button: runs are
scheduled and gated on the controller, and a button here would let
somebody who has never heard of a maintenance window start one.

The window is a different process from the service, and a Windows
service in session 0 cannot show a window at all — so the service
publishes what it knows to `status.json` and the window reads that
alongside the log. A file rather than a socket or a named pipe: nothing
listens, there are no pipe ACLs to get wrong, and it still answers when
the service is stopped. That last case matters most, because a stopped
service is the usual reason a host quietly stops being patched, and the
window says so in as many words.

## Commands

`kite-agent.exe` is a GUI-subsystem binary, so a double-click opens
the window with no console flashing behind it. Run from a terminal it
attaches to that terminal and prints normally.

| Command | What it does |
|---|---|
| `kite-agent` | Open the status window |
| `kite-agent enroll -controller <url> -token <token>` | Exchange a token for this host's credential |
| `kite-agent install` | Register and start the service |
| `kite-agent uninstall` | Remove the service |
| `kite-agent run` | Run the poll loop in this console |
| `kite-agent once` | Poll a single time and exit — the first thing to try when a host is not picking up work |
| `kite-agent status` | Print what the service last published, as JSON |

## Files on the host

| Path | What it is |
|---|---|
| `%ProgramFiles%\kite\` | The two executables |
| `%ProgramData%\kite\agent.conf` | Controller URL, host id, this host's credential |
| `%ProgramData%\kite\agent.log` | Operational log, rotated at 5 MB with one previous kept |
| `%ProgramData%\kite\status.json` | What the service last published, for the window |
| `%ProgramData%\kite\excludes.json` | Exclude patterns from the last `excludes` stage |
| `%ProgramData%\kite\pending_reboot.json` | Written before a reboot so the stage is reported once the host is back |

Program Files and ProgramData are split deliberately: Program Files is
administrator-writable only and is the conventional home for a service
binary, while the state the service writes constantly belongs elsewhere.
The state directory's ACL is restricted to SYSTEM and Administrators —
it holds this host's credential.

## What it patches

Windows Update through the COM API (`Microsoft.Update.Session`), not
PSWindowsUpdate. That module has to be installed from PSGallery first,
which needs internet access on a host that may deliberately have none,
and turns "assess this machine" into "install software on this machine".
The COM API is present on every supported Windows version.

Every PowerShell call is made with `-NoProfile -NonInteractive
-ExecutionPolicy Bypass`, so a host with the default Restricted
execution policy — which is most locked-down ones — works untouched.

Severity comes from Microsoft's own `MsrcSeverity`, so a severity-scoped
run is honoured natively here, unlike apt, which publishes no severity at
all. An update Microsoft grades nothing is reported as `unknown` rather
than graded down, and a search that could not run reports
`updates_ok=false` rather than an empty list: "we could not tell" and
"there is nothing" are different answers, and reporting the first as the
second is how an unpatched fleet looks healthy.

Excludes are applied as skips. Windows Update cannot hold a package at a
version, so a `pin` rule keeps that update out of the run exactly as a
`skip` does — claiming to pin would be worse than saying it is not
supported.

Containers are not offered: this agent discovers none, and the
`containers` stage fails saying so rather than reporting a container
update that never happened.

## Layout

```
cmd/kite-agent/     the service and status window
cmd/kite-setup/     the installer
internal/agent/         poll/execute/report, config, logging, service
internal/agent/scripts/ the PowerShell the agent runs, compiled in
internal/gui/           both Win32 windows
internal/installer/     installation steps, shared by wizard and /S
internal/selfcfg/       reading configuration appended to the binary
internal/console/       reattaching a GUI binary to its terminal
```

## Building

```bash
./build.sh          # -> ../controller/dist/
```

Needs Go 1.23+ and cross-compiles from Linux — no cgo in either binary,
so the controller produces the Windows programs it hands out without a
Windows machine anywhere in the loop. The agent is built first and
compressed into the installer, so the order matters; `build.sh` handles
it. CI builds both on every push and uploads them as artifacts.

Tests run on any platform:

```bash
go vet ./... && go test -race ./...
```

They cover the controller contract, config handling, stage logic, the
silent-install switches, and the appended-config format — including a
test that the Go reader understands what the controller's Python writer
produces, because a format with two implementations drifts silently
otherwise. They do not cover the PowerShell scripts or the windows,
which need Windows.

## Status

**Tested on real Windows hosts.** On top of that, everything testable off
Windows runs in CI on every push, and both binaries are built for Windows
each time.

The agent also reports its network (adapters, addresses,
default gateway, listening sockets with their process) and updates
itself when the console asks: it downloads the controller's
`kite-agent.exe`, checks the `X-Kite-Sha256` and
`X-Kite-Agent-Version` it was served with, renames the running exe
aside to `.old`, puts the new one in place and restarts the service
through a detached `net stop`/`net start`. The installer also retries
enrolment a few times when the connection drops.

The status window's files -- `status.json` and the log -- are in
`C:\ProgramData\kite\status\`, readable by the machine's users.
`C:\ProgramData\kite` itself stays locked to SYSTEM and Administrators
because `agent.conf` holds the host's credential, and the window runs
unelevated. A timed-out
PowerShell scan can no longer hang the agent either: a child process
left holding its output is given 15 seconds after the kill, then
abandoned.

Not yet done: code signing, so SmartScreen will warn on the download.
Note that a generated per-host installer cannot be signed anyway —
appending the configuration invalidates an Authenticode signature — so
signing would cover the generic download only.
