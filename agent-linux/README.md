# kite-agent

Runs on each Linux host — RHEL-family (`dnf`) and Debian-family (`apt`)
both, from this one codebase (`agent.py` detects which package manager is
actually on the host at runtime and dispatches accordingly; see
`detect_package_manager()`). Polls the controller for pending stages,
executes them locally, reports back. No inbound port needed — outbound
HTTPS/HTTP to the controller only, so this works even behind a firewall
later.

**Platform note**: RHEL-family (Rocky/RHEL/Alma/Oracle/CentOS Stream) is
the one this has actually run against real hosts. Debian/Ubuntu support
is new, real (not stubbed — genuine `apt-get`/`apt-mark` command
construction, tested via mocking, see `tests/test_agent.py`), but not yet
verified against a real Ubuntu/Debian host — see "Known gaps" below.

## Install via RPM (recommended, RHEL-family only)

This is the "just like Qualys/Wazuh" path — a real dnf-installable
package with proper upgrade/removal handling, rather than copying files
by hand.

**Build the RPM** (on any Rocky 8 or 9 host — needs `rpm-build`):

```bash
sudo dnf install -y rpm-build
bash packaging/build.sh
# -> packaging/out/kite-agent-<version>-1.noarch.rpm  (OUT=dir to put it elsewhere)
```

Build natively on a Rocky host rather than cross-building elsewhere —
avoids any payload-compression mismatch between rpm versions (this was
checked and is fine with a plain Ubuntu-built rpmbuild too, using gzip
payload compression, but native is the safer default going forward).

**Install directly** (copy the .rpm to a host, or once it's in the
controller's repo — see the controller README's "Hosting a real dnf
repo" section — install straight from there):

```bash
sudo dnf install -y ./kite-agent-*.noarch.rpm
# or, once the controller is hosting a repo:
sudo dnf install -y kite-agent
```

**One-liner install + enroll + start** — two ways to do this, pick based on how much you're onboarding:

*Per-host token* (tightest scope — each host individually authorized).
The console's **Fleet → Add machine** issues the token and shows the
whole command, with the controller's CA fingerprint; it comes down to:

```bash
sudo KITE_CONTROLLER=https://<controller> KITE_TOKEN=<token> \
  KITE_CA_FINGERPRINT=<sha256 from the console> dnf install -y kite-agent
```

*Shared secret* (same pattern as Wazuh's authd password / Qualys's
Activation ID — configure once on the controller, reuse across every
host's install command, zero admin action per host after that). Needs
`KITE_ENROLL_SECRET` set in the controller's `.env` first — see the
controller README:

```bash
sudo KITE_CONTROLLER=https://<controller> KITE_SECRET=<shared-secret> \
  KITE_HOSTNAME=app-web-05 KITE_TEAM=Platform \
  dnf install -y kite-agent
```

`KITE_HOSTNAME` defaults to the host's actual system hostname if
omitted. Optional either way: `KITE_OS_FAMILY`, `KITE_VMID`,
`KITE_ROLE`, and `KITE_INSECURE=1` — needed for the self-signed
cert `controller-install.sh` sets up by default (see the controller's
`Caddyfile`); drop it once the controller has a cert this host trusts.
The `curl -k` above matches the same self-signed default for that one
bootstrapping call, before the agent has its own `--insecure`/
`KITE_INSECURE` setting to fall back on.

Without any of these env vars set, installing just installs the
package — no auto-start, since there's no credential yet — and prints
manual instructions for both paths at the end.

If auto-enroll fails (bad credential, controller unreachable), the
package install itself still succeeds — you'll see a warning and the
manual enrollment steps instead of a failed transaction.

**Upgrading**: `sudo dnf install -y ./kite-agent-<new-version>.noarch.rpm`
(or `dnf update kite-agent` from a repo) preserves your existing
`/etc/kite/agent.conf` — no re-enrollment needed — and restarts the
service automatically if it was already running.

**Removing**: `sudo dnf remove kite-agent` stops and disables the
service first. Your enrollment config and any state files aren't part of
the package, so they're left behind (in case of a reinstall) — clean
those up by hand if you're decommissioning the host for good:
`sudo rm -rf /etc/kite /var/lib/kite`.

## Install manually (alternative — no RPM build tooling needed)

RHEL-family:

```bash
# copy this directory to the host first (scp, git clone, whatever), then:
cd kite-agent
./install.sh
```

This installs `python3-requests`, the `dnf versionlock` plugin, `dnf-utils`
(for `needs-restarting`), and the systemd unit — but does **not** enroll or
start the agent, since it needs a token from the controller first.

Debian/Ubuntu — same idea, `apt`-based:

```bash
cd kite-agent
./install-debian.sh
```

Installs `python3` + `python3-requests` (from the distro repo, not `pip` —
newer Debian/Ubuntu's PEP 668 "externally managed environment" refuses a
plain `pip3 install` outside a venv, so there's no reason to fight that
for one widely-packaged dependency) and the same systemd unit. No `.deb`
package or apt repo yet — that's the Debian-family equivalent of the RPM
path above, not built yet (see "Known gaps").

## Enroll

Two ways, whichever fits: a per-host one-time token (tightest scope), or
a shared secret if the controller has `KITE_ENROLL_SECRET` configured
(same pattern as Wazuh's authd password / Qualys's Activation ID — see
the controller README). The RPM's `%post` can do either automatically —
see "Install via RPM" above — but you can also run it by hand:

With the self-signed certificate `controller-install.sh` sets up by
default, add `--ca-fingerprint <sha256>` with the fingerprint the
console's Enroll tab shows: `enroll.py` downloads the controller's root
CA, checks it against that fingerprint, saves it as
`/etc/kite/controller-ca.crt`, and from then on every call to the
controller is checked against it alone (`--ca-cert <file>` takes an
already-checked copy instead; with the RPM, `KITE_CA_FINGERPRINT` /
`KITE_CA_CERT`). A controller with a public certificate needs
neither.

`--insecure` turns certificate checks off instead. Agents enrolled that
way switch themselves over on their next start: they take
the controller's root CA once, over the connection they already trust,
and check every call against it from then on; with a public certificate,
against the system's CAs. They switch only after a request checked that
way succeeds, and the dnf repo file (`sslverify`) follows.

`--insecure` prints a loud warning at enroll time (the
long-lived agent secret is about to cross the network with no
protection against interception), and `agent.py` logs the same warning
on every startup where `verify_tls: false` is still set in
`agent.conf`, so it stays visible rather than a one-time thing you
might not see again.

```bash
# token path:
python3 /opt/kite-agent/enroll.py --controller https://<control-vm> --token <token>

# shared-secret path (hostname required, since there's no token tying it to one):
python3 /opt/kite-agent/enroll.py --controller https://<control-vm> \
  --secret <shared-secret> --hostname app-web-05 --team Platform
```

Issue a one-time token for the hostname in the console (Fleet → Add
machine; an admin), or with the API from a signed-in session:

```bash
curl -b $JAR -X POST $CONTROLLER/enroll/tokens -H 'content-type: application/json' \
  -d '{"hostname":"app-web-03","team":"Platform","role":"Web app server"}'
```

(`$JAR` holds the session from `POST /auth/login`; see the controller
README's "Core flow".)

Then, on the host:

```bash
python3 /opt/kite-agent/enroll.py \
  --controller https://<control-vm> \
  --token <token from above> \
  --vmid <proxmox VM ID for this host>
```

This writes `/etc/kite/agent.conf` (mode 600, root-only) with a
long-lived per-host credential — shown once, right here, never again.

## Start

```bash
systemctl daemon-reload
systemctl enable --now kite-agent
journalctl -u kite-agent -f
```

## OS family detection

At enrollment, the agent reads `/etc/os-release` to guess an `os_family`
key (`rocky8`, `rocky9`, `rhel8`, `rhel9`, `alma8`, `alma9`, `ol8`, `ol9`,
`centos8`, `centos9`, `ubuntu22`, `ubuntu24`, `debian12`, ...) — this is
what the controller matches against uploaded OS Scripts. A minimal image
with no `/etc/os-release` falls back to parsing `/etc/rocky-release`,
RHEL-family only (Debian ships `/etc/os-release` universally, so it
doesn't need an equivalent fallback). Override it if the auto-detection
guesses wrong:

```bash
python3 enroll.py --controller ... --token ... --os-family rocky8
```

Separately, and not tied to `os_family` at all: `agent.py` itself detects
which package manager is actually on the host (`dnf` vs `apt-get`, via
`shutil.which`) every time it runs, and picks the matching built-in stage
handlers. `os_family` only controls custom OS-scripts matching — a host
enrolled with the wrong/missing `os_family` still patches correctly with
the right package manager either way.

## Custom OS scripts

If the controller has a script uploaded for this host's OS family and the
current stage (`preflight`, `excludes`, or `patch` — not `reboot`, see the
controller README for why), the agent runs that instead of its built-in
handler. It's written to `/var/lib/kite/stage_scripts/<stage>.sh`
(the stage name is reduced to a bare filename and checked to still
resolve inside that directory before being used, so a malicious/MITM'd
controller can't use it to write outside `stage_scripts/` — see
`run_custom_script` in `agent.py`), `chmod 700`, and executed as
`bash <path>` with these env vars set: `KITE_JOB_ID`,
`KITE_HOSTNAME`, `KITE_STAGE`, `KITE_EXCLUDES`,
`KITE_PINS`. No code changes or redeploy needed on this side to pick
up a new script — it's fetched fresh on every poll. Running whatever
script content the controller sends is the actual, by-design trust
model here (see "Enroll" above and the controller's TLS/`--insecure`
notes) — the path sanitization only guards *where* it's written, not
*whether* it runs.

## Check-in cadence and on-demand triggering

The agent polls the controller on a long, configurable baseline interval
(`--poll-interval` at enrollment, default 900s / 15 min — can be set to
hours) — a plain, quick request with no held-open connection. Earlier
builds of this agent used HTTP long-polling (holding a connection open
server-side for near-instant response); that got dropped deliberately —
held-open connections are exactly what corporate proxies, NAT gateways,
and load balancers tend to silently kill on real networks, and the
symptom looks like `Read timed out` errors in the log with no obvious
cause. If you're upgrading from an agent build that used long-polling,
expect to see that error in old logs — it stops once this version is
installed.

**For instant on-demand action**, touch the local trigger file (needs
root, since `/var/lib/kite` is `0700`):

```bash
sudo touch /var/lib/kite/trigger
```

The agent checks for this file every ~2 seconds while otherwise sleeping
toward its next scheduled poll, and wakes immediately (consuming the
file) the moment it appears. This mirrors how Qualys's own on-demand
scan works — their real, documented mechanism is a local flag (a
registry key on Windows, a shell script on Linux) the agent watches
locally, not a network push from their cloud. If you already have
SSH/Ansible/cron access to a host — which as the fleet operator you do —
this gives you "run now" with zero network complexity and nothing that
can be silently dropped by a proxy in the middle.

A controller-initiated "run now" click in the web UI still waits for the
next scheduled poll under this design (bounded by whichever
`--poll-interval` that host was enrolled with) — there's no way around
needing *some* signal to reach the agent without either an inbound port
or a persistent connection, and we've deliberately chosen not to keep
either of those. Keep the baseline interval short if this matters to
you; the trade-off is explicit, not hidden.

## Testing without touching real packages

```bash
python3 agent.py --dry-run --once
```

`--dry-run` logs every command it *would* run (`dnf update -y ...`,
`dnf versionlock add ...`, `systemctl reboot`, etc.) instead of executing
it, and `--once` polls a single time instead of looping — useful for
confirming the agent talks to the controller correctly before it's
allowed anywhere near a real `dnf update`. This is also how the flow was
tested while building it, against the controller directly.

There's also a real (if narrow) unit test suite now — `pip install -r
requirements-dev.txt && pytest` — covering package-manager detection and
the dnf/apt stage-handler command construction (which commands get built,
in what order, how a failure partway through propagates) via mocking
`run_cmd`/`subprocess`/`os.path.exists`, no real host needed. It does
**not** cover actually running those commands against a real package
manager — see "Known gaps".

## Why the reboot stage is different from the others

Every other stage runs a command and reports the result synchronously.
Reboot can't — the agent process triggering the reboot is a process
about to disappear mid-job. So `stage_reboot`:

1. If `needs-restarting -r` says no reboot is needed, reports `done`
   immediately, same as any other stage.
2. If a reboot is needed, it writes the job id to
   `/var/lib/kite/pending_reboot.json` **before** rebooting, then
   calls `systemctl reboot` and returns `'deferred'` — nothing is
   reported yet.
3. systemd restarts the agent after boot (`Restart=always`). On every
   startup, `resume_pending_reboot()` checks for that state file — if
   present, it reports the `reboot` stage `done` (with the host's
   current uptime as evidence it actually came back) and deletes the
   file.

If the host never comes back — a real failure case worth testing before
you trust this in front of anyone — the job sits at `reboot: running` on
the controller until the controller's own stuck-stage detection catches
it (default: flagged after 15 minutes for `reboot` specifically, shorter
than other stages — see the controller README's "Metrics & monitoring"
section). That's detection, not resolution: the controller still can't
reach into the host to do anything about it, a human decides via Force
Stop.

## Known simplifications worth knowing about

- `stage_excludes` (dnf) builds the versionlock spec as
  `<pattern-minus-*>-<version>*` (e.g. `filebeat*` + `8.x` →
  `dnf versionlock add "filebeat-8.x*"`). That's right for the common
  case but not exhaustive versionlock syntax — worth testing against your
  actual package names before relying on it, especially for packages with
  epochs.
- `stage_excludes` (apt) uses `apt-mark hold`, which only accepts exact
  installed package names — no wildcard support like dnf's
  `--exclude`/`versionlock`. A pattern with a `*` in it is reported back
  as skipped rather than silently matching nothing; if you're sharing
  patch definitions across RHEL-family and Debian-family hosts, keep
  wildcards out of any pattern you need to actually take effect on both.
- The pins and holds the agent places are recorded in
  `/var/lib/kite/holds.json`. At each run's excludes stage, any of
  them no rule asks for any more (the rule was removed or its version
  changed) is released first. A hold placed by hand isn't in that file
  and is left alone.

## Known gaps (Debian/Ubuntu support specifically)

- **No `.deb` package or apt repo yet** — `install-debian.sh` is the
  Debian-family equivalent of `install.sh`, not of the RPM path. A real
  `.deb` + hosted apt repo (mirroring `packaging/build.sh` and the
  controller's automatic RPM repo signing) is real follow-up work, not
  done here.
- **macOS isn't covered at all** — a known gap, not silently ignored;
  see `controller/ROADMAP.md`.
