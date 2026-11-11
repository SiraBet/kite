# kite-controller

The controller half of kite: the database, the job/stage engine, the
patch-definition and checklist logic, the web console, and the
agent-facing API. It runs on its own host and **never connects into your
machines** — agents (`agent-linux/` for RHEL- and Debian-family hosts,
`agent-windows/` for Windows) poll this API and execute locally.

## Worth knowing before you read further

- **Runs need an agent.** A run started from the console sits at the
  `preflight` stage until a matching agent is actually polling that host.
- **Auth is session-based with server-enforced roles** (Operator / Lead /
  Admin) — see `app/auth.py` and `app/routers/auth_router.py`. The roles
  are enforced server-side, not just hidden in the UI.
- **Change control is opt-in.** Checklists always apply. Approval tickets
  and maintenance-window enforcement are built and supported but off by
  default (`require_ticket`, Settings → Policy) — see `app/settings_store.py`.
- **Tickets are a local table**, created through the API and shaped like a
  ServiceNow/Jira response, so pointing it at a real ITSM later doesn't
  change anything downstream. If you don't turn ticket gating on, none of
  this is in your way.

## OS-specific scripts (optional overrides)

By default, `preflight`, `excludes`, and `patch` run the agent's built-in
logic for that host's package manager (dnf, apt, or Windows Update). You
can override any of those three, per OS family (e.g. `rocky8`, `rocky9`,
`win2022`), by uploading a script via **Per-system scripts** — useful once
you're managing OS families with genuinely different patching needs, or an
OS the built-in handlers don't cover.

- **One active script per (OS family, stage)** — uploading a new one
  replaces the old one (which moves to history), it never stacks. This is
  deliberate: two scripts fighting over the same stage is exactly the
  failure mode to avoid.
- **Groups of machines you choose.** A group is any set of machines, of
  any OS: make one on **Per-system scripts** (+ New group), rename or
  delete it there, and add machines one or many at a time, there or from a
  machine's page (Admin → Groups). A machine can be in several groups. A
  group can carry its own scripts: for each stage a machine runs its
  group's script, else its OS family's, else the built-in default. At
  most one of a machine's groups may have a script for any one stage, and
  a group with scripts holds Windows or Linux machines, not both; adding
  machines or uploading is refused otherwise, so it's never a guess which
  script runs. Removing a group's scripts leaves the group; deleting a
  group keeps its scripts in history. Changes are admin-only and logged.
- **New uploads start "untested"** — the UI warns (but doesn't block) before
  a run that would use one, and it flips to "tested" automatically the
  first time it completes successfully on any real host.
- **`reboot` is NOT scriptable** — the built-in reboot handler persists
  state to disk before rebooting so the agent can resume and report back
  after the host comes up. A custom script has no way to hook into that
  and would leave a job stuck at `reboot: running` forever if it rebooted
  the host itself. See `app/models.py`'s `SCRIPTABLE_STAGES` comment.
- Fully-worked templates are in `examples/os-scripts/`:

  | Directory | What it adds over the family template |
  |---|---|
  | `rhel-family/` | generic dnf: retries, pin-state reconciliation |
  | `rocky8/`, `rocky9/` | the EL8/EL9 differences — `needs-restarting` moved package, EL9's crypto policy rejecting SHA-1-signed repo metadata, an `os_family` sanity guard |
  | `windows-family/` | PowerShell/WSUS equivalent |
  | `win2019/`, `win2022/` | build-number guard and per-release `winget` coverage |

  Download, customize, re-upload.
- **Or ask an AI coding assistant to write one.** The repo ships
  instructions at `ai/skills/kite-stage-script/` (pointed to by the root
  `AGENTS.md`) — open the repo in your assistant and ask for a stage script
  for whatever `os_family` your hosts report. They cover
  the contract below, which stages are scriptable, and the per-distro traps
  (apt has no severity metadata, Windows Update cannot pin a version), so it
  writes to the real constraints instead of guessing.
- Custom scripts run on Linux and Windows alike, to the same contract: the
  Windows agent writes the script out and runs it under
  `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass`.
- A custom script is given the run's severity scope as `KITE_SEVERITY`
  (`''`/`all`, `security`, or a list like `Critical,Important`), so a custom
  `patch` script applies the same scope the built-in handler would. Agents
  older than this variable simply don't send it; the `rocky8`/`rocky9`
  `patch.sh` templates warn loudly and fall back to
  `KITE_SEVERITY_DEFAULT` (set it to `security` if you would rather an
  old agent stay narrow) rather than quietly patching everything.
- Scripts run as root (same as everything else the agent does) and get
  these env vars: `KITE_JOB_ID`, `KITE_HOSTNAME`, `KITE_STAGE`,
  `KITE_EXCLUDES` (space-separated skip patterns), `KITE_PINS`
  (space-separated `pattern=version`), `KITE_SEVERITY` (the run's
  severity scope). Exit 0 = success, anything else =
  failed; combined stdout+stderr is captured as the stage output.

## Enrollment: per-host token vs. shared secret

Two ways to authorize a new host, same trade-off Wazuh and Qualys make:

- **`POST /enroll/tokens`** — one-time, per-host, expires. Tightest
  scope: each host is individually authorized by whoever runs this.
  Default, no config needed.
- **`POST /agent/self-enroll`** — a shared secret, reused across every
  host's install command. Zero admin action per host after that —
  bootstraps enrollment only, and is replaced by a unique per-host
  credential immediately on success, same as Wazuh's `authd` password or
  Qualys's Activation ID. **Always enabled**, not opt-in: if you don't
  pin `KITE_ENROLL_SECRET` in `.env`, the controller generates one on
  first start, prints it to the log, and saves it beside the database
  (`enroll_secret`, mode 0600) so it stays the same across restarts —
  rather than treating "pick a secret" as a blocking first-install
  decision. Persisting it matters: a secret regenerated on every start
  would silently invalidate every install command carrying it as soon as
  the controller restarted.
  Anyone holding the current secret can enroll a host under any hostname
  they claim — reasonable for a single-operator lab on a private
  network, not for anything wider. Rotate it by deleting that file (or
  changing the pinned value) and restarting. Self-enrollments are
  tagged `warning` tone in the audit log so they're visually distinct
  from token-based ones.

  `KITE_SECRET_KEY` — the key encrypting the Proxmox token and
  notification secrets — works the same way and is persisted for a
  stronger reason: it isn't just inconvenient when it changes, it makes
  everything encrypted under it permanently unreadable. Set
  `KITE_STATE_DIR` to keep both somewhere other than beside the
  database.

## Home dashboard

Every login lands on Home. It answers "is my fleet OK, and is anything
happening right now" without a click: reachability and what's dragging
it down, hosts needing attention ranked offline → stale → unpatched,
in-flight runs with live stage progress, the next scheduled runs, recent
activity, and platform/team/agent-version breakdowns.

It's served by one endpoint, `GET /dashboard`, rather than the browser
calling `/hosts` + `/runs` + `/audit` + `/schedules` and reducing them
client-side. Three reasons, in `app/routers/dashboard.py`'s own words:
it's the most-loaded view in the app so four round trips is the wrong
shape; several of the numbers need a whole table to compute but yield a
single integer, which shouldn't be computed in a place that can't be
tested; and connectivity tiering already exists in Python
(`app/monitoring.py`) so the dashboard reuses it rather than adding a
third caller of the JavaScript copy.

## Risk-based patching

Every run used to apply everything available. Real patch programs patch
by risk: "Critical and Important this cycle, defer the rest." kite
reports what's pending per host with its severity, and a run can be
restricted to a severity band.

Severity comes from **the host's own repository metadata**, read by the
agent — no external feed, no API keys, and nothing for the controller to
reach out to. The two package managers differ in what they can answer,
and the difference is reported rather than smoothed over:

| | Source | Severity |
|---|---|---|
| dnf | `dnf updateinfo list --available` | Real per-advisory levels: Critical, Important, Moderate, Low, plus an advisory id |
| apt | `apt list --upgradable` | **None published.** A security update is identifiable by its origin suite (`*-security`); its severity is recorded as `unknown` |

`unknown` is not `low`. Assigning apt security updates a level nobody
published would be inventing a number, so the console shows them as
"Security" with no level.

### "We don't know" is not "nothing pending"

A single unreachable repository fails a host's entire update query. If
that were reported as zero, the host would appear fully patched while
carrying dozens of outstanding advisories — so the agent reports whether
the assessment *ran*, separately from what it found:

- A failed query does **not** clear the last known list. Blanking it
  would read as "this host is now fully patched".
- The host page says the package manager could not be queried, rather
  than showing an empty, reassuring list.
- The dashboard counts unassessed hosts **separately**; they are never
  folded into the totals.

### Restricting a run

`severity_filter` on a run or schedule:

| Value | Effect |
|---|---|
| `""` / `all` | Every available update (the default, and what every run did before) |
| `security` | Security advisories only |
| `critical,important` | Those severities only |

dnf enforces all three natively (`--security`, `--sec-severity=`). Note
that `--sec-severity` is ignored unless `--security` is also passed, so
kite always sends both — the alternative is silently patching
everything when the operator asked for Critical only.

apt cannot honour a severity band, so one degrades to security-only and
**the stage output says it did**. The run wizard warns before you start
rather than leaving it to be discovered afterwards. apt's security-only
path resolves the security-origin packages and runs
`apt-get install --only-upgrade` on exactly those, rather than a blanket
`upgrade`.

A typo in a severity (`hihg`) is refused at run creation. Matching
nothing would patch an empty set and report success.

### Patching several machines at once

Select machines in Fleet and click **Patch N machines**. The steps are
the same as for one machine (ticket, checklist, scope, severity),
confirmed once for all of them. The confirm step lists each machine
with its pending updates and safety net. You must choose how they roll
out:

- **One at a time.** Each machine starts when the previous one has
  finished, health check included. If one fails or is force-stopped,
  the batch pauses: **Continue with the next machine** or **Stop the
  rest**.
- **In parallel.** Every machine starts now; a failure on one doesn't
  stop the others.

Every machine is checked before anything starts (no other run going,
containers to update when the scope includes them), so all the problems
show at once. Each machine still gets its own ordinary run, with its own
snapshot, history and page. The batch page lists them in order with
where each is; a machine that can't start when its turn comes (someone
started another run on it meanwhile) is skipped and noted. Stopping a
batch starts nothing more; a run already going carries on, and can be
force-stopped from its own page. A batch updates every compose-managed
container on each machine; to pick containers, patch a machine on its own.
`POST /batches` with `rollout` `one_at_a_time` or `parallel` (required),
`GET /batches/{id}`, `POST /batches/{id}/continue`, `POST /batches/{id}/stop`.

### When an update can't be installed

A repository sometimes offers an update the machine can't install: a
build for a newer OS release that needs a newer glibc, or a vendor repo
missing a dependency. dnf then refuses the whole transaction, so nothing
is installed. The patch step says which package, from which repository,
and what it needs, before dnf's own output. The run page lists each one
with **Add skip rule** (admins), which creates a `skip` update rule for
that package on that OS family.

To install everything else instead, turn on **Settings → Policy → Skip
updates that can't be installed**. dnf hosts then run with `--nobest
--skip-broken`, and the run lists what it left at the current version.
It's off by default: a package that silently never gets patched is worse
than a loud failure.

apt never fails a whole upgrade this way: it leaves such updates out and
installs the rest. The run says which, and why:
**kept back** (the update needs a package added or removed, often a new
kernel, which `apt-get upgrade` never does; the run gives the
`apt-get install --only-upgrade …` to install them, plus a **Skip**
button per package for admins) and **phased** (Ubuntu is rolling it out
gradually; it installs on a later run by itself).

### Where risk shows up

- **Home** — an Outstanding risk card: totals by severity, hosts
  carrying Critical, and the most exposed hosts.
- **Fleet** — a Risk column, sortable. Worst severity first, then volume
  within a level, because one Critical needs attention before forty
  Moderates. Counts come from one grouped query for the whole list.
- **Host detail** — every pending update, most severe first, with its
  advisory id.
- **`/metrics`** — `kite_pending_updates{severity=…}`,
  `kite_hosts_unassessed`, `kite_containers{managed_by=…}` and
  `kite_containers_outdated`. Unassessed hosts are their own series
  rather than a severity bucket: an alert rule that treats unknown as
  zero is the one that lets a fleet rot quietly.
- **Notifications** — a `critical_update_found` event when a Critical or
  Important update *newly appears* on a host. Only new findings fire;
  re-announcing the same advisory on every check-in would turn the
  channel into noise nobody reads.

## Container inventory

Agents report what containers their host is running, so a fleet that is
fully patched at the OS level can still be seen to be running a
two-year-old image. Home carries a fleet-wide summary; each host's detail
page lists its containers.

`docker pull` is not an update — it fetches a new image and leaves the
running container on the old one. Updating means **recreating** the
container, and whether that is safe depends entirely on how it was
created, which is why kite records that and acts only on the one
case with a safe answer:

| Managed by | What kite does | Why |
|---|---|---|
| Compose | **updates it** — `pull` then `up -d` in the recorded project directory | The compose file records ports, volumes, env and restart policy, so recreation reproduces the deployment rather than guessing at it |
| Standalone `docker run` | reports it, never touches it | The flags exist only in someone's shell history; `docker inspect` reconstructs most of them, and the parts it gets wrong are how a volume mount disappears |
| Kubernetes / Swarm / Nomad | reports it, never touches it | The orchestrator owns lifecycle — an out-of-band change is either reverted or bypasses the rollout safety it exists to provide |

## Run scope: the OS, the containers, or both

A host's packages and the containers on it are independent surfaces.
Patching the guest leaves a stale image running; pulling an image does
nothing for the kernel underneath. So a run picks what it touches:

| Scope | Pipeline |
|---|---|
| `os` (default) | preflight → snapshot → excludes → patch → reboot → healthcheck → soak |
| `containers` | preflight → snapshot → containers → healthcheck → soak |
| `both` | preflight → snapshot → excludes → patch → reboot → **containers** → healthcheck → soak |

A containers-only run drops the package stages entirely rather than
running them as no-ops — a skipped stage reads as something having gone
wrong, and `reboot` in particular should not appear when nothing was
installed that could require one. In `both`, containers come **after**
reboot: container lifecycle is independent of the guest's, so updating
images first would just have them restarted moments later.

Scope is chosen on the run wizard's confirmation step, alongside a
per-container picker (defaulting to every updatable container), and on a
schedule when you create it. Both are set per run and per schedule, so
"OS monthly, images weekly" is two schedules rather than a compromise.

Selection is **frozen at run creation**: a container started after the
operator confirmed the checklist is not swept in. A schedule resolves
its own selection per host at fire time instead, since a weekly schedule
across a team should pick up whatever each host is running that week.
A containers-only run against a host with nothing updatable is refused
rather than completing successfully having done nothing.

### Rollback: one capture per service

Before updating a compose service, the agent tags the image it is
currently running as `kite-rollback/<project>_<service>:previous`.
That tag **is** the rollback point.

For a compose service specifically, the image is the only thing an
update changes — the compose file supplies ports, env, volumes and
restart policy, and volumes persist across recreation. So capturing the
image captures everything the update touched.

`docker tag` copies nothing; it is a second name for an image already on
disk. The cost is that the old image stops being garbage-collectable,
which is the point. The tag name is deterministic per service, so each
update **moves** it onto the new capture and the previous image becomes
untagged and collectable: exactly one retained image per service, no
accumulation, no configuration to bound it.

A capture failure aborts the run before anything is pulled. Updating
without a way back is what the capture exists to prevent.

Rolling back re-points the compose file's own image reference at the
captured image and recreates — the project on disk is never edited. It
runs as its own job (`scope: containers`, `container_action: rollback`),
never mixed with OS patching: an undo and a change in one run, under one
audit entry, is not something anyone can reason about afterwards. The
Fleet host page has a **Roll back** button per service that has a
capture.

**Volumes are not captured.** If a newer image migrated a schema or
rewrote files in a volume on first start, restoring the image does not
undo that. The confirmation dialog says so. For workloads where that
matters, use a host with the `proxmox` rollback backend — a VM snapshot
does capture volume state, since it is all on the same disk.

A capture removed out of band (`docker image prune`, a manual `rmi`)
stops being offered: the agent reports what is actually present on each
inventory pass rather than trusting its own history.

`compose pull` runs with `--ignore-pull-failures`. A project that mixes
registry images with locally built ones is ordinary, and an image in no
registry can never be pulled — aborting there would mean such a project
could never be updated at all. Pull output stays in the stage record, so
a failure is visible rather than hidden; `up -d` is the step whose
failure fails the stage, because it is the one that changes what runs.

**"Update available" is tri-state, and the third state matters.** True
means the tag has demonstrably moved upstream; false means it
demonstrably has not; **null means the comparison could not be made** —
a private or unreachable registry, or a locally built image. Null is
displayed as "not determined" and counted separately, never folded into
"up to date". Claiming an image is current on the strength of a check
that failed is the one answer worth avoiding.

Digest-pinned images (`name@sha256:…`) are frozen deliberately, so they
are never queried and never offered as updatable.

The comparison is between **config digests** for the host's own
platform, not repo digests. A multi-arch tag's repo digest is the digest
of the manifest *list*, while a registry query returns per-platform
manifests — comparing those two reports drift on every image, always.

Enumeration is local and cheap and runs on each idle poll. The registry
lookup costs one round trip per distinct image and is throttled
separately (`KITE_DRIFT_INTERVAL`, default 6h). A host with no
container runtime reports an empty list, which correctly clears anything
previously recorded for it.

Registry credentials are not managed by kite — the agent uses
whatever the host already has. A host that can pull an image can check
it; storing registry credentials here would add a secret to protect for
no capability gained.

## Developing against a realistic fleet

The console is shaped entirely by data, and until recently the only way
to get any was to enroll real hosts — which made "fix something on a
page" start with half an hour of setup, and meant the empty state was
the only state most contributors ever saw.

```bash
cd controller
KITE_DB=dev.db python3 tools/seed_dev_fleet.py
KITE_DB=dev.db python3 -m uvicorn app.main:app --port 8000
```

15 hosts across 3 teams and 4 OS families, a run mid-flight, finished
and failed history, two schedules, and an activity feed. Deliberately
not all green: some hosts are offline, one has never been patched, one
is well past 30 days — a seed where everything is healthy exercises
nothing.

Add `--scale 400` (into a fresh database) for a large fleet: that many
more machines with long names, 40 groups, 80 update rules, pending
updates, vulnerabilities, a 120-machine batch and 3,000 activity
entries. Check a page change against it: a page that looks fine with 15
machines can stretch, overlap or slow down with hundreds. Long lists in
the console are paged, capped with "+N more", or scroll inside their
panel for this reason.

This is a developer tool, not a demo mode. Nothing in the shipped
product seeds itself, no endpoint calls it, and it refuses to touch a
database that already has hosts unless you pass `--force`. A fresh
install still starts empty.

## Console layout

`frontend/` is a 64-line HTML shell plus `css/app.css` and 18 JavaScript
files under `js/`, served from the `/ui` mount.

They're plain classic scripts sharing one global scope — no bundler, no
modules, no build step, the same trade the rest of the project makes.
That means **load order is load-bearing**, and `kite.html` is the
manifest: function declarations hoist, but the top-level `const`s
(`state`, `api`, `ICONS`, `navItems`) do not, so a file that reads one
must come after the file that defines it. `app.js` is last because it
calls into every view.

`tests/test_frontend_render.py` reads that manifest rather than
hardcoding a list, so a file added to one and not the other fails a test
instead of producing a blank page; two more tests catch a JS file that
nothing references and a referenced file that doesn't exist.

Each sidebar tab remembers where you were (a run's progress, Coverage,
a settings tab). Clicking the tab you're already on, or double-clicking
it, goes to its main page. **Run patching**'s own page lists runs in
progress and recent ones.

## Testing the console

`tests/test_frontend_render.py` executes the console's JavaScript in a
real V8 engine (via `py-mini-racer`) and renders every view against
representative state — no browser, no build step, no headless-Chrome
dependency, because the views are pure functions from `state` to an
HTML string.

It catches syntax errors, undefined identifiers, a view that throws when
its data is still `null` on first paint, unescaped interpolation of
attacker-influenced text (hostnames come from enrolling agents), and
elements that ended up with two `class` attributes — which browsers
resolve by silently discarding the second. It does not catch anything
about layout, CSS, or real click behaviour; those still need a browser,
and the file says so.

## Upgrading an existing deployment

Pull the new code and re-run the installer, which restarts the
controller and rebuilds any agent whose version changed:

```bash
sudo git pull
sudo ./controller/controller-install.sh
```

or, for the Docker path, `docker compose up -d --build`: the image
builds the agents, and the controller copies any newer than the ones in
its data volume on start. Either way, enrolled agents then update
themselves (Settings → Policy → Agent updates). A plain `systemctl
restart` after `git pull` updates the controller but keeps handing out
the old agents.

Schema changes are applied automatically on startup by Alembic (see
`migrations/`). There is no hand-run SQL step:

- **`init_db()` runs `alembic upgrade head`.** Before this, it called
  `Base.metadata.create_all()`, which creates missing *tables* but never
  adds missing *columns*. That is why the manual step existed at all,
  and why skipping it produced a controller that started up perfectly
  and then failed every query with `no such column`.
- **Any database, any age, is handled.** `migrations/versions/0001_baseline.py`
  reconciles rather than assuming a blank slate: tables that don't exist
  are created, tables that do exist get whatever columns they're
  missing. A database from any earlier kite comes forward in one
  step, with its rows intact.
- **A copy is taken first.** Whenever there's actually a migration to
  apply, the controller writes `kite.pre-migration-<timestamp>.db`
  next to the live database before touching it, and logs the path. To
  roll back a bad upgrade: stop the service, move that file over
  `kite.db`, check out the previous code, start again. The newest
  five copies are kept and older ones deleted
  (`KITE_DB_BACKUPS_KEEP`; `0` keeps them all).

Nothing about the backfilled values changed from the old manual
procedure. `hosts.rollback_backend` / `jobs.rollback_backend` are NULL
on existing rows, meaning "no per-host override, use the global
default"; `patch_defs.os_family` is `''`, meaning "applies to every OS
family"; `users.auth_source` is `'local'`, since every account that
already existed was created locally and none should suddenly be treated
as LDAP-managed. `jobs.hostname` (a snapshot of the host's name at job
creation, so a job stays identifiable if its host is later deleted) is
left NULL on old rows and displayed as unknown rather than guessed.

On first startup after upgrading from an early build,
`bootstrap_checklist()` seeds `checklist_items` with the same 4 items
that ship as the default template, so existing runs don't
suddenly see an empty — and therefore trivially "fully confirmed" —
checklist.

**Restart, don't just re-run the installer.** `controller-install.sh`
explicitly restarts the service on every run now — an earlier version
used `systemctl enable --now`, which is a no-op on an already-running
service, so an upgrade could silently leave old code running in memory
indefinitely even after new files were copied to disk. If you're on an
older copy of the script, add `sudo systemctl restart
kite-controller` after it finishes, to be sure.

### Backing up

**Automatic:** once a day the controller takes a consistent, compressed
copy of its database (sqlite's online backup API, safe while agents are
writing) into `backups/` beside it (`KITE_BACKUP_DIR` to move it,
e.g. to another disk), readable by the service only. It keeps the newest
**7** and deletes older ones after each backup: Settings → Policy →
Database backups changes the number, 0 turns them off, and **Back up
now** takes one on demand. Admins can download any of them there, from a
console login only (never with an API token); taking and downloading are
in the Activity log. Session and enrollment tokens are stored only as
hashes, so a backup holds no sign-in anyone could reuse. They sit on the controller's
own disk, so download one now and then, or point `KITE_BACKUP_DIR`
at other storage.

The activity log is kept for **365** days (same card; 0 keeps it all).
Older entries are removed in the same daily pass, after the backup, so
the day's copy still holds them.

**Restoring** is done on the controller, on purpose not from the
console:

```bash
sudo systemctl stop kite-controller
cd /opt/kite-controller
sudo -u kite sh -c 'gunzip -c backups/kite-<when>.db.gz > kite.db.restored'
sudo -u kite mv kite.db kite.db.before-restore
sudo -u kite rm -f kite.db-wal kite.db-shm
sudo -u kite mv kite.db.restored kite.db
sudo systemctl start kite-controller
```

A copy taken by hand works the same way. Use the online backup API, not
`cp`: the database runs in WAL mode (see `app/db.py`), so recent commits
live in a separate `-wal` file and a plain file copy can capture a
database missing its newest writes, or a torn one if an agent commits
mid-copy.

### Adding a schema change (contributors)

Edit `app/models.py`, then generate a revision:

```bash
cd controller
alembic revision --autogenerate -m "add whatever_column"
```

Review the generated file — autogenerate is a starting point, not an
oracle — and commit it alongside the model change.
`tests/test_migrations.py` fails if the models contain anything no
migration creates, so a forgotten revision is caught in CI rather than
on someone else's install.

## The agent's dnf repo (so hosts can `dnf install kite-agent`)

The controller serves `repo/` as a dnf repository at `/repo`, already
populated by the installer or a release tarball, and signs it itself
(see "GPG-signing the repo" below). The console's **Add machine**
command sets a host up against it; by hand, see `INSTALL.md` step 3.

After copying an RPM you built into `repo/` by hand, publish it with

```bash
cd /opt/kite-controller && sudo -u kite venv/bin/python -m app.repo_signing
```

which signs it, refreshes the repo metadata (`createrepo_c`) and signs
that too. Running `createrepo_c` on its own leaves the index signature
stale, and hosts checking it then refuse the repo.

The repo file the console writes on each host contains two settings
worth knowing about:

`metadata_expire=300` makes dnf re-read this repo's package list once
it's five minutes old. dnf's default is 48 hours, so without it a plain
`dnf update kite-agent` can miss a newly published agent for two
days. The repo is tiny; checking it costs nothing.

`skip_if_unavailable=1` is not optional politeness. Without it, dnf
treats an unreachable repository as a hard error and **every** dnf
command on the host fails — including `dnf update`. A controller that is
down, moved, or simply not listening would therefore stop the hosts it
manages from being patched at all, by kite or by anyone, and would
break unrelated work like `dnf install` on every one of them. With it,
dnf logs a warning and carries on; the only thing lost while the
controller is away is the ability to install or upgrade the agent
itself.

### GPG-signing the repo

Automatic. On first start the controller makes a signing key (RSA 4096,
in `signing/` beside the database, readable by the service only; never
copy it off the controller), and on every start it signs any agent RPM
not yet signed, publishes the public key as `repo/RPM-GPG-KEY-kite`
and signs the repo index (`repomd.xml.asc`). Hosts also check the
controller's certificate (see "The controller's certificate authority"),
but the signature is what a package is judged by wherever it came from. After
copying an RPM into `repo/` by hand, sign it straight away with
`sudo -u kite venv/bin/python -m app.repo_signing` (from
`/opt/kite-controller`) instead of waiting for a restart.

Needs `gnupg2`, `rpm-sign` and `createrepo_c` on the controller (the
installer and the Docker image include them). Without them the repo
stays unsigned, the startup log says why, and enrolment falls back to
`gpgcheck=0`.

New hosts are enrolled with `gpgcheck=1` and `repo_gpgcheck=1`. Hosts
enrolled before the repo was signed switch themselves over: on start
the agent fetches the key once, imports it and turns both checks on in
its `kite.repo`. It never replaces that key on its own;
if the controller is reinstalled with a new key, the agent logs it and
keeps the old setting until someone removes
`/etc/pki/rpm-gpg/RPM-GPG-KEY-kite` on the host and restarts the
agent.

### The controller's certificate authority

With the default self-signed setup, Caddy issues the controller's
certificates from its own local CA: a new certificate every 12 hours, a
new intermediate every week, all under one root that lasts ten years.
The controller publishes that root at `GET /download/ca.crt` (no login
needed: it's a public certificate) and shows its SHA-256 fingerprint
with the enrol commands, so a host can check it's talking to this
controller rather than turning certificate checks off. It's the same
fingerprint a browser shows for the root.

The controller reads the root from Caddy's admin API on the same machine
(`KITE_CADDY_ADMIN`, default `http://localhost:2019`), and only
while Caddy issues the certificates itself: with `--domain` (Let's
Encrypt) nothing is published and agents check the certificate the
usual way. Behind another proxy, or under Docker (where Caddy's admin
API isn't reachable from the controller's container), give the root as
a PEM file with `KITE_CA_CERT`. From Docker's Caddy:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./controller-ca.crt
```

then mount that file into the controller container and point
`KITE_CA_CERT` at it. Without a root to publish, enrol commands
keep turning certificate checks off, as before.

If Caddy's data is lost, it makes a new root, and hosts that pinned the
old one can't connect until they're enrolled again.

## Automatic VMID resolution

Proxmox stamps every VM with a random SMBIOS UUID, and that same value
is readable from inside the guest at `/sys/class/dmi/id/product_uuid` —
no root, no qemu-guest-agent needed. The agent reports this at
enrollment; the controller (which already holds Proxmox API access for
snapshots) cross-references it against every VM on the configured node
to find the matching numeric VM ID, and sets `proxmox_vmid`
automatically. No manual step, no copying VM IDs out of the Proxmox UI.

An agent can also name its VM ID itself (`enroll.py --vmid`). Because
that link decides which VM gets snapshotted and restored, the controller
only takes it from a one-time token enrollment, and only for a host that
has no VM linked yet. It is ignored with the shared enrollment secret,
and it never replaces an existing link: change one with
`PATCH /hosts/{id}`. Either case is recorded in the activity log as
`enroll_vmid_ignored`.

If it doesn't resolve at enrollment time (Proxmox creds weren't
configured yet, or a transient API issue), retry it later — either the
"resolve VMID" button next to that host in the Fleet tab, or
`POST /hosts/{id}/resolve-vmid`.

## Rollback backends

The `snapshot` stage resolves to a backend per host rather than one
hardcoded Proxmox VM snapshot — which left bare-metal, cloud, and plain KVM/libvirt hosts with
no safety net at all. It's pluggable now (`app/rollback/`), resolved per
host: a per-host override (Fleet → host detail → "Rollback backend") if
set, else the global default (Settings → Policy → Rollback safety net). A
mixed fleet doesn't have to pick just one.

Two backends ship today:

- **`proxmox`** (default, unchanged behavior) — a real VM snapshot via
  the Proxmox API, executed by the controller. Needs `proxmox_vmid` set
  on the host (see "Automatic VMID resolution") and the connection
  details below.
- **`dnf_history`** — no hypervisor needed. The *agent* (not the
  controller — this genuinely runs on the host, not against an API)
  captures the current `dnf` transaction id right before patching, and
  reports it as the reference point: `dnf history undo <id>` reverts
  this run if needed. RHEL-family only. Lighter-weight than a full
  snapshot, and the trade-off is real: an undo-last-transaction safety
  net, not a full point-in-time restore — good enough for "this patch
  broke something, put the packages back," not for "revert everything
  including config file changes."
- **`none`** — an explicit, visible opt-out. The stage reports "skipped
  intentionally" (audit-logged) and the run proceeds with no safety net,
  rather than either failing the job or silently pretending something
  was captured.

Nothing here ever automatically restores/rolls back — that's true of the
`proxmox` backend today too, and stays true for `dnf_history`: a human
decides, using the reference the stage captured. Automatic rollback isn't
what this phase built.

**Configuring Proxmox connection details** — Settings → Connections in the
console (which also has a **Test connection** button), or `.env` (`PROXMOX_HOST`/`PROXMOX_NODE`/`PROXMOX_TOKEN_ID`/
`PROXMOX_TOKEN_SECRET`/`PROXMOX_VERIFY_SSL`, unchanged from before this
phase). Both work, resolved field-by-field with the DB (Settings UI)
taking priority — an existing `.env`-configured deployment keeps working
with zero migration, and a fresh one can be configured entirely through
the UI, no file editing or restart needed. The token secret you enter via
Settings is encrypted at rest (`app/crypto.py`, Fernet/AES) under
`KITE_SECRET_KEY` — auto-generated and printed to the startup log if
unset, same pattern as `KITE_ENROLL_SECRET`, but pin it (`.env` or a
systemd credential, see `kite-controller.service`) before entering
anything real: unlike the enroll secret, losing this key after something
is encrypted under it makes that value permanently unreadable, not just
in need of re-pinning.

**Not built yet** (see `ROADMAP.md`): LVM/Btrfs/ZFS local
snapshots for bare metal, and cloud provider snapshot APIs (EBS, etc).
The architecture is the part this phase actually delivers — adding one of
those is a new file in `app/rollback/` plus (for an agent-side backend
like LVM) a new `stage_snapshot` case in the agent, not a rewrite.

### Cleaning up old snapshots

The Proxmox snapshot taken before each run is a way back from a bad
patch, useful in the days right after it. It isn't a backup: it lives
on the VM's own storage, holds on to every block that changes after it
(LVM-thin, ZFS, qcow2), and long chains slow qcow2 disks. So kite
removes its own old ones, after each successful run and once a day:

- **Settings → Policy → Clean up old snapshots** (on by default): keep
  the newest **2** per machine, none older than **7** days. Either can
  be 0 for no limit, or turn cleanup off to keep everything.
- Only snapshots kite took (`kite-job<run>-<time>`). Anything
  you or Proxmox made is never listed or touched.
- Never removed: snapshots from a run that failed, was force-stopped or
  is still going, and ones marked **Keep**. They don't count towards
  the limit either.
- The machine page lists them with what cleanup will do to each, and
  **Keep** / **Delete now** (lead and above). Every removal is in the
  Activity log.

Deleting uses the same `VM.Snapshot` privilege as taking them.

**Restoring one** is the way back from a bad patch: **Restore** on the
machine page's Snapshots tab, or **Restore that snapshot…** on the page
of the run that took it. Admin only, confirmed by typing the machine's
name, and refused while a run is going on the machine. Proxmox rolls the
VM's disks back to that moment, so everything written since is lost.
kite's snapshots hold no memory, so Proxmox leaves the VM off;
kite starts it again if it was running, which needs `VM.PowerMgmt`
on the token. Without it the VM stays off and the page says so; start
it in Proxmox. Rolling back uses `VM.Snapshot`. Each restore, and its
outcome, is in the Activity log.

The machine page's **Safety net** says what a run there falls back to:
**SNAP** (a VM snapshot: a Proxmox VM id with the Proxmox backend),
**PKG** (dnf history only) or **NONE**.

## Feature completeness

Four independent gaps closed in this phase:

- **Admin-customizable checklist items** — Settings → Checklist items.
  Backed by a real
  `checklist_items` table, editable (add/remove) by an admin, driving
  every run's checklist step. No reordering yet — order is insertion
  order (by id); delete and re-add to reorder. At least one item is
  required at all times (enforced server-side) — a run needs *something*
  to confirm, so the last item can't be removed. Upgrading an existing
  deployment seeds the original 4 items automatically on first startup
  (`bootstrap_checklist()`), so nothing silently changes for existing
  installs.
- **Update rules for any set of machines** — a rule (`POST /defs`)
  applies to every machine, or to any mix of OS families, groups and
  single machines (`targets`: `{"kind": "os" | "group" | "host", "value":
  ...}`; the older `os_family` field still works). A machine gets every
  rule that names its OS family, one of its groups, or itself. What a
  rule applies to can be changed later (`PUT /defs/{id}/targets`, Update
  rules → change), and the change is kept in its history. Enforced where
  rules are sent to an agent (`app/groups.py`'s `rules_for`), not just a
  UI filter. A group a rule names can't be deleted until the rule is
  changed, and a removed machine stays named in a rule rather than
  turning it into an every-machine rule.
- **Scheduled / recurring patching** — Schedules tab. Weekly only for
  now (day-of-week + hour, UTC) — a real "Nth weekday of the month" rule
  (actual Patch Tuesday) isn't built yet. A background loop
  (`SCHEDULER_INTERVAL_SECONDS`, default 300s) checks every enabled
  schedule against the current UTC day/hour and starts a real run — same
  Job/JobStage machinery as a human clicking "Patch this host" — for
  every host in scope (by team, or every host if unset) that isn't
  already mid-run. Two things a scheduled run does differently from a
  human-initiated one, both deliberate and both visible in the audit
  log, not hidden: no maintenance-window check (the schedule's own
  day/hour *is* the intended window), and the checklist is
  auto-confirmed with `confirmed_by: "system (scheduled)"` rather than a
  real person clicking checkboxes — nobody's there to do that at 3am
  UTC. Ticket gating is **not** bypassed: if "require ticket" is on, the
  schedule needs a `ticket_id` pointing at a ticket that's still
  `Approved` at fire time (checked fresh every time, not just when the
  schedule was created) — an un-approved or missing ticket makes that
  cycle skip and log a warning rather than patch anyway. A schedule
  reaches its machines either all at once or **one at a time**
  (`rollout`: `parallel` | `one_at_a_time`; the console offers one at a
  time first). One at a time runs as a batch, in hostname order: the
  next machine starts only when the one before it finished cleanly, and
  a failed or stopped run pauses the rest and sends a notification
  (`batch_paused`) so someone can continue or stop it from the batch
  page. If the schedule comes round again before that happens, what is
  left of the earlier rollout is stopped and a new one starts. Schedules
  created before this option keep firing on every machine at once.
- **Password reset** — Settings → Users → "Reset password" (admin-only).
  Replaces "delete and recreate the account": keeps the user's id, role,
  and audit history intact, sets a **temporary** password (one the admin
  types, or a generated one, shown once), and signs out every existing
  session and API token for that account — doubles as account-recovery for
  a suspected-compromised login, not only a forgotten one. Signing in with
  the temporary password leads straight to **Choose your password**; until
  the user picks their own, the server refuses everything but that and
  signing out. New accounts work the same way unless the admin unticks
  "They choose their own password at first sign-in", and so does the
  first-run admin account. LDAP accounts are untouched: their password
  lives in the directory.

## Integrations

**Outbound notifications** — Settings → Notifications. Three
independent, optional channels, any or all of them at once:

- **Generic webhook** — `POST`s `{"action", "detail", "tone"}` as JSON.
  Works with anything that can receive a webhook.
- **Slack** — a standard Slack incoming-webhook URL, posts a formatted
  message. No first-class Microsoft Teams support — Teams retired its
  old Office 365 Connector webhooks vendor-side, and the replacement
  (Power Automate flows) isn't a stable API surface worth chasing with
  bespoke code; point the generic webhook at a Teams "when a webhook
  request is received" flow instead, which works today.
- **Email** — plain SMTP (stdlib `smtplib`, no new dependency), with
  optional STARTTLS and login. With STARTTLS the mail server's
  certificate is checked against the system's CAs and the configured
  host name, so the login is only ever sent to that server. A relay with
  a self-signed certificate needs that check turned off:
  `PUT /settings/notify_smtp_verify_cert` with `{"value": "false"}`
  (admin). The connection is still encrypted, but no longer
  authenticated.

All three send on the same events: a stage failing, a stage stuck past
its threshold (see "Metrics & monitoring"), a host going offline, or a
schedule skipped for a missing/unapproved ticket. Job completion is
opt-in (`notify_on_success` toggle) — off by default, since a success
message per host per run is noise at fleet scale even though it's a
real, available trigger.

Architecturally, this hooks into `audit.py`'s `log()` — every notable
system event already flows through that one function — rather than
calling a `notify()` function at each individual site in
`jobs_engine.py`/`monitoring.py`/`scheduler.py`, which would be easy to
miss one of. Delivery is synchronous with a 5-second timeout and a
broad exception catch: a notification failure (unreachable webhook, bad
SMTP creds) never breaks the operation it's reporting on, logged as a
warning instead. No queue, no retry — if the channel is down when this
fires, that notification is just gone; a real message queue is more
infrastructure than this project's scope justifies right now.

The webhook/Slack URLs and the SMTP password are encrypted at rest
(`app/crypto.py`, same as the Proxmox token — see "Rollback backends")
and write-only through the Settings UI, same pattern.

**ITSM ticket webhook** — `POST /tickets/webhook`, authenticated with a
shared secret (Settings → Notifications → ITSM ticket webhook, sent as
the `X-Kite-Webhook-Secret` header) rather than a session cookie,
since this is meant to be called by another system, not a logged-in
person. Upserts a `Ticket` row by `ticket_id` — creates it if new,
updates status/window/etc if it already exists, since a real ticket's
status changes over its lifecycle (`Pending approval` → `Approved`, or
withdrawn afterward). Same payload shape as the existing
`POST /tickets` (admin/lead, manual path — still there, e.g. for a lab
with no ITSM behind it) — the stub was already shaped like a real
ticket response before this phase, so this was wiring, not a redesign.
No secret configured means the endpoint refuses every request rather
than accepting unauthenticated ticket writes by default.

Not built (and out of scope for a single self-hosted tool to chase):
bespoke ServiceNow/Jira API clients. Point *their* outbound-webhook
capability at this endpoint instead —

- **ServiceNow**: a Business Rule (or Flow Designer action) on the
  change-request table's `state` field, doing an outbound REST call to
  `https://<controller>/tickets/webhook` with the secret header, on
  approval.
- **Jira**: an Automation rule triggered on issue transition (e.g. to
  "Approved"), with a "Send web request" action to the same URL/header.

Both are configuration on the ITSM side, not code here — untested
against real ServiceNow/Jira instances in this environment (none
available), but the payload contract itself (`ticket_id`, `status`,
`window_start`, `window_end`, `description`, `requester`) is real and
covered by `tests/test_ticket_webhook.py`.

## API tokens and the local MCP server

`tools/kite_mcp.py` lets any MCP client (an AI assistant that supports
the Model Context Protocol) answer questions
about the fleet ("which hosts have critical updates?", "why did run 412
fail?", "what in Proxmox has no agent?"). It is **read-only** and **local**:
the MCP client starts it as a subprocess on your machine, and it calls this
API over your LAN or VPN. Nothing new listens on a port and nothing is exposed
to the internet. It's a single file that uses only the standard library and
runs on Python 3.8+.

It authenticates with an **API token** (`kite_…`):

- Create one in the console (or `POST /tokens` from a session). It is shown once.
- A token acts **as its owner**: it sees only what that user sees, and a role
  change applies at once.
- Every token is **read-only**. Any non-GET request with one is refused (403),
  even for an admin.
- **Expiry is mandatory**, from 1 to 365 days with a default of 90. A token
  never consults LDAP, so a directory-disabled account would otherwise keep a
  working credential.
- Revoked on an admin password reset or account deletion. A token can't list,
  create or revoke tokens; that needs a console login.

Create a token under **Settings → API tokens**. Every role can do this,
including read-only accounts. The confirmation dialog shows how to fetch the
script from this controller (`GET /download/mcp-server`) and the server entry
to add to your MCP client's configuration, filled in. Most clients take the
same JSON shape (some as a command that adds it); to keep the token out of
that file, use a token file instead:

```bash
curl -fsSLo ~/kite_mcp.py https://kite.lan/download/mcp-server
install -m 600 /dev/null ~/.config/kite/token   # paste the token into it
python3 ~/kite_mcp.py --check                   # verify without a client
```

```json
{
  "mcpServers": {
    "kite": {
      "command": "python3",
      "args": ["/home/you/kite_mcp.py"],
      "env": {
        "KITE_URL": "https://kite.lan",
        "KITE_TOKEN_FILE": "/home/you/.config/kite/token",
        "KITE_CA_FILE": "/home/you/.config/kite/root.crt"
      }
    }
  }
}
```

`KITE_CA_FILE` is the controller's root CA for the default self-signed install:
download it from `https://<controller>/download/ca.crt` and check its fingerprint
against the one shown on the Enroll tab (see "The controller's certificate
authority" above). On the
controller itself you can point `KITE_URL` at `http://127.0.0.1:8000`
instead.

What the tools return goes to the model provider as part of the conversation,
so stage output is tail-truncated (`KITE_MAX_OUTPUT`, 4000 chars). Hostnames,
package names and stage output come from the hosts themselves, so the server
tells the client to treat them as untrusted data.

## Installed software

Each agent reports everything installed on its machine,
read-only, with its inventory:

- **RHEL family:** every rpm package (`rpm -qa`), with the source package
  it was built from, which is what RHEL/Rocky/Alma advisories name.
- **Debian/Ubuntu:** every installed deb (`dpkg-query`), with its source
  package, which is what Debian and Ubuntu advisories name.
- **snap and flatpak** apps, where those tools exist.
- **Windows:** the programs in Programs and Features (64- and 32-bit,
  from the uninstall registry), installed updates (KBs), and the exact OS
  build. It runs as SYSTEM, without winget.
- The OS release itself.

The full list goes to the controller only when it changed. Otherwise the
agent sends a hash of it, and the controller asks for the list again
(`software_resend`) if it doesn't hold that one. The machine page's
**Software** tab lists it with a search box (`GET /hosts/{id}/software`).
This is the ground truth vulnerability matching works from.

The winget check (third-party app updates on Windows) also works as
SYSTEM now: when `winget` isn't on the PATH, the agent uses the App
Installer copy under `Program Files\WindowsApps`.

## Vulnerabilities

Off by default. When an admin turns it on (**Settings → Vulnerabilities**),
the controller matches each machine's installed packages against its
distribution's own security advisories and names the CVEs an update
fixes. It is the one feature that connects the controller to the
internet:

- **Source:** [OSV](https://osv.dev)'s public bulk files
  (`osv-vulnerabilities.storage.googleapis.com`, override with
  `KITE_OSV_URL` for a mirror). Only files are downloaded; nothing
  about your machines, not even package names, is sent anywhere.
- **Covered:** RHEL, Rocky Linux, AlmaLinux, Debian and Ubuntu, and only
  the releases your machines run. Windows itself is covered separately
  (below), as are the programs installed on it.
- **Size:** the first download is the whole ecosystem file: 5-30 MB for
  the RHEL family, about 80 MB for Debian, and about 800 MB for Ubuntu,
  which takes several minutes. It is written next to the database, so
  that disk needs about twice the file's size free, and removed after.
  After that, the daily refresh fetches only the records that changed
  (`modified_id.csv`), with a full download every 90 days.
- **What counts:** only records that name a fixed version, so every
  match is something a patch run fixes. Where several kernels are
  installed, only the newest counts. On RHEL 8 and later, an AppStream
  module's advisory is compared only with that module's builds, never
  with the base OS package of the same name.
- **When:** each machine is matched when it reports its software and
  after every refresh.

**Windows itself** (10, 11, and Server 2012 and later) is matched against
Microsoft's [Security Update Guide](https://msrc.microsoft.com/update-guide)
(`api.msrc.microsoft.com`, override with `KITE_MSRC_URL`;
`app/windows_os.py`). The guide lists each CVE per Windows product with
the update (KB) that fixes it and the OS build that update brings.
Windows updates are cumulative, so a CVE counts as open when the
machine's build is below the fixed build and that KB isn't installed.
Only the Windows versions your machines run are asked about, by name
("Windows 10 Version 22H2 for x64-based Systems"): Microsoft learns
those names, nothing about the machines. Each version is a few MB,
fetched whole every day, since Microsoft often revises old entries.
Windows' own components only: .NET, Office and Edge are separate products
in the guide (Edge is matched through NVD, below). A machine whose agent
doesn't report the architecture or Server Core is taken as x64 with a
desktop.

**Software from vendors' own repositories, snaps, flatpaks and Windows
programs** isn't in any distribution's advisories, so it's matched
separately (`app/third_party.py`), from a fixed list of products matched
by package name:

- **Go tools** (Docker Engine/CLI/Buildx/Compose, containerd, Vault,
  Consul, Nomad, Terraform, NVIDIA Container Toolkit, Tailscale, Caddy,
  Teleport, Elastic Beats, Helm, Kubernetes): GitHub's advisories from
  OSV's `Go` file (about 13 MB), with exact fixed versions.
- **Everything else on the list** (Node.js, PostgreSQL, Zabbix, the Wazuh manager,
  Fluent Bit, the Elastic stack, Grafana, nginx, MongoDB, MySQL, MariaDB,
  Redis, HAProxy, GitLab, Chrome, Edge, Firefox, Thunderbird, VS Code,
  7-Zip, Notepad++, VLC, PuTTY, WinSCP, Git, Wireshark, FileZilla,
  KeePass, Docker Desktop, TeamViewer): NVD's API
  (`services.nvd.nist.gov`), product by product. Every product on the
  list is queried, whatever your machines run, so the queries reveal
  nothing about them. NVD is slow (its first pass can take an hour) and
  rate-limited; an API key from NVD in `KITE_NVD_API_KEY` makes it
  about ten times faster. After the first pass, only changes are fetched.

Only packages that didn't come from the distribution are matched this
way: an rpm whose vendor isn't the distribution, or a deb whose version
carries no Ubuntu/Debian build marker. A distribution's own nginx or
PostgreSQL carries backported fixes that upstream version numbers can't
show, so its advisories stay the judge. NVD's data is less exact than a
distribution's, and NVD hasn't analysed every recent CVE ("Deferred"),
so a vulnerability it hasn't mapped to a product can't show. Each match
is labelled with where it came from.

Where it shows: a **Vulnerabilities** tab and summary tile on the machine
page, **Fleet → Vulnerabilities** to search one CVE (or package, or
machine) across the fleet, and `GET /hosts/{id}/vulnerabilities`,
`GET /vulnerabilities?cve=2024-6387` and `GET /vulnerabilities/status` on
the API. OSV and a machine's repositories don't change at the same
moment, so for a few days around a release an advisory can show here
before the machine's Updates tab offers the update, or the other way round.

## Network discovery

Topology's tree has a network level: **controller → cluster → node →
bridge → VM**. Each node fans out into the bridges its VMs are plugged into,
named by the bridge's Proxmox comment and marked as a VLAN, a bridge on a
physical port, or an internal bridge with no physical port. A VM with NICs
on several bridges (a firewall with one per zone) appears under each,
marked ⇄. Each tile shows that NIC's address and what listens on it,
still coloured by patch severity. The machine page gets a matching Network
section. Nothing is maintained by hand. Two sources fill it in, joined by
MAC address:

- **Proxmox**, re-read every 10 minutes by a background loop: each node's
  bridges and each guest's NICs. On a non-VLAN-aware setup a bridge over
  `eno1.20` is VLAN 20; on a VLAN-aware bridge the NIC's `tag=` decides.
  This works for every guest, enrolled or not, and uses the existing token
  (`Sys.Audit`, `SDN.Audit`, `VM.Audit`). **Refresh** in Topology re-reads it
  on demand.
- **The agent** (Linux), on every poll: interfaces and addresses
  (`ip -j addr`), the default gateway, and listening sockets with the
  owning process (`ss -tulnp`). Ports bound to one address only show on
  that address's network. Loopback-only listeners are kept but marked as
  unreachable.

Each port keeps its first-seen time. When a host's agent reports a new
listener (not loopback, below the 32768 ephemeral range), kite logs
`port_opened` and sends a notification. The host's first report is a
baseline and doesn't count.

The controller never scans anything. *Listening* means a process accepts
connections there; a firewall may still block it. Firewall rules and
reachability are on the roadmap. The Windows agent reports the
same facts from Windows' own network cmdlets (`Get-NetAdapter`,
`Get-NetIPAddress`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint`). Hosts on
an older agent show as **network not reported**, never as having nothing
open. Network detail is visible to operators and above, not to read-only
accounts, and isn't exposed through the MCP tools.

### Arranging the map

Topology uses the whole width, and **Full screen** gives it the whole
window (esc to leave). Drag any card to move it: a node, bridge or gateway
takes everything under it along, a single VM moves alone, and the lines
follow. The arrangement is kept in your browser, so a refresh or a new VM
keeps it. **Reset layout** puts everything back.

Selecting a VM with containers hangs them off it as part of the tree:
**VM → runtime (docker, podman) → each container**, with its compose
project and image on the line. Select the runtime for the per-project
summary, or a container for its detail.

Listening ports belong to each VM's panel. A bridge's panel folds them
into a single count ("3 machines · 9 ports") that opens into a short list
per machine, so a busy bridge stays readable.

### Gateways: the router drawn once, above its zones

A router or firewall VM has a NIC on every zone it routes, so on the plain
tree it would sit under every bridge. Mark it as a gateway and Topology
draws it once instead: **node → uplink bridge → gateway → the bridges it
routes → their VMs**. Its uplink is its NIC on a bridge with a physical
port; with none, the bridge of another gateway that routes it (a router
behind a router), or the node itself. Each other bridge it has a NIC on
moves under it, unless another gateway already routes that bridge.

Two ways to mark one, either works for any appliance:

- **Tag the VM `kite-gateway` in Proxmox** (Options → Tags). It's
  authoritative, travels with the VM, and needs nothing stored in kite.
  Remove the tag to undo it.
- **Click.** Untagged VMs that look like a gateway get a *GW?* hint: a NIC
  on an uplink bridge plus one on an internal bridge, or a router-like
  name (pfSense, OPNsense, VyOS, OpenWrt, `fw`, `gw`, …). Its panel offers
  **Show as gateway** and **Not a gateway** (lead and above); either can be
  undone. Nothing is promoted automatically: a dual-homed server matches
  the bridge rule too.

A gateway with no kite agent counts as **Gateway** in Coverage, not
as unmanaged: routers and firewalls are usually patched from their own UI,
and kite never runs anything on one.

## Read-only accounts

The `viewer` role (shown as "Read-only") sees everything the console shows:
fleet, runs, coverage, topology and the activity log. It can't start, cancel
or change anything. This is enforced server-side on every request that isn't
a GET, which matters because starting or cancelling a run is otherwise open
to any authenticated user. The only exceptions are changing the account's
own password and managing its own (read-only) API tokens. It suits auditors
and wall displays, and is a valid LDAP default role.

## Proxmox coverage and topology

In the console, coverage is **Fleet → Coverage** and the map is **Topology**.

Two read-only views over the cluster, using the same Proxmox token as the
snapshot backend. They need only audit rights and are cached for 60s
(`?refresh=true` skips the cache):

- `GET /proxmox/coverage` lists every guest and whether kite manages it:
  `managed` (linked by vmid), `name_match` (one host has the same short name
  but was never linked; fix with resolve-vmid), `unmanaged`, `ignored` or
  `template`. It also lists **stale links**: hosts whose recorded vmid Proxmox
  no longer reports, so their snapshots will fail. Guests that are deliberately
  unmanaged can be ignored with a reason (`POST /proxmox/ignored`, lead+).
  Proxmox hides what the token can't see, so "missing" can also mean
  "not visible to this token". If a fetch fails, both views keep serving
  the last good fetch, marked stale and showing its age, instead of going
  blank.
- `GET /topology` returns node → guests → enrolled host, with each node's
  **blast radius**: guests that go down with it, active runs, hosts without a
  snapshot safety net (LXC on the proxmox backend, an unlinked vmid,
  `dnf_history` or `none`), and critical updates pending. If Proxmox is
  unreachable, hosts with a pinned `proxmox_node` stay placed and the rest are
  listed as unplaced.

## Multi-node Proxmox, agent self-update, and LDAP

**Multi-Proxmox-node / cluster support** — the Proxmox rollback backend
does not assume every VM lives on one globally configured
`PROXMOX_NODE`. `app/proxmox.py`'s `list_cluster_vms`/`resolve_vm_node`
call Proxmox's `/cluster/resources` endpoint, which works whether or not
your Proxmox is actually clustered (a single, non-clustered node just
reports its own VMs through the same API), and returns every VM tagged
with the node it's actually running on right now. Automatic VMID
resolution (see above) now searches the whole cluster instead of only
the configured node — a fleet spanning multiple Proxmox nodes resolves
correctly instead of only ever matching a VM that happens to be on the
one node someone typed into `.env`. The snapshot stage resolves a VM's
node the same way at run time, live, rather than caching it — a VM that
gets migrated between nodes doesn't leave a stale node behind. Fleet →
host detail → "Proxmox node" lets you pin a specific node per host
instead (skips the lookup call — useful for a restricted API token that
can't read `/cluster/resources`, or a VM you know never migrates).
Falls back to the old single-node behavior automatically if the cluster
lookup fails for any reason (older Proxmox, insufficient token
permissions) — nothing breaks for an existing single-node deployment
that never touches any of this.

**Agent self-update** — the agent sends its own version
(`AGENT_VERSION` in `agent-linux/agent.py`) on every poll. When a newer
build is published in the controller's repo, Fleet says how many agents
are behind and offers **Update all to X**; a machine's page offers the
same for that one host. Each agent then runs `dnf -y --refresh upgrade
kite-agent-X` the next time it's otherwise idle, and restarts itself. Updates
only ever go up: an agent already on a newer build is left alone. Settings →
Agent updates sets the fleet-wide policy: keep every agent on the newest
build this controller holds (recommended), move them to one chosen
version, or don't update them.
Nobody logs in to the hosts; that's how vendor agents (Qualys, Wazuh's
manager-driven upgrades) do it too. The controller signals this via a response header
(`X-Kite-Self-Update`) rather than the poll response body, so the
existing `/jobs/next` JSON contract (`null`, or a job-stage instruction)
is unchanged — an older agent build that doesn't send its version at all
simply never gets offered a self-update, no breakage. This deliberately
never preempts an in-flight job stage: the controller only ever sets the
header on an otherwise-idle poll (see `routers/agent.py`'s
`next_job_stage`), so a self-update can't race a running patch job.
Debian/Ubuntu agents have no apt repo to upgrade from, so
they reinstall from the controller's agent bundle
(`/download/agent-linux`, the same one the Ubuntu install uses): the
download is checked against the checksum the controller sends with it
and must be the requested version, the previous `agent.py` is kept as
`agent.py.prev`, and the service restarts. For them, "published" is the
one version that bundle holds. Windows agents download the
controller's `kite-agent.exe` (its version is in the
`kite-agent.exe.version` file `build.sh` writes beside it), check the
checksum and version the same way, rename the running exe aside to
`.old` (Windows won't overwrite a running exe, but will rename one), put
the new one in place and restart the service. The
Linux and Windows agents share one version number and are released
together (a test fails the build if they drift). **Update all** sends
target `latest`, each agent to the newest build for its OS, so it also
does the right thing while the controller serves builds of different
releases. A systemd
service restarting itself through the package manager upgrading it is a
well-trodden pattern — it is how `dnf-automatic` and `yum-cron` restart
other services on upgrade, and the RPM's own `%post` already runs
`systemctl try-restart` (see `packaging/kite-agent.spec`).

**SSO / LDAP** — Settings → SSO / LDAP, "search + bind" against an LDAP
or Active Directory server (`app/ldap_auth.py`, using `ldap3` — pure
Python, no C extension/system libldap dependency). A search account (or
an anonymous bind, if none is configured) looks up the entry matching
the configured filter, then a second bind as that entry's own DN with
the password the user typed is what actually decides success or
failure — the search account never validates a password itself, and
nothing from the directory is trusted just because an entry was found.
The connection itself is checked: an `ldaps://` server must present a
certificate that is valid for its host name, and an `ldap://` address is
upgraded with StartTLS, under the same check, before any bind. The
certificate is verified against the system's CAs, or against
`ldap_ca_cert_file` (a PEM file on the controller) for a directory with
a private CA. Two admin-only settings relax this for a lab, through
`PUT /settings/{key}`: `ldap_verify_cert` = `false` keeps the encryption
but stops checking the certificate, and `ldap_starttls` = `false` lets
an `ldap://` address stay in clear text.
The username is filter-escaped (`ldap3.utils.conv.escape_filter_chars`)
before being substituted into the search filter — the LDAP-injection
equivalent of a parameterized SQL query.

Login precedence: a username that already has a **local** kite
account (like the bootstrap admin, or anyone created directly via
Settings → Users) always authenticates against its local password,
regardless of whether LDAP is enabled — this is deliberate, so a
misconfigured or unreachable directory can never lock out local admin
access. Any other username tries LDAP; on a successful bind with no
existing local account, one is created on the spot
(`auth_source='ldap'`) at the configured default role, and an admin
adjusts that role afterward via Settings → Users (`PATCH /users/{id}`,
also new this phase). An LDAP-sourced account always re-authenticates
against the directory on every login — nothing is cached locally, so
revoking directory access takes effect immediately, and
`/auth/change-password` and the admin "Reset password" action both
refuse outright for these accounts (there's no local password to
change). Usernames are matched without regard to case, as the
directory matches them: `Alice` and `alice` sign in to the same account, and
an LDAP account is stored in lower case, so a role set on it holds however
the name is typed. Group-to-role mapping isn't built — every LDAP login
provisions at one configured default role; a real mapping is a
reasonable follow-up, not implemented here. Not tested against a real
directory server in this environment (none available) — the search+bind
logic is covered by `tests/test_ldap_auth.py` with a mocked
`ldap3.Connection`, and the fail-closed behavior against an unreachable
server (a 401 after the connection timeout, not a hang or a 500) was
verified live against a real non-routable address.

## Fleet dashboard: last-seen and offline detection

The agent heartbeats every 60s regardless of its job-poll interval, and
the Fleet tab shows how long ago each host last checked in, refreshing
every 30s. A host that's gone quiet for more than ~2.5 missed heartbeats
(150s) shows as **Offline** — overriding whatever its last known patch
status was, since "haven't heard from it" is more urgent information
than a stale "Healthy" badge from before it went dark.

Admins can remove a host record from the Fleet tab — only enabled while
it's showing Offline, as a safety rail against accidentally deleting a
host that's actually fine. This only removes kite's record of the
host (audit history stays), it doesn't touch the actual VM. Refuses if
the host has an active run in progress.

## Run persistence, Fleet linking, and force-stop

- **A reload keeps your place.** The URL hash (`#run/job/<id>`) is the
  source of truth for which run is on screen, so a reload re-fetches
  that job from the API rather than depending on in-memory state.
- **A locked host links to its run.** `HostOut` carries an
  `active_job_id`, computed server-side in one query for the whole fleet
  rather than N+1, so "View progress" on a locked host jumps straight to
  that job's progress screen.
- **Force stop, precisely scoped.** `POST /runs/{id}/cancel` (lead+ role)
  stops kite from tracking a run and unlocks the host — it does
  **not** send any signal to the agent. If a command is genuinely still
  executing on the host when this is called, it keeps running; this
  only exists for the case where the agent's gone unresponsive (host
  shows Offline) and the job would otherwise be stuck forever. The host's
  status afterward is set to `unknown`, not `healthy` — the controller
  genuinely doesn't know what state a force-stopped host is in. A late
  stage report arriving from an agent that was still mid-command when
  cancellation happened is acknowledged and ignored rather than erroring.

## Agent communication: plain polling + a local trigger, not a held-open connection

`/agent/{host_id}/jobs/next` is a plain, quick request-response — no
held-open connection. An earlier version of this held the connection
open server-side (long-polling) for near-instant response; that got
reverted. Real reason, not a hypothetical: held-open HTTP connections
are exactly what corporate proxies, NAT gateways, and load balancers
tend to silently kill on real networks, surfacing as `Read timed out`
errors with no obvious cause. Confirmed with real Qualys documentation
too — their own default check-in interval is 4+ hours, and their actual
on-demand mechanism is a **local** flag the agent watches (a registry
key on Windows, a shell script on Linux), not a network push from their
cloud at all.

So the agent now polls on a long, configurable baseline interval
(default 900s / 15 min, set at enrollment via `--poll-interval`), and
for instant on-demand action there's a **local trigger file**
(`/var/lib/kite/trigger`, root-only) the agent checks every ~2s
while otherwise sleeping — touch it (via SSH, Ansible, whatever already
manages the host) and the agent wakes and polls immediately. No network
signal needed for that case at all.

`last_seen` still updates on every poll attempt (success or empty),
regardless of this change — that fold-in from the earlier design was
worth keeping either way, since it means the dashboard reflects real
contact without a separate `/heartbeat` call.

**Honest limitation, stated plainly**: a controller-initiated "run now"
click in the web UI, with no local access to the host, still waits for
that host's next scheduled poll — there's no way to avoid this without
either an inbound port on the agent or a persistent connection, and both
were deliberately ruled out. Keep the baseline interval short if that
latency matters more than the quietness.

## Fleet connectivity: three tiers, not binary online/offline

A host that's missed one poll cycle isn't necessarily down — it might
just be a network blip. `last_seen` age is bucketed into three tiers
(calibrated to the ~55s long-poll baseline):

- **Healthy** — under ~110s (2 missed cycles would be needed to fall out of this)
- **Stale** (amber, "Not confirmed recently") — 110s-330s — ambiguous, shown but not alarmed
- **Offline** (red) — over 330s, or never reported in — sustained silence, high confidence something's actually wrong

An admin can remove any host, from Fleet (select, **Remove**) or its
machine page, except one with a run in progress. Removing deletes
kite's record of it (inventory, network details), not the machine;
past runs stay in the history. If the host is still checking in, the
confirmation says so: its agent keeps running and is turned away from
then on, so it gives the uninstall command for that OS. Enrol it again
from **Add machine** to bring it back.

## Setup

This is the plain local/dev-mode way to run it — no TLS, listens on
every interface. For an actual deployment, use `controller-install.sh`
instead (see `INSTALL.md`), which puts Caddy in front with TLS and
binds uvicorn to localhost only.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
# .env is optional — copy .env.example to .env only to override a
# default (Proxmox details, SMTP, a pinned secret). See below.
```

Visit `http://<control-vm>:8000/` for the console itself, or
`http://<control-vm>:8000/docs` for interactive API docs (Swagger UI),
once enabled with `KITE_API_DOCS=true`. They are off by default: `/docs`,
`/redoc` and `/openapi.json` answer without sign-in.
The frontend is served by the controller directly (same origin, no CORS
config needed for normal use) from `frontend/kite.html`.

## Proxmox setup

One API token, used for three things: snapshots before a patch (when the
rollback safety net is the `proxmox` backend), Fleet → Coverage, and
Topology. Snapshots go through the Proxmox REST API, not libvirt/virsh,
even though it's KVM underneath. kite never starts, stops or changes
a VM.

1. **Create the token.** On any Proxmox node, as root:

   ```bash
   pveum role add KiteAccess -privs "VM.Audit Sys.Audit SDN.Audit VM.Snapshot VM.PowerMgmt"
   pveum user add kite@pve --comment "kite controller"
   pveum acl modify / --users kite@pve --roles KiteAccess
   pveum user token add kite@pve kite --privsep 0
   ```

   The last command prints the token ID (`kite@pve!kite`) and the
   secret. The secret is shown only once. What each privilege is for:
   `VM.Audit` reads guests (Coverage, Topology, VM-id lookup), `Sys.Audit`
   reads node status and network config, `SDN.Audit` lets that config
   include the bridges (since Proxmox 8, bridges are SDN resources, and
   without it every `vmbr*` is silently omitted, so VLANs can't be
   derived), `VM.Snapshot` takes and restores snapshots, and
   `VM.PowerMgmt` starts a VM again after a restore. An existing token adds
   one with `pveum role modify KiteAccess --privs VM.PowerMgmt --append 1`. Drop
   `VM.Snapshot` and `VM.PowerMgmt` if you only want Coverage and Topology. To allow snapshots
   on specific VMs only, grant the role on `/vms/<vmid>` instead of `/`.
   Coverage then only shows the guests the token can see. Don't reuse
   `Administrator`.
2. **Connect it.** In Settings → Connections, add a connection with a
   name, the address of any node (port 8006 is assumed), the token ID and
   the secret. **Test connection** reports the nodes and guests the token
   can see, and which uses its privileges cover. The secret
   is encrypted at rest.

   **Several connections.** Add one per cluster and one per standalone
   host, each with a token created on that host. A node that later joins
   an existing cluster needs nothing: the cluster's connection already
   sees it. VM ids only mean something within one connection, so each
   machine is linked to a connection and a VM id. Automatic matching
   searches every connection, and Topology draws one cluster box per
   connection. If a test finds nodes that another connection already
   sees (a standalone host that has since joined a cluster), it says so,
   because keeping both would show those VMs twice.

   An install that was configured before connections existed keeps
   working. Its connection becomes the first in the list on the next
   start. When the secret came from `.env`, it stays there and isn't
   copied into the database.
3. **Link each VM.** A snapshot targets a VM ID, not a hostname.
   kite resolves it from the SMBIOS UUID the agent reports. Hosts it
   couldn't match appear under Fleet → Coverage as name matches or stale
   links, with a one-click fix.

## SSH / sudo — note

This controller **does not SSH into hosts**. That's deliberate: the agent
runs locally on each host — a systemd service on Linux, a Windows service
on Windows — and polls outward, so there is no key anywhere that grants
root across the fleet and nothing needs inbound access to your machines.
A host that can reach the controller can be managed; the controller never
needs to reach it.

## Core flow (via the API, before the agent exists)

Ticket gating (step 4 below) is **off by default** — a fresh install
lets step 6 run with no `ticket_id` at all. Most self-hosted/homelab
installs aren't running an ITSM behind this and shouldn't be forced
through a ticket just to patch their own fleet. The walkthrough below
still creates and passes one anyway, since that's the fuller flow and
it works identically whether the setting is on or off — turn it on
via Settings → "Require an approved ticket to run a patch" (or
`PUT /settings/require_ticket`) if you want it enforced.

```bash
BASE=http://localhost:8000      # on the controller itself; https://<controller> elsewhere (add -k for its default certificate)
JAR=/tmp/kite.cookies

# 0. Sign in (an admin, for the steps below). API tokens are read-only;
#    changes need a signed-in session, kept here in a cookie jar.
curl -c $JAR -X POST $BASE/auth/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<password>"}'
# A new install's admin must choose its own password before anything else
# (every other call answers 403 password_change_required until then):
curl -b $JAR -X POST $BASE/auth/change-password -H 'content-type: application/json' \
  -d '{"current_password":"<password>","new_password":"<a new one>"}'
curl -c $JAR -X POST $BASE/auth/login -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<a new one>"}'

# 1. Issue a one-time enrollment token for a host you're about to install the agent on
curl -b $JAR -X POST $BASE/enroll/tokens -H 'content-type: application/json' \
  -d '{"hostname":"app-web-03","team":"Platform","role":"Web app server"}'
# -> {"token": "...", ...}

# 2. (This step is what the agent does automatically on first start)
curl -X POST $BASE/agent/enroll -H 'content-type: application/json' \
  -d '{"token":"<token from step 1>","os_version":"rocky9.8","proxmox_vmid":101}'
# -> {"host_id": 1, "agent_secret": "..."}  — save this, shown once

# 3. Set/confirm the Proxmox VM ID for snapshot targeting (if not set at enrollment)
curl -b $JAR -X PATCH $BASE/hosts/1 -H 'content-type: application/json' -d '{"proxmox_vmid":101}'

# 4. Create an approved ticket (stand-in for ServiceNow/Jira)
curl -b $JAR -X POST $BASE/tickets -H 'content-type: application/json' \
  -d '{"ticket_id":"CHG-4821","status":"Approved","description":"Quarterly patching","window_start":1,"window_end":5,"requester":"J. Alvarez"}'

# 5. Add a patch definition (skip or pin)
curl -b $JAR -X POST $BASE/defs -H 'content-type: application/json' \
  -d '{"pkg_pattern":"postgresql15*","mode":"skip","reason":"Requires DBA-led migration",}'

# 6. Start a run (checklist items must all have confirmed_by set)
curl -b $JAR -X POST $BASE/runs -H 'content-type: application/json' -d '{
  "host_id": 1, "ticket_id": "CHG-4821",
  "checklist": [{"item_index":0,"item_text":"KVM snapshot capability verified","confirmed_by":"M. Okafor"}]
}'
# -> job created, first agent stage marked "running" and waiting for the agent to poll it

# 7. Check job status any time
curl -b $JAR $BASE/runs/<job_id>

# 8. Audit log
curl -b $JAR $BASE/audit
```

## Job/stage model

Every run walks a fixed pipeline (`app/models.py: STAGE_SEQUENCE`):

| stage | executor | what happens |
|---|---|---|
| preflight | agent | connectivity, dnf lock, disk space, host self-lock |
| excludes | agent | apply skip/pin rules via `dnf versionlock` + `--exclude` |
| snapshot | controller | Proxmox API snapshot of the guest VM |
| patch | agent | `dnf update` |
| reboot | agent | reboot if needed, wait for SSH/agent to come back |
| healthcheck | agent | basic service/uptime check |
| soak | controller | short wait + final re-check |

The controller auto-executes `controller` stages and advances the job.
`agent` stages sit at `status: running` until the agent for that host
polls `GET /agent/{host_id}/jobs/next`, does the work locally, and
reports back via `POST /agent/{host_id}/jobs/{job_id}/stages/{name}/report`.

## Metrics & monitoring

`GET /metrics` — Prometheus exposition format, open by default (same as
every Prometheus exporter; restrict at the network/firewall level
first). Where that isn't enough, set `KITE_METRICS_TOKEN` and the
endpoint requires `Authorization: Bearer <token>`; in Prometheus that is
`authorization: {credentials: <token>}` on the scrape job. Only
aggregate counts, never hostnames or anything host-identifying:

- `kite_hosts_connectivity{tier="healthy|stale|offline"}` — same
  three-tier logic as the Fleet dashboard (see "Fleet connectivity"
  above), computed server-side too now so it's alertable outside the UI
- `kite_hosts_status{status=...}` / `kite_jobs_status{status=...}`
  — current counts by DB status
- `kite_jobs_stuck` — jobs currently sitting on an agent stage past
  its threshold (see below)
- `kite_stage_failures_total{stage=...}`,
  `kite_stage_stuck_total{stage=...}`,
  `kite_host_offline_transitions_total` — cumulative counters,
  process lifetime, for `rate()`/alerting in Prometheus

A background pass (`MONITOR_INTERVAL_SECONDS`, default 300s) checks for
two things and writes to both the audit log and the app's own log
(`KITE_LOG_FORMAT=json` for aggregator-friendly output, `text` by
default) the first time each is detected — not on every pass, so this
doesn't spam:

- **A stuck agent stage** — nothing in the job engine times out a stage
  on its own (see `app/jobs_engine.py`); if an agent dies, a host never
  comes back from reboot, or a custom OS script hangs, a stage sits at
  `running` silently forever otherwise. `STUCK_STAGE_MINUTES` (default
  60 — a real `dnf update` can legitimately run a while) covers most
  stages; `reboot` gets its own shorter `STUCK_REBOOT_MINUTES` (default
  15) since a host that's actually just rebooting is back in a few
  minutes, not tens of them.
- **A host going offline** — logged once on the healthy/stale → offline
  transition, not on every pass while it stays offline.

One case is acted on rather than only reported: **a run its machine
never collected**. A step handed to an agent waits to be polled for; if
the machine is off, the run would otherwise start whenever it came back,
possibly days later and outside the window it was meant for, holding the
host's one run slot (and any one-at-a-time batch behind it) until then.
A run whose machine has made no contact since the step became ready is
cancelled after `run_start_timeout_hours` (Settings, default 4; `0`
waits forever), or two of the machine's own poll intervals if that is
longer. It is logged and notified as `run_expired`. A machine that has
polled since is never expired this way: it may be doing the work.

None of this auto-fails a stuck stage or takes any action beyond
detecting and surfacing it — the controller can't reliably tell "actually
dead" from "legitimately slow" from here, so a human still decides via
Force Stop (see above). Outbound alerting on top of these signals
(Slack/Teams/webhook/email) lives in `app/notifications.py`, not
built here — this is the "make it observable" half.

## Known gaps (intentional, for a v1)

- TLS is on by default (`controller-install.sh` puts Caddy in front —
  see "Setup" above and `INSTALL.md`), but with a self-signed cert
  unless you point it at a real domain + Let's Encrypt. That means
  traffic is encrypted against passive sniffing, but not authenticated
  against an active on-path attacker impersonating the controller —
  see `INSTALL.md`'s "Security posture" section for the full trade-off
  and how to close it. Running the plain `uvicorn` dev command in
  "Setup" above with no reverse proxy at all is the one case with no
  TLS whatsoever — fine for local dev, not for anything reachable
  beyond localhost.
- Ticket source is a local table by default; a real ITSM system can push
  into it via `POST /tickets/webhook` (see "Integrations"),
  but that's an inbound webhook contract, not a bespoke ServiceNow/Jira
  API client, and hasn't been tested against a real instance of either.
- No two-person approval on patch-definition edits (logged, not gated).
- LDAP/SSO has no group-to-role mapping — every directory
  login provisions at one configured default role; an admin promotes/
  demotes from there. Not tested against a real directory server in this
  environment.
- Cluster-aware Proxmox lookups depend on the configured API
  token being able to read `/cluster/resources`; a token scoped narrower
  than that silently falls back to the old single-node behavior instead
  of failing loudly.
