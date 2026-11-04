# kite roadmap

## Positioning

There is a real gap between writing your own Ansible patch playbook —
flexible, but you build every safety rail yourself, with no rollback,
audit trail or UI until you build it — and running Foreman/Katello or
Uyuni, which are genuinely powerful but heavy to operate: content views,
lifecycle environments, and a Candlepin/Pulp or Salt stack to keep alive
before the first host gets patched.

kite aims at the middle, and defaults to the smaller end of it. A
single FastAPI process and a static console: pending updates per host
with severity, scheduled and on-demand runs, per-OS stage scripts,
snapshot rollback, and a full audit trail — present from the start rather
than bolted on.

The change-control machinery (approval tickets, maintenance windows, the
ITSM webhook) is built and supported, but **off by default**: the person
patching their own lab should not have to file a ticket against themselves
to do it, and a team with a real change process can switch it on without
re-platforming. Checklists are the one gate that is always present, since
a run should never be a single unconsidered click.

The goal is not to match Foreman feature for feature; it is to stay the
tool that gets a real fleet safely patched in an afternoon, and keeps its
operational weight near zero as the fleet grows.

---

## Status

**Ready for production use on Linux fleets.** RHEL-family (dnf) and
Debian-family (apt) hosts are supported, and both have been exercised
end to end against real hosts, and so has the Windows agent, which works
to the same contract.

| Area | State |
|---|---|
| Control plane | FastAPI + SQLite, one process, migrations applied on startup |
| Deployment | `docker compose up -d`, or `controller-install.sh` on RHEL/Rocky 8–9 |
| TLS | On by default, self-signed via Caddy's local CA; Let's Encrypt with one config change |
| Auth | Server-enforced sessions and RBAC (operator/lead/admin), optional LDAP/AD |
| Linux agents | dnf and apt, one codebase, verified against real hosts |
| Windows agent | Installer plus native status window, downloaded from the console, per-host build carries its own token; Windows Update, self-update; tested on real Windows hosts |
| Rollback | Pluggable: Proxmox snapshot, dnf history, or explicit none |
| Change control | Checklists always; tickets, maintenance windows and ITSM webhook optional |
| Observability | `/metrics` (Prometheus), structured logs, stuck-stage detection |
| Notifications | Webhook, Slack, SMTP |
| Scheduling | Weekly recurring runs |
| Risk | Per-host pending updates with severity; runs restrictable to a severity band |
| Containers | Docker/Podman/nerdctl inventory with drift detection; compose services updatable and rollback-capable per run |
| Tests | 819 controller, 142 Linux agent, 95 Windows agent, lint clean, all green in CI |

### Capabilities

**Deployment and upgrade.** Two commands from a clean machine, with no
configuration file to prepare: secrets are generated on first start and
persisted alongside the database so they survive restarts. Upgrading is
`git pull` plus a restart — Alembic migrations apply automatically at
startup, and the controller writes a consistent copy of the database
before applying one. A database from any earlier version is reconciled
in a single step.

**Patching.** Every run walks a fixed pipeline — preflight, excludes,
snapshot, patch, reboot, healthcheck, soak — with preflight, excludes
and patch overridable per OS family by uploading a script. Agents poll
and execute locally; the controller never connects into a host.

**Safety.** A checklist gates every run. Tickets, approval status and
maintenance windows gate it too when enabled. Rollback backends are
resolved per host and frozen onto the job at creation. Everything that
happens is audit-logged, with identity taken from the authenticated
session rather than anything the client sends.

**Containers.** Agents report the containers their host runs, how each
is managed, and whether its image tag has moved upstream. A run chooses
its scope — the OS packages, the containers, or both — and compose
services are updated by pulling and recreating them in their own project
directory, after capturing the image being replaced so the update can be
undone. Standalone and orchestrated containers are reported but never
touched: neither can be recreated safely.

**Risk.** Agents report pending updates with the severity their
distribution publishes — real advisory levels on dnf, security-or-not on
apt, which has no severity metadata. A run can be restricted to a
severity band. A host whose package manager could not be queried is
counted as unknown, never as zero.

**Operations.** A home dashboard aggregates fleet reachability,
attention items, in-flight runs, upcoming schedules and recent activity
into a single request. Stuck stages are detected and surfaced but never
auto-failed — the controller cannot reliably distinguish "slow" from
"dead", so a human decides.

---

## Known gaps

Stated plainly rather than left to be discovered.

- **The Windows binaries are not code signed.** SmartScreen will warn on
  the download. A per-host installer cannot be signed in any case:
  appending its configuration invalidates an Authenticode signature, so
  signing would cover the generic download only.
- **No MSI.** The installer is a wizard `.exe` with a `/S` silent mode,
  which covers scripted deployment but not Group Policy software
  installation, which requires an MSI.
- **The console has no browser-level tests.** Its JavaScript runs in a
  real JS engine under test and every view is rendered and asserted
  against, which covers view logic, escaping and structure. It does not
  cover layout, CSS, or click behaviour.
- **One controller process only.** SQLite is single-writer with no
  replication, and the three background loops assume a single instance.
  Running two controllers needs the Postgres option below plus leader
  election.
- **No `.deb` package or apt repository for the agent.** RPM packaging
  and a signed dnf repo exist; Debian-family hosts install manually via
  `install-debian.sh`, and agent self-update is therefore dnf-only.
- **Schedules are weekly.** Day-of-week plus hour, in UTC. A true
  "nth weekday of the month" Patch Tuesday rule is not implemented.
- **No macOS agent.**
- **Checklist items cannot be reordered.** Order is insertion order;
  delete and re-add to change it.
- **LDAP has no group-to-role mapping.** Every LDAP user is provisioned
  at one configured default role, adjustable per user afterwards.
- **Only compose containers can be updated.** Standalone containers
  cannot be recreated safely — their creation flags are recorded
  nowhere — and orchestrated ones belong to Kubernetes, Swarm or Nomad.
  Both are reported and left alone; there is no plan to change this.
- **apt has no per-advisory severity.** Debian and Ubuntu publish
  security updates identifiably but without severity levels, so a
  severity-scoped run degrades to security-only there. This is a
  limitation of the distributions' metadata, not something kite can
  work around without inventing numbers.
- **A container capture does not include volumes.** It restores the
  image a service was running, which is everything an update changed for
  a compose service — but if a newer image migrated a schema or rewrote
  files in a volume on first start, restoring the image does not undo
  that. A host on the `proxmox` backend does get volume state back,
  since a VM snapshot covers the whole disk.
- **The agent repo must be marked `skip_if_unavailable=1`.** dnf treats
  an unreachable repository as a hard error, so a controller that is
  down would otherwise break every dnf command on every host it manages.
  The generated install command and both install guides set it; a repo
  file written by hand before this should be updated.
- **Notifications are best-effort.** Synchronous delivery, short
  timeout, no queue and no retry: if a channel is down when an event
  fires, that notification is lost. A notification failure never breaks
  the operation it reports on.

---

## Planned

Roughly in the order they are worth doing.

### Exposure: firewall rules and "what can reach what"

Network discovery (VLANs from Proxmox, addresses and listening ports from
the agent) answers *where* a machine is and *what it listens on*. The next
step is *who can reach it*, so the console can say "critical openssl
update, and 443 is reachable from the internet: patch this first". That is
the Wiz-style "toxic combination" applied to patching. In order:

- **pfSense rule import, read-only.** pfSense CE has no official API, so
  this means either the community REST package or a parsed `config.xml`
  backup. It covers interfaces → VLANs, rules per interface, aliases, and
  port forwards from WAN. Show the rules that apply between two VLANs as
  evidence before computing anything from them.
- **Host firewall from the agent.** nftables, firewalld, iptables, and
  Windows Firewall later. A port can listen and still be blocked on the
  host itself.
- **Reachability with an honest "unknown".** Internet and cross-VLAN
  exposure come from the above, and anything the model can't evaluate
  (an unmodelled rule type, a missing host firewall report) shows as
  unknown with the rule cited, never as "blocked". Traffic within a VLAN
  never crosses pfSense, so the network firewall says nothing about it.
- **Exposure-ranked patching.** An "exposed and critical" list on
  Overview and Topology.

Network detail stays operator+ and out of the MCP tools: it is a map of
what to attack.

### Considered and deferred: a read-only observer agent on the firewall

A report-only agent build (patching compiled out) on the firewall would
fill in subnets, gateway addresses, DHCP/ARP addresses for VMs without a
guest agent, and devices that aren't Proxmox guests, joined to Proxmox
NICs by MAC. Deferred: it means a FreeBSD build, a second agent role
through enrollment and job dispatch, per-field provenance in the data
model, and software running on the one machine that must never break.
Drawing the gateway once (a Proxmox tag or a click, above) solved the
visible problem without any of that. If it comes back, the cheaper first
steps are the Proxmox node's `bridge fdb` for devices behind the uplink,
and the pfSense rule import above, which needs no agent.

### CVE detail on Windows: what's left

Windows itself is matched against Microsoft's Security Update Guide (see
README "Vulnerabilities"), its own components only. Still open: .NET,
Office and the other Microsoft products the guide lists separately
("... on Windows 10 Version 22H2"), which need the agent to report which
of them are installed.

### Windows: signing and Group Policy deployment

Code signing for the agent and installer, and an MSI so the agent can be
rolled out with Group Policy.

### More rollback backends

`app/rollback/` is a seam: a new backend is a new file, not a rewrite.
Proxmox and dnf-history ship today. LVM, Btrfs and ZFS local snapshots
would cover bare metal; cloud provider snapshot APIs would cover EC2 and
equivalents. Cloud APIs are asynchronous — submit, then poll — which the
deferred controller-stage mechanism in `app/jobs_engine.py` already
supports.

### PostgreSQL as an option

SQLite stays the zero-configuration default. Postgres becomes opt-in for
anyone who wants concurrent writers or replication. Migrations are
already configured with `render_as_batch=True`, so revisions work on
both backends.

### Horizontal scaling

Only worth attempting after Postgres. The `monitor`, `scheduler` and
deferred-stage loops each assume they are the only instance running;
each needs leader election or a shared lock first.

### Smaller items

- A browser pass over the console, and screenshots in the README.
- `.deb` packaging and an apt repository, which also unlocks agent
  self-update on Debian-family hosts.
- Monthly and "nth weekday" schedule rules.
- Checklist reordering.
- LDAP group-to-role mapping.
- A macOS agent.

---

## Design decisions worth knowing

Recorded because these are the questions that come up first, and because
reversing one should be a deliberate act.

**Agents poll; the controller never connects in.** There is no SSH key
with root over the fleet, and nothing needs to reach into a host. A
compromised agent credential grants that one host — which kite
already patches as root — and nothing else. The cost is latency: a
scheduled run reaches a host on its next poll, and a local trigger file
exists for on-demand wake-ups.

**The console is served as static files, with no build step.** Plain
classic scripts sharing one global scope. This keeps deployment to a
single process serving a directory, and keeps contribution open to
anyone who can read JavaScript without installing a toolchain. The cost
is that load order matters, which the HTML documents and the tests
enforce.

**Migrations run automatically on startup.** For self-hosters whose
upgrade is `git pull` plus a restart, a manual migration step is a
skipped step — and skipping this one breaks the controller. The risk of
an unattended schema change is covered by taking a database copy first.

**Ticket gating is off by default.** Most self-hosted installs have no
ITSM behind them and should not be forced through a ticket to patch
their own fleet. The feature is complete and one setting away; only the
default changed.

**Secrets are generated rather than demanded.** A first install should
not begin with "choose an enrollment secret". They are generated,
printed once, and persisted so they stay stable across restarts. Pinning
them explicitly always takes priority.

**Stuck stages are surfaced, not auto-failed.** The controller cannot
tell a legitimately slow `dnf update` from a host that is never coming
back. It raises the signal — audit log, operational log, Prometheus
counter, notification — and leaves the decision to a person.
