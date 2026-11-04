# Installing kite

Two ways to run the controller: **Docker** (fastest, any OS) or
**natively on Rocky/RHEL 8 or 9**.

## Docker

Needs Docker Engine with the Compose plugin, v2.24 or newer
([install Docker](https://docs.docker.com/engine/install/)). Use real
Docker, not the `podman-docker` shim.

```bash
git clone https://github.com/SiraBet/kite.git
cd kite/controller && docker compose up -d
docker compose logs controller | grep -A4 "ADMIN LOGIN"
```

The console is at `https://localhost/`. TLS, rate limiting and the schema
are all set up. The encryption key and enrolment secret are generated on
first start and kept in the data volume.

- **The admin password is printed once.** If you lose it, run
  `docker compose exec controller python tools/reset_admin_password.py`.
- **Port 443 already taken?** Run `KITE_HTTPS_PORT=8443 docker compose up -d`.
- **A real domain:** edit `docker/Caddyfile`.
- **Overrides** such as Proxmox credentials, SMTP or a pinned enrolment
  secret: copy `.env.example` to `.env`.
- **Upgrade:** `git pull && docker compose up -d --build`. Migrations run
  on start, after a copy of the database is taken.

## Native install on Rocky/RHEL

One opinionated path, start to finish, for a bare-metal or VM install.

### What you're building

- **One control VM** (Rocky 9, 2 vCPU / 2 GB RAM / 20 GB disk is plenty) —
  runs the controller: web console, API, job engine, and hosts a real
  `dnf` repo for the agent package.
- **One agent per host you want patched** — a `dnf`-installable package,
  enrolled with a single command.

### 1. Control VM

Spin up Rocky 9, then download the latest release tarball, verify it, and
run the installer:

```bash
ver=1.0.0   # the release you're installing
curl -fsSLO https://github.com/SiraBet/kite/releases/download/v${ver}/kite-controller-${ver}.tar.gz
curl -fsSLO https://github.com/SiraBet/kite/releases/download/v${ver}/kite-controller-${ver}.tar.gz.sha256
sha256sum -c kite-controller-${ver}.tar.gz.sha256   # must print: OK
tar xzf kite-controller-${ver}.tar.gz
cd kite-controller-${ver}
sudo ./controller-install.sh
```

The release tarball is self-contained: it already includes **both agents
built and ready to serve** — the Windows installer under `dist/` and the
Linux agent RPM (signed, with `dnf` repo metadata) under `repo/` — so the
install finishes with working agents and needs no Go, no `rpmbuild`, and
no internet beyond the download. That one script replaces what used to be
a dozen-plus separate manual steps: installs Python 3.9+ (on Rocky/RHEL 8,
whose `python3` is 3.6, a newer one beside it), `firewalld` and Caddy,
creates a dedicated `kite` system user (least-privilege — the service
doesn't run as root), copies the project to `/opt/kite-controller`,
sets up the Python venv, generates `.env` from the template if one
doesn't already exist, deploys the Caddyfile (self-signed TLS by default)
and the systemd service, and opens the firewall port. It's safe to re-run
if something fails partway.

> **Installing from a source checkout instead** (`git clone`) is the
> developer path: the agents are build artifacts and are *not* in git, so
> a clone ships neither. Build them once with `agent-windows/build.sh`
> (needs Go 1.23+) and `agent-linux/packaging/build.sh` (needs
> `rpm-build`), or just use a release tarball. The installer prints which
> agents are present at the end.

Have a real DNS name pointing at this host? Pass it and the installer
configures a browser-trusted Let's Encrypt certificate automatically —
no warnings, no `-k`, nothing to edit:

```bash
sudo ./controller-install.sh --domain kite.example.com
```

This needs the host reachable from the internet on 80 and 443. Without
`--domain` you get the zero-config self-signed default, which works by
IP with no DNS at all — see the security note at the end of this file.

At the end it prints the console URL and a reminder to check the log for
your enrollment secret:

```bash
journalctl -u kite-controller -n 30 --no-pager | grep -A5 KITE_ENROLL_SECRET
```

**Simplification worth knowing about**: you don't have to pick or
configure a secret before this works. The controller generates one on
first start (same behavior Wazuh's manager has for its own registration
password), prints it to the log, and saves it beside the database as
`enroll_secret` (mode 0600) so it stays the same across restarts. Read
it from the log once and you're done.

Pin it explicitly only if you'd rather manage it yourself, or want it
held somewhere other than next to the database:

```bash
sudo tee -a /opt/kite-controller/.env << 'EOF'
KITE_ENROLL_SECRET=<the one from the log, or your own>
EOF
sudo systemctl restart kite-controller
```

`KITE_SECRET_KEY` (which encrypts the Proxmox token and the
notification secrets) is handled the same way, and matters more: if it
ever changes, everything encrypted under it becomes permanently
unreadable. `KITE_STATE_DIR` moves both files elsewhere.

Verify it's up: `https://<control-vm-ip>/` in a browser should show
the console with an empty Fleet. Expect a certificate warning on first
visit — Caddy issues its own certificate from a local CA your browser
doesn't know (see `controller/Caddyfile`); click through it, or swap in
a real domain + Let's Encrypt per that file's comments.

A warning is expected; a connection that fails outright is not. If you
see `tlsv1 alert internal error` instead of a trust prompt, the
Caddyfile has been edited to drop either `local_certs` or `on_demand` —
both are required together. See the comments in `controller/Caddyfile`.

### 2. Log in and create real accounts

The controller auto-creates a default `admin` account on first boot —
check the startup log for the one-time password:

```bash
journalctl -u kite-controller -n 30 --no-pager | grep -A4 "ADMIN LOGIN"
```

(Lost it? `cd /opt/kite-controller && sudo -u kite venv/bin/python
tools/reset_admin_password.py` resets it from the host. Run it from that
directory: the database path in `.env` is relative to it.)

Log in with that, then (recommended) change the password via the
Settings tab or `POST /auth/change-password`, and create real accounts
for whoever else needs access — Settings → Users, or `POST /users`.
Roles are the same Operator/Lead/Admin tiers the UI has always shown;
they're enforced by the server now, not just the browser.

### 3. Enroll a host

The controller already ships with a working agent package and repo — no
build step needed for a fresh lab (`packaging/build.sh` is only for
when you've changed the agent's source and need to rebuild it).

The agent repo is signed automatically: the controller makes its
signing key on first start and signs every agent package and the repo
index (README "GPG-signing the repo"). Hosts check the controller's
certificate against its own root CA, after checking that root's
fingerprint (README "The controller's certificate authority"); the
console's Add machine command shows the fingerprint and does all of
this for you. By hand it's, on each Rocky/RHEL/Alma 8 or 9 host:

```bash
curl -fsSk https://<control-vm-ip>/download/ca.crt -o /tmp/kite-ca.crt && \
test "$(openssl x509 -in /tmp/kite-ca.crt -outform DER | sha256sum | cut -d' ' -f1)" = "<fingerprint>" && \
sudo install -D -m 644 /tmp/kite-ca.crt /etc/kite/controller-ca.crt && echo "controller CA checked"

sudo tee /etc/yum.repos.d/kite.repo << 'EOF'
[kite]
name=kite agent
baseurl=https://<control-vm-ip>/repo
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://<control-vm-ip>/repo/RPM-GPG-KEY-kite
sslverify=1
sslcacert=/etc/kite/controller-ca.crt
skip_if_unavailable=1
metadata_expire=300
EOF

sudo KITE_CONTROLLER=https://<control-vm-ip> \
     KITE_SECRET=<the enrollment secret from step 1> \
     KITE_HOSTNAME=$(hostname) KITE_TEAM=Platform \
     KITE_CA_CERT=/etc/kite/controller-ca.crt \
     dnf install -y kite-agent
```

`<fingerprint>` is shown on the console's Add machine panel (the same
SHA-256 your browser shows for the controller's root certificate). Stop
if "controller CA checked" isn't printed. With `--domain` (a public
certificate) skip the first three lines, and use `sslverify=1` without
`sslcacert` and no `KITE_CA_CERT`.

One command: adds the repo's package to the system, installs it,
enrolls with the controller, and starts the service. Check the Fleet
tab — the host should appear with a `Healthy` badge within about 15
seconds (the agent's poll interval).

**Why this is the recommended path over a per-host token**: it's one
secret, reused across every host's install command — matches how Qualys
and Wazuh actually do this at scale, verified against their real docs.
The per-host token flow (`POST /enroll/tokens`) still exists and is
tighter-scoped (each host individually authorized) if you want that for
a specific sensitive host — see the controller README.

### 4. Proxmox (optional — snapshots before patching, restores, Coverage and Topology)

Skip this if you just want to see the console and patch flow working.
Without it a run's snapshot stage has nothing to snapshot: until you add
it, set Settings → Policy → Rollback safety net to *dnf history* or *none*.

1. **Create an API token** on any Proxmox node, as root:

   ```bash
   pveum role add KiteAccess -privs "VM.Audit Sys.Audit SDN.Audit VM.Snapshot VM.PowerMgmt"
   pveum user add kite@pve --comment "kite controller"
   pveum acl modify / --users kite@pve --roles KiteAccess
   pveum user token add kite@pve kite --privsep 0
   ```

   The last command prints the token ID and the secret (shown once).
   `--privsep 0` matters: a privilege-separated token has none of the
   user's permissions unless you grant them to the token too, and gets
   `403`s. What each privilege is for:

   | Privilege | Used for |
   |---|---|
   | `VM.Audit` | reading guests and their config: Coverage, Topology, VM-id lookup |
   | `Sys.Audit` | node status and network config (Topology) |
   | `SDN.Audit` | seeing bridges, and so VLANs (Proxmox 8+ hides them without it) |
   | `VM.Snapshot` | the snapshot before each run, deleting old ones, and restoring one |
   | `VM.PowerMgmt` | starting a VM again after a restore |

   Leave out `VM.Snapshot` and `VM.PowerMgmt` if you only want Coverage
   and Topology. An existing token adds one with
   `pveum role modify KiteAccess --privs <privilege> --append 1`.
2. **Connect it**: Settings → Connections → add a connection with the
   node's address, the token ID and the secret. **Test connection** lists
   which of the uses above the token's privileges cover.
3. **Link each machine to its VM**: machines usually match their VM on
   their own (by SMBIOS UUID); otherwise set the VM id on the machine's
   page.

The controller README's Proxmox section has the rest: several clusters,
narrowing the token to specific VMs, snapshot cleanup and restoring.

### Upgrading later

```bash
cd /path/to/kite && sudo git pull
sudo ./controller/controller-install.sh
```

Re-running the installer is what upgrades the agents too: it rebuilds
any agent whose version changed (the Windows one needs Go installed)
and publishes it, and enrolled agents then update themselves (Settings →
Policy → Agent updates).

Schema changes apply automatically on startup (Alembic, see
`controller/migrations/`), and the controller writes a
`kite.pre-migration-<timestamp>.db` copy beside the live database
before applying one. There's no hand-run SQL step — earlier versions of
this project needed one, and skipping it left a controller that started
fine and then failed every query. See `controller/README.md`'s
"Upgrading an existing deployment" for the rollback procedure and for
how to take a backup on demand.

### Security posture — what's default, what's a deliberate trade-off

**Secure by default, no action needed:**
- **Real login required on every endpoint** — session cookie (HttpOnly, not JS-readable, `SameSite=Lax`, and `Secure` whenever the request arrived over HTTPS, which is every request behind the default Caddy setup), checked server-side on every request. Expired sessions are reaped by the background monitor pass rather than lingering in the database. The Operator/Lead/Admin roles are enforced in the API itself now, not just shown differently in the browser.
- **Identity is never client-supplied** — who ran a patch, who confirmed a checklist item, who uploaded a script: all come from the authenticated session, not a field the browser sent. The audit log is backed by real proof, not self-reported strings.
- A default `admin` account is auto-created on first boot with a random password, printed once to the startup log — same pattern as the enrollment secret. Change it after first login (`/auth/change-password`) rather than treating it as permanent. Both that and the admin-driven "Reset password" action (Settings → Users) invalidate every other existing session for the account, so a leaked session cookie stops working the moment either happens.
- Passwords are hashed with PBKDF2-HMAC-SHA256 (200k iterations, per-user salt), minimum 12 characters (server-enforced, not just a UI hint), never stored or logged in plaintext after account creation.
- **Login is rate-limited per real client IP (5/min)**, correctly so even behind the default Caddy reverse proxy — it reads the client address Caddy itself appends to `X-Forwarded-For`, not one a client could spoof to get its own bucket. A flood spread across many source IPs (each individually under that per-IP limit) still can't exhaust the server: failed logins that would otherwise queue up burning CPU on password hashing get a fast, honest "server busy" response instead of hanging.
- Controller runs as a dedicated non-root `kite` system user, not root
- Agent secrets are hashed at rest, never stored/logged in plaintext after enrollment
- Enrollment secret auto-generates with real entropy rather than defaulting to something guessable
- Each host's agent credential is scoped to that host only — compromising one agent doesn't expose others
- Patch definitions and OS scripts are versioned and audit-logged on every change, gated to Admin
- Only the controller's port needs to be open — agents only ever call out, nothing needs to reach in to them
- CORS is closed by default (no cross-origin browser access at all) — the console is served same-origin, so nothing needs it; only relevant if you're running a separate frontend against this API
- Outbound notification webhooks (Settings → Notifications) refuse to fire at loopback/link-local/metadata addresses (e.g. a cloud instance's `169.254.169.254`) — an admin configuring one can't turn the controller into a probe against its own network or host. Ordinary LAN destinations are still allowed, since a self-hosted webhook receiver on the same network is a real, intended use case here.
- SQLite runs in WAL mode with a busy-timeout — many hosts checking in around the same time no longer risk a "database is locked" failure under realistic fleet-sized concurrency.

**Deliberate trade-offs for lab simplicity — revisit before this leaves a private network:**
- **Self-signed TLS cert by default** — Caddy terminates HTTPS out of the box (see step 1) with certificates from its own local CA, which browsers don't trust. Agents don't need to: they pin that CA after checking its fingerprint (README "The controller's certificate authority"), so they're protected against an on-path attacker impersonating the controller. Your browser still warns until you trust the root yourself or switch to a real domain + Let's Encrypt (`--domain`).
- **Shared enrollment secret** (for agent self-enroll, separate from user login) means anyone holding it can enroll a host under any claimed hostname. Rotate it if it's ever exposed; the per-host token flow avoids this entirely if you need it for a specific host.
- **No account lockout** on repeated failed logins, just the per-IP rate limit above — use a real password, not something short (the 12-character minimum is a floor, not a target).
- **The Ticket step is off by default** — nothing gates a run except checklist confirmation unless you turn it on (Settings → "Require an approved ticket to run a patch"). Fine for a lab or a homelab with no real ITSM behind it; turn it on before treating this as a change-control tool for real.

None of these are things that got missed — they're the actual, named cost of "as easy as possible," written down instead of left implicit.
