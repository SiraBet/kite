# Changelog

Notable changes to kite, newest first. Versions follow
[semantic versioning](https://semver.org/). The controller and both
agents share one version number and are released together.

## 1.1.0 — 2026-11-12

A security and reliability release. It closes the findings of a code and
security review, and adds staged rollouts for schedules. Several
defaults are stricter than in 1.0.0: read **Upgrade notes** before
upgrading.

### Upgrade notes

Each of these changes what an existing install does after upgrading.

- **LDAP now requires a verified, encrypted connection.** An `ldaps://`
  directory must present a certificate valid for its host name, and an
  `ldap://` address is upgraded with StartTLS. If sign-in through LDAP
  stops working, point `ldap_ca_cert_file` at your directory's CA, or
  for a lab set `ldap_verify_cert` or `ldap_starttls` to `false`. Local
  accounts are unaffected, so a local admin can always sign in to change
  these.
- **Email notifications verify the mail server's certificate.** A relay
  with a self-signed certificate needs `notify_smtp_verify_cert` set to
  `false`.
- **Runs waiting for an offline machine are cancelled** after
  `run_start_timeout_hours` (default 4). Set it to `0` to keep the old
  wait-forever behaviour.
- **`/docs`, `/redoc` and `/openapi.json` are off** unless
  `KITE_API_DOCS=true`.
- **Writes from another origin are refused.** The console is unaffected
  behind the bundled Caddy configuration. Behind a proxy that rewrites
  `Host`, pass `X-Forwarded-Host` or list the console's origin in
  `CORS_ORIGINS`.
- **`enroll.py --secret ... --vmid N` no longer sets the VM ID.** Hosts
  enrolled with the shared secret are linked to their VM by SMBIOS UUID
  or by an admin.
- **Webhook notifications no longer follow redirects.** Configure the
  final URL.
- **Changing your password revokes your API tokens.** Create new ones
  afterwards.
- **API changes:** `GET /runs` returns the newest 200 runs and takes
  `limit` and `offset`; `GET /audit` caps `limit` at 1000; `PUT
  /settings/{key}` answers 404 for a setting that does not exist;
  `GET /settings` returns directory and mail server details to admins
  only.
- **Database:** one additive migration (`0027_schedule_rollout`),
  applied automatically on start.

### Added

- Schedules can roll out **one machine at a time**: the next machine
  starts only when the previous run finished cleanly, and a failure
  pauses the rest and sends a notification. Existing schedules keep
  firing on every machine at once.
- Runs whose machine never collects them **expire** instead of starting
  days later.
- Optional bearer token on `/metrics` (`KITE_METRICS_TOKEN`).
- Host edits (VM link, rollback backend, team and so on) are recorded in
  the activity log.

### Security

- An agent can no longer choose which Proxmox VM its host record points
  at when enrolling with the shared secret, or repoint an existing link.
- LDAP usernames are matched case-insensitively, so a role change cannot
  be sidestepped by retyping the name.
- LDAP and SMTP connections verify certificates (see Upgrade notes).
- State-changing requests must come from the console's own origin.
- A one-time enrollment token can no longer be redeemed twice by
  simultaneous requests.
- The Debian/Ubuntu agent refuses a self-update that arrives without a
  checksum, as the Windows agent already did.
- An agent can no longer report a controller-run stage (snapshot, soak)
  as done.
- What an agent can report is bounded in size; stage script uploads are
  limited to 1 MB and their filenames sanitised.
- Webhook URLs are kept out of the log.
- Directory and mail server settings are visible to admins only.
- Updated Starlette, FastAPI, python-multipart and requests, which
  includes fixes for denial-of-service issues reachable before sign-in.

### Fixed

- Deleting a machine no longer turns an update rule that named only that
  machine into a fleet-wide rule, and a removed machine's id is never
  reused.
- A non-numeric SMTP port no longer interrupts audit logging and the
  operations that depend on it.
- A schedule's severity filter is validated, so a typo no longer
  produces a schedule that runs weekly and installs nothing.
- The RPM declares the project's real license (Apache-2.0).

## 1.0.0 — 2026-11-05

First release.
