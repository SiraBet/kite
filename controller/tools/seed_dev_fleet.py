#!/usr/bin/env python3
"""
Seed a plausible-looking fleet into a development database.

Why this exists: every screen in the console is shaped by data, and
until now the only way to get any was to enroll real hosts. That made
the most common contribution — "fix something on a page" — start with
half an hour of setup, and it made the empty state the only state most
contributors ever saw. A dashboard in particular is meaningless with
zero hosts.

This is NOT a demo or trial mode, and deliberately not reachable from
the app: it's a script a developer runs against a throwaway database.
Nothing in the shipped product seeds itself, no endpoint calls this, and
it refuses to touch a database that already has hosts in it unless you
say --force. What the product does on a fresh install is unchanged —
an empty fleet and an honest empty state.

    cd controller
    KITE_DB=dev.db python3 tools/seed_dev_fleet.py

Then start the controller against the same database and log in with the
admin account it prints.

    KITE_DB=big.db python3 tools/seed_dev_fleet.py --scale 400

adds that many more machines, with groups, update rules, scripts,
pending updates, vulnerabilities, runs and activity in proportion -- for
checking that pages still read well with a large fleet, not just 15
machines.
"""
import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import models  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.security import generate_secret, hash_secret  # noqa: E402

# Shaped to exercise the UI rather than to look tidy: a couple of hosts
# are deliberately offline, one has never been patched, one is well past
# the 30-day mark. A seed where everything is green tests nothing.
HOSTS = [
    # hostname,        role,          team,        os_family,  seen_min_ago, patched_days_ago
    ("web-01",         "web",         "platform",  "rocky9",   2,            3),
    ("web-02",         "web",         "platform",  "rocky9",   4,            3),
    ("web-03",         "web",         "platform",  "ubuntu22", 6,            11),
    ("db-primary",     "database",    "platform",  "rocky9",   3,            8),
    ("db-replica",     "database",    "platform",  "rocky9",   5,            8),
    ("cache-01",       "cache",       "platform",  "debian12", 9,            21),
    ("build-01",       "ci",          "developer", "ubuntu22", 7,            2),
    ("build-02",       "ci",          "developer", "ubuntu22", 12,           2),
    ("git-01",         "vcs",         "developer", "rocky8",   8,            45),   # overdue
    ("mail-01",        "mail",        "corporate", "rocky8",   1440, 62),           # offline + overdue
    ("file-01",        "storage",     "corporate", "win2022",  35,           14),   # stale
    ("dc-01",          "directory",   "corporate", "win2019",  4,            9),
    ("print-01",       "print",       "corporate", "win2019",  2880, None),         # offline, never patched
    ("monitoring-01",  "observability", "platform", "rocky9",  3,            1),
    ("staging-app-01", "app",         "developer", "ubuntu22", 11,           None),  # never patched
]

ACTIVITY = [
    ("run_completed", "web-01 — job 41, ticket CHG-2201", "success"),
    ("stage_done", "job 41 — healthcheck", "neutral"),
    ("run_started", "web-01 via CHG-2201, 4 checklist items confirmed", "neutral"),
    ("host_offline", "mail-01 — no contact since yesterday", "warning"),
    ("run_completed", "db-replica — job 40, ticket CHG-2198", "success"),
    ("def_added", "kernel* pinned at 5.14.0-427 — validated for this workload", "neutral"),
    ("stage_failed", "job 39 — preflight: insufficient disk space on /var", "danger"),
    ("run_started", "git-01 via CHG-2195, 4 checklist items confirmed", "neutral"),
    ("login", "", "neutral"),
    ("schedule_fired", "Weekly platform patching — started 5 run(s)", "success"),
    ("host_enrolled", "staging-app-01 (Ubuntu 22.04) via shared secret", "warning"),
    ("setting_changed", "require_ticket = true", "neutral"),
]


# Container inventory, shaped to exercise all three drift states and all
# three management modes. Keyed by hostname.
CONTAINERS = {
    "web-01": [
        ("shop-web", "nginx:1.25", "running", "compose", "shop", False, True),
        ("shop-redis", "redis:7-alpine", "running", "compose", "shop", False, False),
    ],
    "web-02": [
        ("shop-web", "nginx:1.25", "running", "compose", "shop", False, True),
    ],
    "db-primary": [
        ("pg", "postgres@sha256:9c2a1f", "running", "compose", "data", True, False),
        ("pg-exporter", "quay.io/prometheuscommunity/postgres-exporter:v0.15.0",
         "running", "compose", "data", False, False),
    ],
    "cache-01": [
        ("legacy-api", "reg.internal/legacy-api:latest", "running", "standalone", "", False, None),
    ],
    "build-01": [
        ("runner", "gitlab/gitlab-runner:alpine", "running", "standalone", "", False, True),
        ("dind", "docker:24-dind", "exited", "standalone", "", False, None),
    ],
    "monitoring-01": [
        ("prometheus", "prom/prometheus:v2.51.0", "running", "compose", "obs", False, False),
        ("grafana", "grafana/grafana:10.4.0", "running", "compose", "obs", False, True),
        ("node-exporter", "prom/node-exporter:v1.7.0", "running", "kubernetes", "", False, None),
    ],
}


# Pending updates per host, shaped so the risk view has all four
# severities, an apt host with no severity data, and one host whose
# assessment failed outright.
UPDATES = {
    "web-01":        [("openssl", "critical", True), ("glibc", "important", True),
                      ("curl", "moderate", True), ("tzdata", "none", False)],
    "web-02":        [("openssl", "critical", True), ("curl", "moderate", True)],
    "db-primary":    [("postgresql-server", "important", True), ("zlib", "low", True)],
    "git-01":        [("kernel", "important", True), ("openssh-server", "important", True),
                      ("vim", "moderate", True)],
    "monitoring-01": [("nss", "moderate", True)],
    # Debian-family: security is identifiable, severity is not published.
    "web-03":        [("libpcre2-8-0", "unknown", True), ("tzdata", "none", False)],
    "cache-01":      [("libssl3", "unknown", True)],
}
# This host's package manager could not be queried at all -- the count is
# unknown, which the console must not render as zero.
UNASSESSED = {"mail-01": "Failed to download metadata for repo 'internal-mirror'"}


def _wipe(db):
    for model in (models.ChecklistConfirmation, models.JobStage, models.Job, models.Batch,
                  models.AuditLog, models.Schedule, models.Container,
                  models.PendingUpdate, models.HostVuln, models.HostSoftware, models.MachineGroupMember,
                  models.MachineGroup, models.PatchDefTarget, models.PatchDef, models.OsScript, models.Host):
        db.query(model).delete()
    db.commit()


def seed(db, now):
    for hostname, role, team, os_family, seen_min, patched_days in HOSTS:
        db.add(models.Host(
            hostname=hostname, role=role, team=team, os_family=os_family,
            os_version=os_family, agent_version="0.1.6",
            agent_secret_hash=hash_secret(generate_secret()),
            poll_interval_seconds=900,
            last_seen=now - timedelta(minutes=seen_min),
            last_patched=None if patched_days is None else now - timedelta(days=patched_days),
            status="healthy", enrolled_at=now - timedelta(days=90),
        ))
    db.commit()

    hosts = {h.hostname: h for h in db.query(models.Host).all()}

    # One run mid-flight so the dashboard's "active runs" card and the
    # progress display have something real to render.
    running = models.Job(
        host_id=hosts["cache-01"].id, hostname="cache-01", ticket_id="CHG-2204",
        operator="dev", operator_role="lead", status="running", current_stage_index=3,
        rollback_backend="dnf_history",
        created_at=now - timedelta(minutes=6), updated_at=now - timedelta(minutes=1),
    )
    db.add(running)
    db.commit()
    db.refresh(running)
    for i, (name, executor) in enumerate(models.STAGE_SEQUENCE):
        status = "done" if i < 3 else "running" if i == 3 else "pending"
        db.add(models.JobStage(
            job_id=running.id, stage_index=i, name=name, executor=executor, status=status,
            output=f"{name} completed" if status == "done" else "",
            started_at=now - timedelta(minutes=6 - i) if status != "pending" else None,
        ))
    hosts["cache-01"].status = "locked"

    # Finished history, so Runs and the 24h counters aren't empty either.
    for offset, (hostname, status) in enumerate([
        ("web-01", "done"), ("web-02", "done"), ("db-replica", "done"),
        ("git-01", "failed"), ("build-01", "done"),
    ]):
        finished = models.Job(
            host_id=hosts[hostname].id, hostname=hostname, ticket_id=f"CHG-22{offset:02d}",
            operator="dev", operator_role="lead", status=status,
            current_stage_index=len(models.STAGE_SEQUENCE),
            created_at=now - timedelta(hours=offset + 2),
            updated_at=now - timedelta(hours=offset + 1),
        )
        db.add(finished)
        db.commit()
        db.refresh(finished)
        for i, (name, executor) in enumerate(models.STAGE_SEQUENCE):
            failed_here = status == "failed" and name == "preflight"
            db.add(models.JobStage(
                job_id=finished.id, stage_index=i, name=name, executor=executor,
                status="failed" if failed_here else "done",
                output="insufficient disk space on /var" if failed_here else f"{name} ok",
                started_at=now - timedelta(hours=offset + 2),
                finished_at=now - timedelta(hours=offset + 1),
            ))

    for hostname, entries in CONTAINERS.items():
        host = hosts[hostname]
        host.container_runtime = "docker"
        for name, image, state, managed_by, project, pinned, drift in entries:
            db.add(models.Container(
                host_id=host.id, container_id=f"{abs(hash(name)) % 10**12:012x}",
                name=name, image=image, state=state, managed_by=managed_by,
                compose_project=project,
                compose_service=name.split("-")[-1] if managed_by == "compose" else "",
                compose_working_dir=f"/srv/{project}" if managed_by == "compose" else "",
                pinned=pinned, update_available=drift,
                # Compose services that have been through an update carry
                # a capture; the rest have never had one taken.
                rollback_available=managed_by == "compose" and not pinned,
                rollback_captured_at=(now - timedelta(days=6)) if managed_by == "compose" and not pinned else None,
                image_digest="sha256:seeded", reported_at=now,
            ))

    for hostname, entries in UPDATES.items():
        host = hosts[hostname]
        host.updates_assessed_ok = True
        host.updates_assessed_at = now - timedelta(minutes=20)
        for package, severity, is_security in entries:
            db.add(models.PendingUpdate(
                host_id=host.id, package=package, new_version="(seeded)",
                advisory="RLSA-2026:1000" if severity not in ("unknown", "none") else "oldstable-security",
                severity=severity, is_security=is_security, reported_at=now,
            ))
    for hostname, error in UNASSESSED.items():
        hosts[hostname].updates_assessed_ok = False
        hosts[hostname].updates_assessed_at = now - timedelta(hours=2)
        hosts[hostname].updates_error = error

    db.add(models.Schedule(
        name="Weekly platform patching", team="platform", day_of_week=1, hour=3,
        enabled=True, created_by="dev", last_fired_at=now - timedelta(days=6),
    ))
    db.add(models.Schedule(
        name="Monthly corporate rollout", team="corporate", day_of_week=5, hour=22,
        enabled=True, created_by="dev",
    ))
    db.add(models.Schedule(
        name="Nightly image refresh", team="platform", day_of_week=3, hour=2,
        enabled=True, created_by="dev", scope=models.SCOPE_CONTAINERS,
    ))
    db.add(models.Schedule(
        name="Critical security only", team="", day_of_week=0, hour=1,
        enabled=True, created_by="dev", severity_filter="critical,important",
    ))

    # Oldest first, so row ids run in the same direction as timestamps —
    # the same relationship real audit rows have.
    for i, (action, detail, tone) in enumerate(reversed(ACTIVITY)):
        db.add(models.AuditLog(
            ts=now - timedelta(minutes=(len(ACTIVITY) - i) * 37 + random.randint(0, 20)),
            actor="dev" if action in ("run_started", "def_added", "login", "setting_changed") else "system",
            role="lead", action=action, detail=detail, tone=tone,
        ))
    db.commit()


# --scale: names long enough to find what they push out of place
_FAMILIES = ["rocky8", "rocky9", "almalinux9", "rhel9", "ubuntu22", "ubuntu24", "debian12", "windows",
             "win2019", "win2022"]
_TEAMS = ["platform", "developer", "corporate", "data-engineering", "security-operations", "retail-stores"]
_ROLES = ["web", "database", "cache", "ci", "file", "app", "directory", "kubernetes-worker", "observability"]
_PKGS = ["openssl", "glibc", "curl", "kernel", "openssh-server", "nss", "libxml2", "python3-libs", "sudo",
         "systemd", "tzdata", "vim-enhanced", "postgresql16-server", "nginx", "containerd.io"]


def seed_scale(db, now, n, rng):
    """`n` more machines, and everything that hangs off machines, in proportion."""
    hosts = []
    for i in range(n):
        fam = rng.choice(_FAMILIES)
        team, role = rng.choice(_TEAMS), rng.choice(_ROLES)
        name = f"{team[:4]}-{role}-{i:04d}" + ("-eu-west-availability-zone-b.internal.example" if i % 37 == 0 else "")
        h = models.Host(
            hostname=name, role=role, team=team, os_family=fam,
            os_version=("Microsoft Windows Server 2022 Datacenter" if fam.startswith("win") else fam),
            agent_version=rng.choice(["0.7.1", "0.7.1", "0.7.0", "0.6.3"]),
            agent_secret_hash="seeded", poll_interval_seconds=900,
            last_seen=now - timedelta(minutes=rng.choice([1, 3, 8, 20, 90, 3000])),
            last_patched=None if i % 23 == 0 else now - timedelta(days=rng.randint(0, 70)),
            status="healthy", enrolled_at=now - timedelta(days=rng.randint(1, 400)),
            updates_assessed_ok=i % 41 != 0, updates_assessed_at=now - timedelta(minutes=30),
            updates_error="" if i % 41 else "Failed to download metadata for repo 'internal-mirror-with-a-long-name'",
            software_reported_at=now,
        )
        db.add(h)
        hosts.append(h)
    db.commit()

    groups = []
    for i in range(40):
        g = models.MachineGroup(name=f"group-{i:02d}" + ("-with-a-much-longer-descriptive-name" if i % 9 == 0 else ""),
                                description="Seeded group" if i % 3 else "")
        g.hosts = rng.sample(hosts, k=min(len(hosts), rng.choice([0, 2, 15, 60, n // 2])))
        db.add(g)
        groups.append(g)
    db.commit()

    for fam in _FAMILIES:
        for stage in ("preflight", "patch"):
            db.add(models.OsScript(os_family=fam, stage_name=stage, filename=f"{fam}-{stage}.sh",
                                   content="#!/bin/sh\necho seeded\n", tested=rng.random() < 0.5, uploaded_by="dev"))
    db.commit()

    for i in range(80):
        kinds = rng.choice([[], ["os"], ["group"], ["host"] * 12, ["os", "group", "host", "host"]])
        targets = []
        for k in kinds:
            value = rng.choice(_FAMILIES) if k == "os" else str(rng.choice(groups).id) if k == "group" \
                else str(rng.choice(hosts).id)
            if (k, value) not in {(t.kind, t.value) for t in targets}:
                targets.append(models.PatchDefTarget(kind=k, value=value))
        pin = i % 4 == 0
        db.add(models.PatchDef(pkg_pattern=f"{rng.choice(_PKGS)}{'*' if i % 2 else ''}", mode="pin" if pin else "skip",
                               version="1.2.3-4.el9" if pin else "", os_family="",
                               reason="Seeded: held back until the application team signs off on the new version",
                               targets=targets))
    db.commit()

    cves = [f"CVE-2026-{40000 + i}" for i in range(120)]
    for h in hosts:
        for pkg in rng.sample(_PKGS, k=rng.randint(0, 9)):
            sev = rng.choice(["critical", "important", "moderate", "low", "unknown", "none"])
            db.add(models.PendingUpdate(host_id=h.id, package=pkg, new_version="9.9.9-1", advisory="RLSA-2026:9999",
                                        severity=sev, is_security=sev != "none", reported_at=now))
        for cve in rng.sample(cves[:20], k=rng.randint(0, 8)) + rng.sample(cves, k=rng.randint(0, 4)):
            db.add(models.HostVuln(host_id=h.id, cve=cve, advisories="RLSA-2026:9999", source="distro",
                                   severity=rng.choice(["critical", "important", "moderate", "low"]), score="7.5",
                                   package=rng.choice(_PKGS), installed="1.0-1", fixed="1.0-2",
                                   summary="Seeded vulnerability with a summary long enough to wrap in a table cell",
                                   url=""))
        h.vulns_matched_at = now
    db.commit()

    for i in range(30):
        db.add(models.Schedule(name=f"Seeded schedule {i:02d} for the {rng.choice(_TEAMS)} estate",
                               team=rng.choice(_TEAMS + [""]), day_of_week=i % 7, hour=i % 24, enabled=i % 5 != 0,
                               created_by="dev"))
    batch_hosts = hosts[:120]
    batch = models.Batch(rollout=models.BATCH_ONE_AT_A_TIME, status="running", host_ids=json.dumps([h.id for h in batch_hosts]),
                         next_index=40, settings=json.dumps({"ticket": "CHG-9000"}), operator="dev", operator_role="lead",
                         created_at=now - timedelta(hours=2))
    db.add(batch)
    db.commit()
    for k, h in enumerate(batch_hosts[:40]):
        job = models.Job(host_id=h.id, hostname=h.hostname, ticket_id="CHG-9000", operator="dev", operator_role="lead",
                         status="done" if k < 39 else "running", batch_id=batch.id,
                         current_stage_index=len(models.STAGE_SEQUENCE) if k < 39 else 2,
                         created_at=now - timedelta(minutes=120 - k * 3), updated_at=now - timedelta(minutes=118 - k * 3))
        db.add(job)
    for i in range(3000):
        action, detail, tone = rng.choice(ACTIVITY)
        db.add(models.AuditLog(ts=now - timedelta(minutes=3000 - i), actor=rng.choice(["dev", "system", "a.long.username"]),
                               role="lead", action=action, detail=detail, tone=tone))
    db.commit()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true",
                        help="wipe existing hosts/jobs/audit rows first")
    parser.add_argument("--scale", type=int, default=0, metavar="N",
                        help="add N more machines, with groups, rules, vulnerabilities and history in proportion")
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        existing = db.query(models.Host).count()
        if existing and not args.force:
            print(f"Refusing to seed: this database already has {existing} host(s).")
            print("Point KITE_DB at a throwaway file, or pass --force to replace them.")
            return 1
        if existing:
            _wipe(db)
        seed(db, datetime.utcnow())
        if args.scale:
            seed_scale(db, datetime.utcnow(), args.scale, random.Random(7))
            print(f"Added {args.scale} more machines, 40 groups, 80 update rules and their history.")
        container_count = sum(len(v) for v in CONTAINERS.values())
        update_count = sum(len(v) for v in UPDATES.values())
        print(f"Seeded {len(HOSTS)} hosts, {update_count} pending updates, "
              f"6 runs, 3 schedules, {container_count} containers, "
              f"{len(ACTIVITY)} activity entries into "
              f"{os.environ.get('KITE_DB', 'kite.db')}.")
        print("Start the controller against the same database; log in with the admin")
        print("account printed on its first startup.")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
