# Contributing to kite

## Layout

- `controller/` — the FastAPI control plane (DB, job engine, agent-facing
  API, the single-file frontend at `controller/frontend/kite.html`)
- `agent-linux/` — the Python agent for RHEL-family (dnf-based) hosts
- `agent-windows/` — the Go agent for Windows hosts, built as a single `.exe`
- `controller/ROADMAP.md` — what's planned, in priority order; a good
  place to find something to work on

## Local development

The controller has no external dependencies beyond Python — SQLite is
the default DB, no separate service to stand up:

```bash
cd controller
python3 -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

No `.env` needed — copy `.env.example` to `.env` only when you want to
override something. First startup prints a generated admin password to
the console; log in with that.

Working on the console or anything data-shaped? Seed a realistic fleet
first, so you're not looking at empty states:

```bash
KITE_DB=dev.db python3 tools/seed_dev_fleet.py
KITE_DB=dev.db uvicorn app.main:app --reload --port 8000
```

Working on the console? It's `frontend/kite.html` (a shell) plus
`frontend/css/` and `frontend/js/` — see `controller/README.md`'s
"Console layout" for why load order matters and where to add a file.

If you'd rather iterate against a real systemd install than `--reload`
(handy when a remote agent has to reach the controller), `dev/` holds a
deploy shortcut for that. Read [`dev/README.md`](dev/README.md) first: it
serves plain HTTP with no TLS, so it belongs on a lab network and nowhere
else. It is not an install path — that's `controller/controller-install.sh`.

Before opening a PR, run `pytest` and `ruff check .` from `controller/`,
`pytest` from `agent-linux/`, and `go vet ./... && go test -race ./...`
from `agent-windows/`. CI runs all three. Changing the schema also needs
an Alembic revision — `tests/test_migrations.py` fails without one.

To exercise a real patch run, point an agent at your local controller:

```bash
cd agent-linux
python3 enroll.py --controller http://localhost:8000 --secret <enroll-secret> --hostname test-host
python3 agent.py --dry-run --once   # --dry-run logs intended commands instead of running them
```

## Conventions worth knowing before you open a PR

- **Comments explain the code, not the task.** No "this is sophisticated,"
  no "unlike the old version," no references to a conversation or ticket
  that led to the change. A comment should cover the *why* of a
  non-obvious constraint or workaround — if it would make just as much
  sense a year from now with no other context, it's fine; if it only
  makes sense to someone who watched the change happen, cut it.

  Concretely, that rules out: internal release or phase numbers, notes
  about what something "used to" do, and narration about how a bug was
  discovered or what has or hasn't been tested yet. State the constraint
  and the reason it exists. Verification status belongs in
  `controller/ROADMAP.md`'s Known gaps, where a reader can find it.
- **One active OS-script per (os_family, stage).** See
  `app/models.py`'s `SCRIPTABLE_STAGES` and `controller/README.md`'s "OS
  Scripts" section before touching that subsystem — uploads replace,
  never stack, and `reboot` is deliberately not scriptable.
- **The `KITE_*` env var contract is the interface between the
  controller and every agent**, current and future. If you're adding a
  new platform agent, match the existing contract (`KITE_JOB_ID`,
  `KITE_HOSTNAME`, `KITE_STAGE`, `KITE_EXCLUDES`,
  `KITE_PINS`, exit-code semantics) rather than inventing a
  parallel one — that's what lets one custom script's mental model
  transfer across platforms.
- Keep diffs scoped to what the change needs. Don't refactor
  surrounding code, rename things, or add abstractions for
  hypothetical future use in the same PR as a fix or feature.

## Reporting bugs / requesting features

Open an issue with the relevant template. For security issues, don't
open a public issue — see `SECURITY.md`.

## License

By contributing, you agree your contributions are licensed under this
project's Apache-2.0 license (see `LICENSE`).
