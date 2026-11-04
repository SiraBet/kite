**What this changes and why**

**Component(s) touched**
controller / agent-linux / agent-windows / docs

**How you tested this**
(CI runs `pytest` and `ruff` automatically. Note anything it can't
cover: a real host, `--dry-run`, manual API calls, a browser pass over
the console.)

**Checklist**
- [ ] Comments explain the code itself, not the task or PR (see
      `CONTRIBUTING.md`)
- [ ] If this touches the `KITE_*` agent contract, it's consistent
      across agent-linux and agent-windows
- [ ] If this changes the DB schema, it ships with an Alembic revision
      (`cd controller && alembic revision -m "..."`)
