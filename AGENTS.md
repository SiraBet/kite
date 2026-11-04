# Notes for AI coding assistants

kite is a patch orchestrator: a controller (`controller/`, Python/FastAPI
with a plain-JavaScript console) and two agents that run on the machines it
patches (`agent-linux/`, Python 3.6+; `agent-windows/`, Go). Start with
`README.md`, then `controller/README.md`.

## Writing a per-OS stage script

When someone asks for a stage script (a `preflight`, `excludes` or `patch`
step for an OS family), read
[`ai/skills/kite-stage-script/SKILL.md`](ai/skills/kite-stage-script/SKILL.md)
and its `reference/` folder **before writing anything**. They hold the
execution contract (interpreter, exit codes, the `KITE_*` environment, the
4000-character output budget), which stages can be replaced and why `reboot`
can't, and the per-distro traps. Worked examples are in
`controller/examples/os-scripts/`.

## Working on the code

- Tests: `cd controller && python3 -m pytest -q`; `cd agent-linux && python3 -m pytest -q`;
  `cd agent-windows && go vet ./... && go test ./...`. Lint: `cd controller && ruff check .`
- The Linux agent must stay Python 3.6 compatible (EL8's system Python).
- Schema changes need an Alembic migration (`controller/migrations/`); the
  test suite fails if the models and migrations disagree.
- Never put real hostnames, addresses or credentials in code, tests or docs:
  use example values (`example.com`, `10.0.0.5`, `web-01`).
