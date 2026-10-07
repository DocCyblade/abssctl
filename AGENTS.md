# abssctl — agent brief

Python 3.11 admin CLI that installs and operates multiple Actual Budget sync-server instances on TurnKey Linux (systemd, nginx, TLS, backups, doctor).

## Docs first

- **Queue:** GitHub Issues on `DocCyblade/abssctl`. One chat per issue. See `docs/GITHUB_WORKFLOW.md`.
- **Catch-up:** `docs/NEXT_STEPS.md` (next three issues and a prompt for the first). If it disagrees with GitHub, rewrite it from GitHub.
- **Milestone story:** `docs/PATH_FORWARD.md`. Not a second checkbox list.
- **Cursor chat workflow:** `docs/CURSOR_WORKFLOW.md`
- Spec: `docs/requirements/abssctl-app-specs.txt` — cite it; do not paste it
- Decisions: `docs/adrs/` — a spec change needs a new ADR and a core dev's approval
- Milestone tracker: `docs/roadmap.rst` (long roadmap; PATH_FORWARD is the milestone story)
- Archived chat ritual: `ops/ai-directives.txt` and `ops/session-log.txt` — history only

## Setup

- Repo root is this folder. Open it as the Cursor workspace.
- `python3.11 -m venv .venv --prompt dev && source .venv/bin/activate && pip install -e ".[dev]"`
- Gate: `make quick-tests` (ruff, mypy, pytest). Docs changes also run `make docs`.

## Layout

- `src/abssctl/` — Typer CLI and providers
- Installs `@actual-app/sync-server` from npm (not a from-source build, not `@actual-app/cli`)
- Actual 25.11+ needs Node >= 22. `abssctl node ensure` installs that Node via `n`. Do not assume the appliance Node 18 is enough. npm must be >= 10.9.9. Actual 26.6.0 does not install on an older npm.

## Rules of the road

- Testing hosts: `docs/TESTING_ACCESS.md`. Only those three VMs. Production server and production PyPI stay untouched.
- One chat per GitHub issue. Prefer `@` files over pasting specs. Follow `docs/CURSOR_WORKFLOW.md`.
- Commit only when asked. Do not push, and do not tag a release, unless a core dev asks in this chat. Release tags follow `.cursor/skills/release/SKILL.md`.
- Out-of-scope work is a draft issue, not a note in the chat. Show the draft and wait. File it only after a core dev says to post it (`.cursor/skills/capture-todo/SKILL.md`).
- Do not redesign the providers, registry, or command tree.
- Ignore `mutants/` and `ops/session-log.txt` as live work lists.
