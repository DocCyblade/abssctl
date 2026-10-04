# abssctl path forward (living TODO)

Version: 1.0.0
Date: 2026-10-04
Branch: `dev-beta1-redux` (cut from `dev-beta1`, not from `dev`)
**How to use:** Check boxes as work finishes. Start each Cursor chat from [`CURSOR_WORKFLOW.md`](CURSOR_WORKFLOW.md).

`dev` is not the base. Its only unique local commit is a `mutants/` dump. Do not merge that commit. Promote this branch to `dev` with a squash only when a slice is ready.

## Status at a glance

| Track | Goal | Status |
|---|---|---|
| **W** | Cursor workflow (replace the Albert / session-log ritual) | Done |
| **S** | One live Actual 26.10.0 install | Process smoke passed; no systemd/nginx on this Mac |
| **N** | Node compatibility matrix through current npm releases | Done |
| **Q** | v1 polish: bounded mutmut CI, man pages, completions, MITP, README/ADR-005 | Done |
| **P** | TestPyPI pre-release of the current tree | Next |

## Track W — Cursor workflow

- [x] **W1** `AGENTS.md`, `.cursor/rules/abssctl.mdc`, `.cursorignore`
- [x] **W2** `docs/CURSOR_WORKFLOW.md` and this file
- [x] **W3** Banner on `ops/ai-directives.txt`; session log left as archive
- [x] **W4** `mutants/` stays gitignored

## Track S — Live 26.10.0 install

- [x] **S1** Node >= 22 available. This Mac's `/usr/local/bin/node` is 22.11.0 and segfaults; Node 22.23.3 serves the UI. `n` is not installed here.
- [x] **S2** `npm install @actual-app/sync-server@26.10.0` produced `build/bin/actual-server.js`.
- [x] **S3** A `_build_instance_config` payload was loaded (`Loading config from …`) and `http://127.0.0.1:6016/` returned the Actual HTML on Node 22.23.3.
- [ ] **S4** systemd and nginx are not installed on this Mac, so the unit and vhost were not started. Run `docs/source/guides/mitp.rst` on a TurnKey host.

## Track N — Compatibility matrix

- [x] **N1** Refresh `docs/requirements/node-compat.yaml` from npm (through 26.10.0)
- [x] **N2** Ship the same YAML at `src/abssctl/data/node-compat.yaml`
- [x] **N3** Node 22.23.3 is the preferred runtime for 25.11+ and 26.x

## Track Q — v1 polish on this branch

- [x] **Q1** Bounded mutmut job (on demand, `src/abssctl/exit_codes.py`). Full suite stays local.
- [x] **Q2** `abssctl docs man path|install` and a shipped `abssctl.1`
- [x] **Q3** `abssctl completion show|install|uninstall`
- [x] **Q4** MITP checklist published in the docs
- [x] **Q5** README and ADR-005 describe beta and Node 22

## Track P — Publish

- [ ] **P1** Tag `v0.1.5a2-dev` for TestPyPI. `v0.1.5a1-dev` failed `make dist` on Ruff UP042 before any upload. Do not republish `0.1.3a1`. Leave production PyPI alone.
