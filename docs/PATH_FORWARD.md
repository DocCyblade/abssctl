# abssctl path forward (living TODO)

Version: 1.0.0
Date: 2026-10-04
Branch: `dev-beta1-redux` (cut from `dev-beta1`, not from `dev`)
**How to use:** Check boxes as work finishes. Start each Cursor chat from [`CURSOR_WORKFLOW.md`](CURSOR_WORKFLOW.md).

`dev` is not the base. Its only unique local commit is a `mutants/` dump. Do not merge that commit. Promote this branch to `dev` with a squash only when a slice is ready.

## Where we are (spec §13)

`docs/requirements/abssctl-app-specs.txt` section 13, and the same list in `docs/roadmap.rst`:

| Spec milestone | Position |
|---|---|
| Planning, Pre-Alpha, Alpha | Done. Scaffold, CLI foundations, and the PyPI project exist. |
| Beta — core features | In the tree (version ops, instances, systemd/nginx, doctor). `version install` follows `000-manual-install.sh`: `package.json` and `build/bin/actual-server.js` at `/srv/app/v<version>`. |
| RC — quality and docs | Support bundle, man pages, completions, and the MITP checklist are in. One Actual 26.10.0 instance is running on `nodeapp00` through systemd and nginx. Upgrade, backup, TLS verify, doctor, support bundle, and cleanup were not part of this run. |
| Release — v1.0.0 | Later. Burn-in across the current Actual release plus the ten prior versions, then GA. Production PyPI is still `0.1.3a1`. |

Docs reading 2026-10-05 (`docs/reviews/2026-10-05-docs-claims.md`) found `version install` partial. Track V closed that layout gap in the tree. Overview and quickstart still describe doctor, restore, TLS, and support bundles as unfinished.

Mutation survivor hunting is local/on-demand work. It is not the next slice.

## Status at a glance

| Track | Goal | Status |
|---|---|---|
| **W** | Cursor workflow (replace the Albert / session-log ritual) | Done |
| **N** | Node compatibility matrix through current npm releases | Done |
| **Q** | v1 polish: bounded mutmut CI, man pages, completions, MITP checklist, README/ADR-005 | Done |
| **P** | TestPyPI pre-release of the current tree | Done (`0.1.5a4`) |
| **S** | First MITP attempt for Actual 26.10.0 | Stopped at version install on `nodeapp00` |
| **D** | Check published docs against the code and tests | Done |
| **V** | `version install` matches `000-manual-install.sh` | Done |
| **M** | One MITP on `nodeapp00` for Actual 26.10.0 | Done |
| **H** | Host layout in the CLI (systemd, ownership, nginx link) | Done |

Leave the production server and production PyPI alone. Test guests an agent may use are `docs/TESTING_ACCESS.md`. VM 9011901 (`nodeapp00`) is not in that set. Do not merge the `mutants/` checkpoint on local `dev`.

## Track W — Cursor workflow

- [x] **W1** `AGENTS.md`, `.cursor/rules/abssctl.mdc`, `.cursorignore`
- [x] **W2** `docs/CURSOR_WORKFLOW.md` and this file
- [x] **W3** Banner on `ops/ai-directives.txt`; session log left as archive
- [x] **W4** `mutants/` stays gitignored

## Track S — Live 26.10.0 install

- [x] **S1** Node >= 22 available. This Mac's `/usr/local/bin/node` is 22.11.0 and segfaults; Node 22.23.3 serves the UI. `n` is not installed here.
- [x] **S2** `npm install @actual-app/sync-server@26.10.0` produced `build/bin/actual-server.js`.
- [x] **S3** A `_build_instance_config` payload was loaded (`Loading config from …`) and `http://127.0.0.1:6016/` returned the Actual HTML on Node 22.23.3.
- [ ] **S4** MITP on `nodeapp00` (snapshot `clean-slate`) got through install, `system init`, and Node 22.23.3. `version install 26.10.0` stops before an instance: the tree is an npm prefix, and the follow-up `npm install` fails because `/srv/app/v26.10.0/package.json` is missing. `0.1.5a4` also imports `packaging`, which is not a declared dependency. systemd and nginx were not started.

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

- [x] **P1** `v0.1.5a4-dev` is on TestPyPI as `0.1.5a4`. Earlier dev tags failed `make dist` before any upload. Production PyPI stays on `0.1.3a1`.

## Track D — Docs claims versus the tree

`docs/source/index.rst` says the Beta milestone delivers configuration, registry inspection, logging, locking, providers, ports, version installs, instance control, doctor, backups, TLS, and support bundles. The `nodeapp00` MITP stopped at version install. `docs/source/guides/quickstart.rst` still says doctor, restore, and support bundles are under development. This track is a reading pass. Do not change behavior to make a claim true.

- [x] **D1** Walk `docs/source/` from `index.rst` (overview, guides, reference, man page) and list each feature the docs say is ready.
- [x] **D2** For each claim, find the command or provider and the test that exercises it. Mark the claim implemented, partial, or docs-only.
- [x] **D3** Write the result in `docs/reviews/`. Update this file and `docs/roadmap.rst` only where the release position was wrong. Leave production PyPI, the real server, and the VM alone.

Reading (`docs/reviews/2026-10-05-docs-claims.md`): the milestone table above stands. Ready claims are implemented except `version install` (npm prefix, then a root `npm install` and a root `build/bin/actual-server.js` check; `packaging` is imported and not declared). Doctor, backups including restore and reconcile, TLS, and support bundles have commands and tests. Overview, quickstart, and several plan pages still describe those as future. Those pages were left as published.

## Track V — Version install matches the production layout

`000-manual-install.sh` runs `npm pack`, extracts the tarball into `/srv/app/v<version>` (`--strip-components=1`), then `npm install --omit=dev --no-save` in that directory. The version root then has `package.json` and `build/bin/actual-server.js`.

`VersionInstaller.install` runs `npm pack <pkg>@<version> --json` and extracts that tarball into `/srv/app/v<version>` with the leading `package/` directory removed. `version install` then runs `npm install --omit=dev --no-save` in that directory. `packaging` is a declared dependency. The provider, registry, and command tree are unchanged. No TestPyPI upload in this slice. Production PyPI stays on `0.1.3a1`.

- [x] **V1** Declare `packaging` in `pyproject.toml`. `cli.py` imports `packaging.version`, and a clean `0.1.5a4` install exits before version install.
- [x] **V2** `version install` produces the same tree as `000-manual-install.sh`: `package.json` and `build/bin/actual-server.js` at `/srv/app/v<version>`, dependencies installed there.
- [x] **V3** Tests cover that layout. Keep the provider, registry, and command tree as they are.
- [x] **V4** `make quick-tests` green. A new TestPyPI upload only if Ken asks. Production PyPI stays on `0.1.3a1`. The real server stays on the manual script.

## Track M — One MITP for Actual 26.10.0

After V. One version, on `nodeapp00`. The current-plus-ten matrix is the spec Release milestone, later.

- [x] **M1** Restore `nodeapp00` from snapshot `clean-slate`.
- [x] **M2** Install the fixed build, run `system init`, ensure Node 22.23.3, `version install 26.10.0`, create one instance, and start systemd and nginx.
- [x] **M3** Record the result in `docs/requirements/node-compat.yaml` (and the shipped copy).

Instance `mitp` (port 6000) is active on Node 22.23.3. nginx returns the Actual HTML for `Host: mitp.local`. The wheel was the local working tree, not TestPyPI. Three host adjustments were required: `systemd.unit_dir` is `/etc/systemd/system` (the default writes units under `/run/abssctl/systemd`); `/srv` is group `actual-sync` and the instance tree is owned by `actual-sync` (create leaves `root:root` mode `0750`); the vhost under `/run/abssctl/nginx` was symlinked into `/etc/nginx/sites-enabled`. Upgrade, backup, TLS verify, doctor, support bundle, and cleanup were not run.

## Track H — Host layout in the CLI

After M. The next instance should start on a TurnKey host without those three hand edits. `nodeapp00` still has `mitp` running; this slice does not touch that host, production PyPI, or the real server.

- [x] **H1** systemd units default to `/etc/systemd/system`. `systemd.unit_dir: null` in an older config resolves to that path.
- [x] **H2** `system init` sets the service group on `/srv` and `/srv/app` (mode stays `0750`). `instance create` owns the instance tree as the service user so the unit can `chdir`, and sets that group on the instance root and install root.
- [x] **H3** nginx vhosts are still rendered under the runtime dir and linked from `/etc/nginx/sites-enabled` (`nginx.sites_enabled`). `instance create` reloads nginx after that link.
- [x] **H4** `make quick-tests` green. No TestPyPI upload. Production PyPI stays on `0.1.3a1`.

## Later (spec Release, and local quality work)

- Mutation survivor hunting beyond the bounded `exit_codes.py` CI job.
- MITP on the current Actual release plus the ten prior versions. npm must be >= 10.9.9; Actual 26.6.0 does not install below that.
- RC burn-in, production PyPI publish, and GA.
