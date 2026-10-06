# abssctl path forward — done tracks

Version: 1.0.0
Date: 2026-10-06
Companion: [`PATH_FORWARD.md`](PATH_FORWARD.md) (the living TODO)

Finished tracks move here once every box is checked. Track S stopped and was superseded by V and M; its unchecked S4 box stays as the record of that attempt.

## Done at a glance

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
| **T** | Test copy of the manual install (name, FQDN, port) | Done |
| **R** | Take over that layout on `test-nodeapp02` | Done |

## Track W — Cursor workflow

- [x] **W1** `AGENTS.md`, `.cursor/rules/abssctl.mdc`, `.cursorignore`
- [x] **W2** `docs/CURSOR_WORKFLOW.md` and `docs/PATH_FORWARD.md`
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
- [x] **D3** Write the result in `docs/reviews/`. Update `docs/PATH_FORWARD.md` and `docs/roadmap.rst` only where the release position was wrong. Leave production PyPI, the real server, and the VM alone.

Reading (`docs/reviews/2026-10-05-docs-claims.md`): the milestone table in `docs/PATH_FORWARD.md` stands. Ready claims are implemented except `version install` (npm prefix, then a root `npm install` and a root `build/bin/actual-server.js` check; `packaging` is imported and not declared). Doctor, backups including restore and reconcile, TLS, and support bundles have commands and tests. Overview, quickstart, and several plan pages still describe those as future. Those pages were left as published.

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

## Track T — Test copy of the manual install

After H. A test guest can be laid out the same way as production. This is not the version matrix. `000-manual-install.sh` is unchanged. The script was run on `test-nodeapp02` on 2026-10-06. The script did not install abssctl. `test-nodeapp01` already has the family sites from the production clone.

- [x] **T1** `tmp-personal-server/000-test-install.sh` copies the manual install. `000-manual-install.sh` is unchanged.
- [x] **T2** The copy takes one or more instances as name, FQDN, and port. It has no production instance names.
- [x] **T3** Layout stays `npm pack`, extract into `/srv/app/v<version>`, `npm install --omit=dev --no-save`, `actual-sync`, `config.json`, systemd unit, nginx site.
- [x] **T4** Default Node is 22.23.3. `NODE` and `ACTUAL_VERSION` are overridable (`REQUIRED_NODE` is used when `NODE` is unset). npm older than 10.9.9 is refused, and the script tells you to upgrade.
- [x] **T5** nginx uses `/root/ssl/star.krajr.net.pem` and `/root/ssl/star.krajr.net.key`.

The script lives under `tmp*` (gitignored), same as `000-manual-install.sh`.

Ran 2026-10-06 on `test-nodeapp02` (left running). npm on the snapshot was 10.1.0, so `npm install -g npm@10.9.9` came first. The script then used its defaults: Actual 25.11.0 and Node 22.23.3. Three instances:

| Name | FQDN | Port |
|---|---|---|
| test1b | `test1b-abssctl-test.krajr.net` | 5110 |
| test2b | `test2b-abssctl-test.krajr.net` | 5111 |
| test3b | `test3b-abssctl-test.krajr.net` | 5112 |

Each `abssctl-<name>` unit is active on Node 22.23.3. `/srv/app/v25.11.0` has `package.json` and `build/bin/actual-server.js`. nginx returns the Actual HTML for those three names. `000-manual-install.sh` was not run.

## Track R — Take over the test-nodeapp02 layout

After T. The guest was left running. This slice installs the local wheel and ingests the three instances. `000-test-install.sh` was not run again. The guest was not rolled back. Production PyPI and the production server were not touched.

- [x] **R1** Local wheel `0.1.5a4` is installed at `/opt/abssctl`, with `/usr/local/bin/abssctl` linked to it. Not a TestPyPI install.
- [x] **R2** `abssctl system init --defaults --yes --instance-root /srv/instances --install-root /srv/app --rebuild-state`. The default instance root `/srv` would have treated `app`, `backups`, and `instances` as instances. The registry now has test1b, test2b, and test3b on ports 5110–5112. The three units stayed active. nginx still returns HTTP 200 for the three test names.

Discovery stores version `current` and leaves the domain unset (the FQDN is only in the nginx `server_name`). `versions.yml` is empty. `version install 25.11.0` would refuse because `/srv/app/v25.11.0` already exists, so it was not run. `current` still points at that tree.

Doctor (exit 4): registry matches discovery, and the systemd units are healthy. `nginx-sites` is red because the provider looks for `/run/abssctl/nginx/sites-available/abssctl-<name>.conf`. The live sites are `/etc/nginx/sites-available/abssctl-<name>.conf`, already enabled. Those symlinks were left alone; pointing them at `/run` would drop the vhosts on reboot. `tls-system-cert` is red because `/etc/ssl/private/cert.pem` and `cert.key` are mode `0400`. The test sites use `/root/ssl/`, not those paths. `app-instance-status` is yellow. `instance status` still shows each unit active on Node 22.23.3.
