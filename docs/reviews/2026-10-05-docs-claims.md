# Docs claims versus the tree

Date: 2026-10-05
Sources: `docs/source/` walked from `docs/source/index.rst` (overview, guides, reference, man page, and `docs/roadmap.rst` via `docs/source/roadmap.rst`)

This is a reading pass. No command behavior was changed.

A claim is **implemented** when the command or provider exists and a test exercises the behavior the page describes. **Partial** means the command and a test exist, and the documented outcome is not what the tree produces. **Docs-only** means a page says the feature is ready and the tree has no command or provider for it. Nothing in the ready list is docs-only.

## What the pages say

`docs/source/index.rst` says the Beta milestone delivers configuration, registry inspection, structured logging, locking, templated providers, ports, version installs, instance control, doctor, backups, TLS, and support bundles.

`docs/source/overview.rst` (Current Status) says the Alpha set is in: `config show`, registry listings, version install/switch/uninstall, the instance lifecycle, logging, locking, templated providers, and the ports registry. Its Next Steps section still lists TLS, backup restore/reconcile, `doctor`, and `support-bundle` as work to do.

`docs/source/guides/quickstart.rst` says lifecycle commands are available, and that doctor probes, restore, and support bundles are under development. Its "What Comes Next?" section places TLS, doctor, support bundles, and restore/reconcile in a future Beta.

`docs/source/reference/cli-commands.rst` and `docs/source/man/abssctl.rst` document the command set as present. The man page also lists `node ensure`, `docs man`, and `completion`, which the CLI reference omits.

`docs/source/guides/mitp.rst` is a checklist to run before promoting the branch. It does not say a run has passed.

`docs/roadmap.rst` says Beta features are in the tree, with version install as the open Beta gap, and that the `nodeapp00` MITP stopped there. That position matches this reading.

## Feature claims

| Claim (home page) | Command or provider | Test | Verdict |
|---|---|---|---|
| Configuration | `config show` in `src/abssctl/cli.py`; loader in `src/abssctl/config.py` | `tests/test_cli.py` (`test_config_show_renders_table`, `test_config_show_json`); `tests/test_config_loader.py` | Implemented |
| Registry inspection | `StateRegistry` in `src/abssctl/state/registry.py`; `version list`, `instance list`/`show`, `ports list` | `tests/test_state_registry.py`; `test_version_list_uses_registry`, `test_instance_list_reads_registry`, `test_instance_show_success`, `test_ports_list_reports_reservations` | Implemented |
| Structured logging | `src/abssctl/logging.py` | `tests/test_logging.py`; `test_operations_logging_creates_records` | Implemented |
| Locking | `src/abssctl/locking.py` | `tests/test_locking.py`; `test_instance_create_acquires_lock` | Implemented |
| Templated providers | `src/abssctl/providers/systemd.py`, `src/abssctl/providers/nginx.py`, `src/abssctl/templates/` | `tests/test_systemd_provider.py`, `tests/test_nginx_provider.py`, `tests/test_template_engine.py` | Implemented |
| Ports | `src/abssctl/ports.py` | `tests/test_ports_registry.py` | Implemented |
| Version installs | `VersionInstaller` in `src/abssctl/providers/version_installer.py`; `version install` | `tests/test_version_installer.py`; `test_version_install_records_registry` and the other `test_version_install_*` cases | Partial |
| Instance control | `instance` commands; systemd and nginx providers | `tests/test_cli.py` create/enable/disable/start/stop/restart/status/logs/env/set-fqdn/set-port/set-version/rename/delete | Implemented |
| Doctor | `src/abssctl/doctor/` (`probes.py`, `engine.py`, `repairs.py`); `doctor` | `tests/test_doctor_probes.py`, `tests/test_doctor_engine.py`, `tests/test_doctor_cli.py` | Implemented |
| Backups | `src/abssctl/backups.py`; `backup create/list/show/verify/restore/reconcile/prune` | `tests/test_backups_registry.py`, `tests/test_cli_backup_helpers.py`; `test_backup_*` in `tests/test_cli.py` | Implemented |
| TLS | `src/abssctl/tls.py`; `tls verify/install/use-system`; nginx template `src/abssctl/templates/builtin/nginx/site.conf.j2` | `tests/test_tls.py`; `test_tls_verify_manual_reports_success`, `test_tls_install_updates_registry`, `test_tls_use_system_switches_source` | Implemented |
| Support bundles | `src/abssctl/support_bundle.py`; `support-bundle` | `tests/test_support_bundle.py`; `test_support_bundle_creates_redacted_archive` and the other bundle cases in `tests/test_cli.py` | Implemented |

`index.rst` also says Actual 25.11 and newer require Node.js 22. `node ensure` is `src/abssctl/node_runtime.py`. Tests: `tests/test_node_runtime.py` (`test_ensure_version_installs_when_missing`) and `test_node_ensure_dry_run_with_explicit_version` / `test_node_ensure_uses_compat_file_when_version_not_supplied` in `tests/test_cli.py`. Implemented.

## Commands the reference and man page treat as present

| Command | Test | Verdict |
|---|---|---|
| `system init` | `tests/test_cli_system_init.py` (dry-run, `--json`, discover, rebuild-state, missing `--allow-create-user`); directory planning in `tests/test_bootstrap_filesystem.py` | Implemented |
| `config show` | see Configuration above | Implemented |
| `version list`, `version check-updates` | `test_version_list_*`, `test_version_check_updates_*` | Implemented |
| `version install` | see Version installs above | Partial |
| `version switch`, `version uninstall` | `test_version_switch_*`, `test_version_uninstall_*` | Implemented |
| `ports list` | `test_ports_list_reports_reservations` | Implemented |
| `instance list/show/create/enable/disable/start/stop/restart/status/logs/env/set-fqdn/set-port/set-version/rename/delete` | matching `test_instance_*` cases in `tests/test_cli.py` | Implemented |
| `tls verify/install/use-system` | see TLS above | Implemented |
| `doctor` (including `--fix` and `--fix --dry-run`) | `test_doctor_fix_dry_run_previews_repairs`, `test_doctor_fix_applies_repairs` | Implemented |
| `support-bundle` | see Support bundles above | Implemented |
| `backup create/list/show/verify/restore/reconcile/prune` | `test_backup_create_generates_archive`, `test_backup_list_and_show`, `test_backup_verify_reports_status`, `test_backup_restore_restores_data`, `test_backup_reconcile_reports_mismatches`, `test_backup_prune_removes_archives` | Implemented |
| `node ensure` | see Node above | Implemented |
| `docs man path/install` | `tests/test_operator_extras.py` (`test_cli_completion_show_and_man_path`, `test_man_install_and_flag_conflict`) | Implemented |
| `completion show/install/uninstall` | `tests/test_operator_extras.py` (`test_render_and_install_round_trip`, `test_cli_completion_show_and_man_path`) | Implemented |

`version switch` and `version uninstall` operate on a version directory and a registry row. Their tests plant that directory. On an appliance they sit behind `version install`, which does not leave a usable tree.

Shared behavior in the CLI reference (`--dry-run`, `--yes`, `--no-backup`, exit codes 0/2/3/4) is exercised across those tests. Implemented.

## Partial: version install

`docs/source/reference/cli-commands.rst` says `version install` places the release under `<install_root>/vX.Y.Z` and records npm integrity. The man page and MITP checklist say the install yields `build/bin/actual-server.js`.

`VersionInstaller.install` runs `npm install <package>@<version> --prefix` and moves that prefix to `/srv/app/v<version>`. The package then sits at `node_modules/@actual-app/sync-server/`. `tests/test_version_installer.py` (`test_install_success_creates_target_directory`) asserts that prefix.

`version install` then calls `_install_version_dependencies`, which runs `npm install` in the version root, and requires `build/bin/actual-server.js` on that same root (`src/abssctl/cli.py`, `version_install`). The prefix has no root `package.json`, so that follow-up install fails. PATH_FORWARD track S records the same stop on `nodeapp00`.

The CLI tests stay green because they replace `VersionInstaller.install`. `test_version_install_records_registry` writes `build/bin/actual-server.js` onto the version root itself via `_ensure_entrypoint`. They do not run the prefix the installer writes, and they do not run the follow-up `npm install` against it.

`src/abssctl/cli.py` imports `packaging.version` at module level. `pyproject.toml` `project.dependencies` does not list `packaging`. Track S already recorded that a clean `0.1.5a4` install exits before version install. This reading only rechecked the import and the dependency list.

## Pages that lag the tree

These pages describe shipped commands as still ahead. They were left unchanged.

- `docs/source/overview.rst` Next Steps: TLS, restore/reconcile, `doctor`, `support-bundle`.
- `docs/source/guides/quickstart.rst`: doctor, restore, and support bundles "under active development"; Beta still to come for TLS, doctor, support bundles, and restore/reconcile.
- `docs/source/guides/doctor-plan.rst`: "will implement" probe categories, and the probe-implementation and JSON-fixture boxes are unchecked. `src/abssctl/doctor/probes.py` has the categories the CLI reference lists (`env`, `config`, `state`, `fs`, `ports`, `systemd`, `nginx`, `tls`, `app`, `disk`), and `tests/test_doctor_probes.py` covers them.
- `docs/source/guides/systemd-nginx-provider-plan.rst` Beta follow-up still says to extend nginx contexts "once TLS commands land" and to capture provider health "for future `doctor --json`". TLS commands and `doctor --json` are in the tree.
- `docs/source/guides/backup-restore-plan.rst` is written as a plan. `backup restore` and `backup reconcile` are implemented and tested. Its later note says to fold reconcile into doctor "once that command lands."
- `docs/source/guides/developer-guide.rst` still names the integration branch `dev-alpha5` and points at `ops/session-log.txt` for the latest session. The living branch is `dev-beta1-redux`. The workflow file is `docs/CURSOR_WORKFLOW.md`.

`docs/source/reference/cli-commands.rst` says `instance show` exits with code 1 when the instance is missing. `instance_show` calls `_command_error(..., rc=2)`, and `test_instance_show_missing` expects exit code 2.

The CLI reference does not mention `node ensure`, `docs man`, or `completion`. The man page does, and those commands are implemented.

## Release position

The milestone table in `docs/PATH_FORWARD.md` and the "Where the spec milestones stand" section of `docs/roadmap.rst` match this reading:

- Planning, Pre-Alpha, and Alpha match the logging, locking, providers, ports, and instance lifecycle in the tree.
- Beta commands for backups, TLS, doctor, and `system init` are implemented and tested. The open Beta gap is `version install`.
- Support bundle, man page, completion, and the MITP checklist are in. The first appliance run stopped at version install.
- The current-plus-ten burn-in remains the Release milestone.

No release-position text was rewritten. `docs/source/index.rst`, `overview.rst`, and `quickstart.rst` were left as published.
