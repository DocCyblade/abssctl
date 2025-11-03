# ADR 0035: System Bootstrap & State Recovery Command

- **Date:** 2025-10-30
- **Status:** Accepted
- **Authors:** DocCyblade, Codex AI Partner
- **Deciders:** abssctl maintainers
- **Consulted:** abssctl collaborators
- **Tags:** bootstrap, cli, recovery, ux

## Context

abssctl currently assumes the host has already been prepared with the correct
service account, directory layout, configuration file, and registry state.
Early adopters must follow documentation or ad-hoc scripts to:

- create the `actual-sync` service user/group,
- provision `/etc/abssctl/config.yml` with the right roots and defaults,
- create `/srv`, `/var/lib/abssctl`, `/var/log/abssctl`, `/run/abssctl`, and
  template directories with correct ownership,
- seed the registry (`instances.yml`, `ports.yml`, `versions.yml`) or reconcile
  it when reinstalling on an existing host.

`abssctl instance create` lays down per-instance scaffolding, and `doctor
--fix` can create directories in narrow scenarios, but there is no single
“first-run” command. This makes it difficult to:

- bring new systems online quickly,
- reinstall abssctl onto servers that already host instances,
- recover the state directory after accidental deletion,
- automate infrastructure provisioning end-to-end.

We need an ergonomic bootstrap command that works for both interactive operators
and unattended automation while providing a path to rediscover and rebuild
state from an existing deployment.

## Options Considered

- **A. Documentation-only bootstrap.** Continue to rely on README/guide
  checklists plus `doctor --fix` for spot remediation.

- **B. Non-interactive script.** Ship a `system init` style command that always
  runs unattended with baked-in defaults and flags for overrides, leaving it to
  tooling to supply configuration.

- **C. Unified bootstrap command with interactive wizard, unattended mode, and
  discovery/recovery support.** Provide an interactive experience by default,
  keep flag/env overrides for automation, and teach the command to scan the
  filesystem to rebuild registry/config state when abssctl is reinstalled on an
  already-configured host.

## Decision

Adopt option **C**: implement a unified `abssctl system init` command that
handles bootstrap, supports full automation, and can rediscover existing
instances to rebuild state.

### Command behaviour

- `abssctl system init` runs interactively by default using Typer/Rich prompts.
  The wizard guides the operator through service user selection, install/instance
  roots, log/state/runtime directories, default domain suffix, TLS defaults, and
  confirmation before applying changes.
- The command is idempotent. It validates existing assets and either reuses
  them when they match or prompts before reconciling conflicts. All operations
  emit structured logs and respect global/per-instance locks.
- Non-interactive runs use `--yes`/`--defaults` (or corresponding environment
  variables) to accept defaults without prompts. Explicit overrides such as
  `--service-user`, `--install-root`, `--state-dir`, and `ABSSCTL_INIT_*` change
  individual values. `--dry-run` prints the planned actions without touching disk.
- Creation of the service user/group is opt-in: interactive runs ask for
  confirmation, non-interactive runs require `--allow-create-user` or an
  equivalent environment knob.
- The command ensures `/etc/abssctl/config.yml` exists (creating it from
  defaults + overrides), creates missing global directories with appropriate
  ownership/permissions, initialises the registry/logs/backups roots, and
  primes template override locations. Optional extras (shell completions,
  sample configs) are offered at the end of the wizard.

### Discovery and state rebuild

- `system init` accepts `--discover` to scan the filesystem for instances that
  match abssctl’s naming/layout conventions. It inspects instance roots,
  `config.json`, systemd units, and nginx sites to infer name, port, domain,
  TLS mode, version binding, and runtime paths, surfacing the findings as a plan.
- `--rebuild-state` (implies discovery) repopulates registry files
  (`instances.yml`, `ports.yml`, `versions.yml`) and regenerates
  `/etc/abssctl/config.yml` if missing, based on discovery results. Existing
  files are backed up before replacement, and conflicts are reported clearly.
- Dry-run + plan output is available for both discovery and rebuild flows,
  allowing auditors to verify results before applying them.
- The discovery/rebuild helpers will also be callable from doctor
  (e.g. `doctor --recover-state`) so mismatches between registry state and live
  filesystem resources can be detected and repaired consistently.

### Shared helpers and exit codes

- New helpers (`ensure_service_user`, `ensure_directory`, `discover_instances`,
  `write_registry_from_discovery`, etc.) will live in reusable modules so both
  `system init` and `doctor` can depend on the same logic.
- The command reuses ADR-013 exit-code conventions: validation failures exit
  with code 2, environment/precondition issues with 3, provider/system errors
  (e.g., user creation failure) with 4.

### Implementation notes

- Phase delivery: (1) helper scaffolding + dry-run logic, (2) interactive wizard
  with defaults/overrides, (3) discovery + rebuild integrations, (4) doctor
  hooks and documentation.
- Tests: unit tests for helper functions, CLI integration tests covering
  interactive (scripted answers), unattended, dry-run, and discovery/rebuild
  scenarios. Fixtures should simulate existing directories/users without
  touching the real host.
- Documentation: update requirements, README/quickstart, CLI reference, roadmap,
  and add usage guidance to doctor output once the command ships.

## Consequences

- **Improved onboarding:** Operators can prepare a fresh host in one guided
  command; automation can run the same flow with defaults and overrides.
- **Resilience:** Reinstalling abssctl or recovering from state loss becomes
  feasible without manual registry editing.
- **Maintenance overhead:** Additional helper modules, CLI surface, and tests
  introduce new code paths to maintain and document.
- **Security considerations:** User creation and permission management must be
  implemented carefully (respecting least privilege and existing policies).
  The command should log all changes for audit purposes.
- **Scheduling impact:** Work on the bootstrap command becomes the top priority
  item (subject to downstream task dependencies) and may require reordering the
  TODO list.

## Related

- Supersedes: N/A
- Superseded by: N/A
- References: `src/abssctl/cli.py`, `docs/requirements/abssctl-app-specs.txt`,
  ADR-006 Filesystem Layout & Ownership, ADR-013 JSON & Exit Codes,
  ADR-029 Doctor Probe Policy, ADR-032 Nginx Rollback Plan.
