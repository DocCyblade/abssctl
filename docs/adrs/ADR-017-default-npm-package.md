# ADR 0017: Default npm Package Name

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** npm, versions

## Context
The Actual Sync Server upstream currently publishes under the npm scope **@actual-app**. We want abssctl to work out of the box with the current correct package *and* remain resilient if upstream renames or re-scopes later. Operators must be able to override the package name without code changes.

## Options Considered
- Default @actual-app/sync-server (recommended)
- Require explicit package name in config

## Decision
Set the default npm package to **@actual-app/sync-server**.

Make this configurable via:
- Global config key in `/etc/abssctl/config.yml`: `npm_package_name: "@actual-app/sync-server"`
- Environment override: `ABSSCTL_NPM_PACKAGE_NAME`
- CLI flag for commands that resolve/install versions (e.g., `install-version`, `list-versions`, `switch-version`): `--npm-package-name`

Effective value follows the documented precedence: **CLI flags > environment variables > /etc/abssctl/config.yml > built-in defaults**. `abssctl doctor` verifies that the configured package exists and is reachable in the selected registry.

## Consequences
- Works out of the box using the correct upstream package today.
- Safe future-proofing: operators can change the package name without a new abssctl release.
- Clear precedence model enables CI customization and reproducible runs.
- `doctor` can detect typos or upstream renames early with actionable guidance.
- Documentation and `--help` must surface the key/flag/env consistently.

## Open Questions
- Maintain an alias map to warn/auto-migrate common legacy names (e.g., `@actual/server`)?
- Allow per-instance overrides in addition to the global default (current decision: global only)?
