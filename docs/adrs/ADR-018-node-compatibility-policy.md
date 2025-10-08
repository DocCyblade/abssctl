# ADR 0018: Node Compatibility Policy

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** node, compat

## Context
The TurnKey Linux (TKL) Node.js appliance ships Node v18 by default. Upstream **@actual-app/sync-server** may raise its `engines.node` requirement over time. abssctl should work on TKL v18 out of the box but must alert operators when the selected Actual version requires a newer Node. abssctl is **not** a Node version manager and should treat the system Node as an external dependency managed by the OS/appliance.

## Options Considered
- Enforce engines via npm metadata (recommended)
- Static matrix in code

## Decision
For v1, adopt a **warn-only** policy.

- `abssctl doctor` queries the npm metadata for the configured package (default `@actual-app/sync-server`) and compares `engines.node` to the system Node version.
- If the requirement is **greater** than the system version, mark **YELLOW** with a clear message and suggested upgrade paths; **do not** exit non-zero solely for this.
- `install-version` and `switch-version` also emit the same warning before proceeding. They **do not** block the operation in v1.
- abssctl does **not** install or upgrade Node (no NodeSource/nvm). Node remains an operator/OS responsibility.

## Consequences
- Zero surprise OS changes: abssctl never mutates the system Node.
- Operators on TKL v18 can still proceed for testing while being warned of potential runtime issues.
- Some installs may succeed but fail at runtime if Node is too old; warnings point to remediation.
- Future policy can tighten to error-block if we choose (see ADR-029 doctor severity).

## Open Questions
- Document the canonical, supported ways to upgrade Node on TKL (newer TKL image vs OS packages) without abssctl doing it.
- Should we add a `--enforce-engines` flag (treat incompatibility as error) and/or a global config toggle?
- Should doctor show a simple matrix of Actual version → minimum Node for quick diagnostics?
