# ADR 0026: Safety Prompts Inventory

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** ux, safety

## Context
We prompt before risky operations and offer backup create.

## Options Considered
- Documented prompts (recommended)

## Decision
Adopt a standard safety‑prompt policy and publish an explicit inventory per subcommand. Prompts appear in interactive use; CI can bypass with `--yes` or `ABSSCTL_ASSUME_YES=1` (see ADR‑025). When a prompt offers to create a backup, users must choose `--backup` or `--no-backup` in non‑interactive mode.

### Inventory
| Command | Default prompt? | Backup behavior | Overrides |
|---|---|---|---|
| **delete-instance** | **Yes** — confirm instance name and show data path/port summary. | Offers to create a backup before deletion. | `--yes` + (`--backup` \| `--no-backup`) |
| **uninstall-version** | **Yes** — confirm removal of version directory. Blocks if any instance uses it. | Not applicable (no instance data). | `--yes` (refuses if in use; switch instances first) |
| **restore** | **Yes** — when target instance has existing data (overwrite risk). | Offers to back up current data before restore. | `--yes --force` + (`--backup` \| `--no-backup`) |
| **switch-version** | **Yes** — if it implies service restart of affected instance(s). | No backup by default. | `--yes` (add `--restart` to restart now) |
| **set-version** (alias) | **Yes** — same semantics as switch-version. | No backup by default. | `--yes` |
| **rename-instance** | **Yes** — confirm old→new and paths. | No automatic backup. | `--yes` |
| **backup prune** | **Yes** — destructive deletion of old archives. | Operates on backup store; not instance data. | `--yes` with `--keep N`/`--age DAYS` |
| **tls install** | **Yes** — if overwriting existing cert/key. | Copies old files to a timestamped backup before overwrite. | `--yes` (no backup flags) |
| **nginx enable/disable/reload** | No prompt (validated with `nginx -t`). | N/A | `--yes` optional |
| **completion install** | **Yes** — when writing to system/user locations. | N/A | `--yes` (see ADR‑020) |
| **docs man install** | **Yes** — when writing to manpaths. | N/A | `--yes` (see ADR‑019) |
| **doctor --fix** (migrations) | **Yes** — before applying file/perm fixes or migrating state. | During **migrate‑state**, moves registries and leaves compat symlinks. | `--yes` (see ADR‑024) |

Notes:
- Read‑only commands (`doctor` read‑only, `list-versions`, `support-bundle`, `backup create`) do not prompt.
- When both backup and confirmation apply, the CLI shows a single consolidated prompt with the safest default.
- Prompt text must always include the **target**, the **action**, and the **recovery hint** (e.g., where the backup will be written).

## Consequences
- Safer defaults for interactive use; CI remains fully automatable via `--yes`/env.
- Consistent operator experience across subcommands; fewer accidental destructive actions.
- Requires careful unit tests to ensure every mutating command obeys the prompt policy and flags (ADR‑013 exit codes).

## Open Questions
- Should `switch-version` optionally offer to take a quick backup when changing major versions?
- For `tls install`, do we also keep only N historical copies to avoid clutter?
- Do we need a global `--require-backup` policy knob for especially cautious environments?
