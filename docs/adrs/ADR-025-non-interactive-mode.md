# ADR 0025: Non-Interactive Mode (--yes)

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** ux, automation

## Context
CI and automation need to bypass prompts safely.

## Options Considered
- Flag + env var (recommended)
- Flag only

## Decision
Introduce --yes/--assume-yes and ABSSCTL_ASSUME_YES=1 to suppress confirmations where appropriate.

### CI Scope (non-interactive-capable subcommands)
- doctor — `--json` recommended; `--fix` requires `--yes`.
- list-versions — supports `--json`.
- install-version — accepts `--yes`; optional `--npm-package-name` override.
- switch-version — accepts `--yes`; will restart instances when `--restart` is supplied.
- uninstall-version — requires `--yes` and `--no-backup` or `--backup` when applicable.
- create-instance — accepts `--yes`.
- delete-instance — requires `--yes` (and `--no-backup` or `--backup`).
- start | stop | restart INSTANCE — accepts `--yes` (no prompt by default in CI).
- backup create — non-interactive; respects `--compression` (see ADR-021).
- backup prune — requires `--yes` with explicit retention (`--keep N` and/or `--age DAYS`).
- restore — requires `--yes`; if overwriting existing data, also `--force`.
- support-bundle — non-interactive.
- nginx enable | disable | reload — accepts `--yes`; validates with `nginx -t` (see ADR-032).
- tls verify | install — `verify` is read-only; `install` requires `--yes`.
- completion install — requires `--yes` to write into system/user locations (see ADR-020).
- docs man install — requires `--yes` for writes (see ADR-019).
- migrate-state (doctor) — part of `doctor --fix`; requires `--yes` (see ADR-024).

## Consequences
- CI can run end-to-end without prompts using `--yes` or `ABSSCTL_ASSUME_YES=1`.
- Destructive operations remain explicit via guard flags (`--no-backup`/`--backup`, `--force`).
- Standardized `--json` outputs (ADR-013) enable reliable CI assertions.
- Implementation must ensure all mutating subcommands respect `--assume-yes` and exit codes documented in ADR-013.

## Open Questions
- Which subcommands remain unskippable (if any)?
