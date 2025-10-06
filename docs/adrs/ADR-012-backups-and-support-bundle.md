# ADR 0012: Backups & Support Bundle

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** backups, support

## Context
Operators need reproducible backups and useful support artifacts.

## Options Considered
- tar.zst + checksums + index (selected)
- No index (harder reconcile)

## Decision
Use tar.zst archives with SHA-256 checksums; maintain /srv/backups/backups.json index; provide support-bundle command with redaction.

## Consequences
- Auditable metadata; easy verify/reconcile
- Requires zstd dependency on target

## Open Questions
- None
