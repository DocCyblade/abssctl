# ADR 0016: UX Guarantees (Dry-Run & Safety Prompts)

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** ux, safety

## Context
Risky operations should be visible and reversible.

## Options Considered
- Prompt + dry-run (selected)
- No prompts (unsafe)

## Decision
All mutating commands support --dry-run; for sensitive ops, prompt to create a backup (overridable with --no-backup).

## Consequences
- Fewer accidental destructive changes

## Open Questions
- None
