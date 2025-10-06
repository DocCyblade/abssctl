# ADR 0013: JSON Outputs & Exit Codes

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** ux, api

## Context
Automation requires stable JSON and predictable exit codes.

## Options Considered
- Documented contract (selected)
- Ad-hoc outputs (rejected)

## Decision
Add --json to read-only listings; exit codes: 0 success; 2 validation; 3 environment; 4 systemd/nginx errors.

## Consequences
- Easier scripting and CI integration

## Open Questions
- None
