# ADR 0014: Logging & Observability

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** observability

## Context
We want both human-readable logs and machine events.

## Options Considered
- Human + JSONL (selected)
- Human-only logs (less automation)

## Decision
Write human logs and operations.jsonl with minimal schema (ts, op_id, actor, target, result, rc). Rotate via logrotate/journald.

## Consequences
- Better postmortems and support bundles

## Open Questions
- None
