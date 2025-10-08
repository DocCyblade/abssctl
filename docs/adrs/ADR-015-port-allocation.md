# ADR 0015: Port Allocation Policy

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** networking

## Context
Instances need deterministic, non-colliding ports.

## Options Considered
- Sequential base strategy (selected)
- Random free port (harder to predict)

## Decision
Default base port 5000; sequential assignment; track reservations in /etc/abssctl/ports.yml.

## Consequences
- Predictable URLs; easy diagnostics

## Open Questions
- None
