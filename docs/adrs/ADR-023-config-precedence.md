# ADR 0023: Config Precedence & Env Overrides

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** config, ux

## Context
We documented the order in the spec; this ADR formalizes it.

## Options Considered
- Adopt the documented order (recommended)

## Decision
Order: CLI flags > environment variables > /etc/abssctl/config.yml > built-in defaults. Env namespace ABSSCTL_*.

## Consequences
- N/A

## Open Questions
- None
