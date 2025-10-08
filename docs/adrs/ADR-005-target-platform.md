# ADR 0005: Target Platform

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** platform

## Context
abssctl targets TurnKey Linux Node.js v18 (Debian) for server automation.

## Options Considered
- TKL Node.js v18 (selected)
- Generic Debian-based systems (future)
- Cross-OS (defer to later)

## Decision
Officially support the TurnKey Linux Node.js v18 appliance. Root/sudo is required for mutating operations.

## Consequences
- Tight integration with systemd and nginx assumptions
- User base limited to TKL in v1

## Open Questions
- None
