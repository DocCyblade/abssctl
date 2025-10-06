# ADR 0009: Providers Architecture

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** arch

## Context
Separate system integrations to keep the CLI core clean.

## Options Considered
- Pluggable provider modules (selected)
- Single monolith module (harder to test)

## Decision
Implement providers: versions (npm), systemd, nginx. Define clear contracts and error taxonomy.

## Consequences
- Easier unit/integration testing per provider
- Slightly more wiring in CLI core

## Open Questions
- None
