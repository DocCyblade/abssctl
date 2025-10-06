# ADR 0007: Security Model

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** security

## Context
Principle of least privilege for services and keys.

## Options Considered
- Dedicated user (selected)
- Run-as-root services (rejected)

## Decision
Run services as dedicated user 'actual-sync'; enforce umask 027; private keys 0600; validate inputs.

## Consequences
- Safer defaults; extra setup steps in doctor --fix

## Open Questions
- None
