# ADR 0010: Reverse Proxy Strategy (nginx)

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** nginx, tls

## Context
We need predictable vhosts and safe reloads.

## Options Considered
- Per-instance vhost (selected)
- Single multi-upstream vhost (harder to manage)

## Decision
One nginx vhost per instance; validate with nginx -t; use reload (not restart); TLS uses TKL defaults unless overridden.

## Consequences
- Isolated changes per instance
- Templating must manage symlinks atomically

## Open Questions
- None
