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
Officially support the TurnKey Linux Node.js appliance. Root/sudo is required for mutating operations.

## Amendment (2026-10-04)
Actual 25.11 and newer require Node.js >= 22. The preferred patch is 22.23.3: Node 22.11.0 segfaults inside ``better-sqlite3`` 13.0.3, and 22.23.3 serves the 26.10.0 UI. abssctl stays on TurnKey Linux, and it installs that Node with ``abssctl node ensure`` (via ``n``) instead of assuming the image's Node 18 is enough to run the sync server. Node 18 remains the historical baseline for older Actual releases only.

The project is in **beta**: instance lifecycle, backups, TLS, doctor, and support bundles are implemented. v1 still needs an appliance burn-in (see ``docs/source/guides/mitp.rst``).

## Consequences
- Tight integration with systemd and nginx assumptions
- User base limited to TurnKey Linux / Debian in v1
- Operators on a stock Node 18 image must run ``node ensure`` before installing Actual 25.11+

## Open Questions
- None
