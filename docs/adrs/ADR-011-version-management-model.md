# ADR 0011: Version Management Model

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** versions, npm

## Context
We install multiple Actual versions and switch via symlink.

## Options Considered
- Versioned directories + 'current' symlink (selected)
- Global in-place install (riskier)

## Decision
Install to /srv/app/vX.Y.Z; manage /srv/app/current symlink; verify integrity; prevent uninstall if in-use.

## Consequences
- Easy rollback via switch-version
- Requires discipline for uninstall guards

## Open Questions
- None
