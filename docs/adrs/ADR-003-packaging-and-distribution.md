# ADR 0003: Packaging & Distribution

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** packaging, ci

## Context
We will publish abssctl to PyPI, support pipx installs, and automate releases.

## Options Considered
- PyPI (selected)
- Internal index only (not desired)
- Manual uploads (error-prone)

## Decision
Publish to PyPI with wheels (manylinux where possible). Use GitHub Actions to build/test/release on tags.

## Consequences
- Simplifies user install (pip/pipx)
- Requires CI secrets for PyPI token

## Open Questions
- None
