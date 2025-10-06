# ADR 0002: Docs & Manpages Pipeline

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** docs, manpages

## Context
We need a single source-of-truth for docs and man pages with reproducible builds.

## Options Considered
- Sphinx + reStructuredText (selected)
- MkDocs + Markdown + external manpage tool
- Manual manpage writing (too brittle)

## Decision
Use reStructuredText as primary doc source and Sphinx to generate man pages from source.

## Consequences
- Unified doc sources; manpages can be generated in CI
- Local build requires Sphinx toolchain

## Open Questions
- None
