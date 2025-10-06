# ADR 0004: CLI Framework: Typer (Click-based)

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** cli, ux

## Context
We need a modern, type-hinted CLI with structured subcommands and completion.

## Options Considered
- Typer (Click-based) (selected)
- argparse (manual plumbing)
- click (without Typer niceties)
- docopt

## Decision
Adopt Typer (Click-based) for command parsing, help, and completion.

## Consequences
- Fast development with annotations
- Click dependency required

## Open Questions
- None
