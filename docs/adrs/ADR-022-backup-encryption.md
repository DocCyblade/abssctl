# ADR 0022: Backup Encryption (Deferred)

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** security, backups

## Context
Operators may want encryption at rest for archives.

## Options Considered
- age-based encryption
- GPG symmetric/asymmetric
- None (v1)

## Decision
Defer to post-v1; plan pluggable encryption (age/GPG) with clear key management guidance.

## Consequences
- Keeps v1 simple: no key management or passphrase prompts in the CLI.
- Operators who require encryption today can use storage-level encryption (e.g., LUKS/ZFS) or an external wrapper pending v1.x.
- We avoid format lock-in by planning pluggable hooks now (header/metadata space reserved in the backup index).
- Clear documentation will mark backup encryption as a post-v1 roadmap item.

## Open Questions
- Which scheme has the best UX for restore on TKL?
