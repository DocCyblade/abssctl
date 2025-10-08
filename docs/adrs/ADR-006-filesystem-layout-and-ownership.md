# ADR 0006: Filesystem Layout & Ownership

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** fs, ops
- **Amended by:** ADR-024 (State location split to /var/lib/abssctl)

## Context
We need predictable on-disk paths and safe permissions.

## Options Considered
- FHS-like layout under /srv and /etc (selected)
- Install under /opt/actual (rejected for TKL norms)

## Decision
Use /srv/app/vX.Y.Z with /srv/app/current symlink; per-instance at /srv/<instance>/; **config** under /etc/abssctl/; **mutable state** under /var/lib/abssctl/registry/ (instances.yml, ports.yml); **runtime locks** under /run/abssctl/; **logs** under /var/log/abssctl/. Ownership: actual-sync user for state/run/logs; dirs 0750, files 0640. (Amends earlier drafts that placed state under /etc; see ADR-024.)

## Consequences
- Consistent backups and support-bundle capture
- Permissions must be enforced by the CLI
- Aligns with Debian FHS (config under /etc, mutable state under /var/lib)

## Open Questions
- None
