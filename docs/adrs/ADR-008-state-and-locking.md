# ADR 0008: State & Locking

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** state, concurrency
- **Amended by:** ADR-024 (State location split to /var/lib/abssctl)

## Context
We need an authoritative registry and safe concurrent operations.

## Options Considered
- Single registry YAML + process lock (selected)
- Database (overkill)

## Decision
Keep registries under **/var/lib/abssctl/registry/**: `instances.yml` and `ports.yml`. Use a global lock at **/run/abssctl.lock**. Perform atomic writes via temp files + rename. On upgrade, if legacy registries are found under **/etc/abssctl** the `doctor --fix` migrates them to `/var/lib/abssctl/registry/` and leaves read‑only compatibility symlinks for one minor release (see ADR‑024).

## Consequences
- Simple to reason about; works well on TKL
- Concurrent operations must respect the lock

## Open Questions
- Should we add per-instance locks alongside the global lock (see ADR-027)?
- Do we need journaled writes for registries or is atomic rename sufficient?
