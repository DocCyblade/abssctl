# ADR 0024: State Location: /etc vs /var/lib

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** state, fs
- **Supersedes:** ADR-006 (filesystem layout) and ADR-008 (state & locking) — for the state location decision only.

## Context
Following the FHS conventions on Debian/TurnKey Linux: **/etc** is for configuration, **/var/lib** is for variable application state, **/run** for runtime/ephemeral locks, and **/var/log** for logs. Early drafts placed instance registries (e.g., instances.yml, ports.yml) under /etc/abssctl, but these are mutable and change at runtime. To align with FHS and simplify packaging/backups/permissions, we will keep config-only in /etc and move changeable state to /var/lib.

## Options Considered
- Split per FHS with migration: /etc for config; /var/lib for state (selected)
- Keep all under /etc (simpler but non-FHS)
- Move config and state both under /var/lib (incorrect for config)

## Decision
Adopt an FHS-compliant split effective v1:

- **/etc/abssctl/** — configuration only: `config.yml`, policy templates, default nginx/systemd template settings. Readable by root and the operator; write-protected from the service user.
- **/var/lib/abssctl/** — mutable state: `registry/instances.yml`, `registry/ports.yml` (and future state files). Owned by `actual-sync:actual-sync`; dirs 0750, files 0640.
- **/run/abssctl/** — runtime locks: `abssctl.lock` (global) and per-instance locks (see ADR-027). Owned by `actual-sync`, mode 0750.
- **/var/log/abssctl/** — logs and `operations.jsonl` (see ADR-014).

**Backwards compatibility & migration**
- On first run after upgrade (or `abssctl doctor --fix`), if `/etc/abssctl/instances.yml` or `ports.yml` exist, move them to `/var/lib/abssctl/registry/`.
- Create **read-only compatibility symlinks** in `/etc/abssctl/` for one minor release (v1.x) and emit a deprecation warning; plan removal in the next minor.
- Update docs, support-bundle, and backup paths to include both `/etc/abssctl` (config) and `/var/lib/abssctl` (state).

**Overrides**
- Allow `ABSSCTL_STATE_DIR` and a matching config key `state_dir` to override the default `/var/lib/abssctl` when necessary (effective config follows ADR-023 precedence).

## Consequences
- FHS-compliant layout improves predictability for operators and packagers.
- Clear separation of concerns: config (backed up and reviewed) vs mutable state (runtime-managed).
- Requires migration logic and compatibility symlinks for one release window.
- Support-bundle and backup docs must include `/var/lib/abssctl` in addition to `/etc/abssctl`.
- Permissions become simpler to reason about (service user owns state; config remains protected).

## Open Questions
- How long should we keep the compatibility symlinks (one minor vs two)?
- Confirm whether any other files (e.g., future caches) belong under `/var/lib/abssctl/cache/`.
- Reconfirm ADR-012 paths: backup archives remain under `/srv/backups/` (not state), with index recorded there.
