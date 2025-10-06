# ADR 0027: Concurrency & Sub-Resource Locks

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** concurrency

## Context
Single global lock prevents overlap; per-instance parallelism may still race on resources.

## Options Considered
- Global + per-instance locks (recommended)
- Global-only lock

## Decision
Adopt global + per‑instance lock scheme.

- **Global lock**: `/run/abssctl.lock` (exclusive `flock`) to serialize operations that change global state (e.g., migrations, provider init, registry schema changes).
- **Per‑instance locks**: `/run/abssctl/<instance>.lock` (exclusive `flock`) to serialize operations on a single instance.
- **Lock ordering**: Always acquire locks in this order to avoid deadlocks: **global → instance(s) → provider‑specific** (systemd, nginx, tls).
- **Operations using per‑instance lock**: `create-instance`, `delete-instance`, `rename-instance`, `start|stop|restart`, `switch-version|set-version`, `restore`, `backup prune` (when scoped to an instance), `tls install` (instance‑scoped), `nginx enable|disable` (instance vhost).
- **Timeout & backoff**: Default wait up to **30s** with exponential backoff (jittered). Configurable via `--lock-timeout SECONDS` and `ABSSCTL_LOCK_TIMEOUT`.
- **Stale lock handling**: Lockfiles contain **PID** and **ISO8601 timestamp**. If the PID is not running and the lockfile mtime is older than **2× timeout**, `doctor --fix` may clean it; otherwise require `--force-unlock <instance>`.
- **Atomic writes**: Registry/state writes continue to use temp‑file + atomic rename (see ADR‑008). Locks gate concurrency; they do not replace atomic I/O.

## Consequences
- Prevents port/unit races while allowing safe parallel work across different instances.
- Deadlock risk mitigated by strict lock ordering and bounded timeouts.
- Small performance overhead during waits; visibility via logs helps diagnosis.
- Operators have clear remediation (`doctor --fix`, `--force-unlock`).

## Open Questions
- Log lock wait durations in `operations.jsonl` for observability?
- Support shared (read) locks for purely read‑only commands, or keep them lock‑free?
- Any need for cross‑host/distributed locking in future multi‑node scenarios?
