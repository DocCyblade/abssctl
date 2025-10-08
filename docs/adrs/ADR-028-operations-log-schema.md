# ADR 0028: Operations Log Schema

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** observability, logging

## Context
We maintain a JSON Lines audit log at **/var/log/abssctl/operations.jsonl**, one JSON object per line. Every top‑level abssctl command writes a single summary record **after completion** (success or failure). Read‑only commands may log at lower verbosity. The goal is to have a small, stable, machine‑parseable schema that’s also human‑diffable and easy to include in support bundles.

## Options Considered
- Fixed minimal schema (selected)

## Decision
Define a minimal, versioned schema and logging policy.

### Logging policy
- **Location**: `/var/log/abssctl/operations.jsonl` (root‑writable; group `actual-sync`; mode `0640`).
- **Cardinality**: one entry per top‑level command invocation.
- **Timing**: write after completion (success or failure). Optional `steps` breadcrumbs for complex ops.
- **Collection**: support‑bundle includes current and rotated files (see ADR‑014).

### Schema (JSON object per line)
- `schema_version` (int) — start at `1`.
- `ts` (string) — UTC ISO‑8601 with `Z`, e.g., `"2025-10-05T18:08:41.322Z"`.
- `op_id` (string) — unique id (ULID preferred or UUIDv4).
- `command` (string) — top‑level subcommand name, e.g., `"create-instance"`.
- `args` (object) — **non‑secret** effective arguments after precedence (ADR‑023).
- `actor` (object) — who initiated the run: `{"type":"user|ci|system","name":"ken|github-actions|root","session":"tty1|run-123"}`.
- `target` (object) — primary resource, e.g., `{ "kind":"instance", "name":"prod-family" }` or `{ "kind":"version", "value":"25.8.0" }`.
- `planned_actions` (array<object>) — high‑level planned steps (safe for dry‑run). Example: `{ "action":"systemd_restart", "unit":"prod-family-budgetapp.service" }`.
- `result` (object):
  - `status` — `"success" | "warning" | "error"`
  - `message` — human summary
  - `errors` — array<string>
  - `warnings` — array<string>
  - `changed` — integer count of applied changes
  - `backups` — array<string> (ids/filenames; avoid absolute paths)
- `rc` (int) — exit code (binds to ADR‑013: 0/2/3/4).
- `duration_ms` (int) — wall‑clock duration using a monotonic timer.
- `lock_wait_ms` (int, optional) — total time waiting on locks (ADR‑027).
- `steps` (array<object>, optional) — breadcrumbs: each `{name, ts, status, detail?}`.
- `redactions` (array<string>, optional) — what was hidden (e.g., `"paths"`, `"secrets"`).
- `context` (object, optional) — bounded ambient info (e.g., `abssctl_version`, `node_version`, `os_release`), added on non‑zero rc or when `--verbose`.

### Redaction policy
- Never log secrets (tokens, passwords, key material) or environment values.
- Prefer relative identifiers to absolute paths. If absolute paths are logged, redact prefixes (e.g., `"/srv/.../data"`).
- For TLS ops, log filenames and metadata (mode/owner), never PEM contents.

### Rotation & retention
- Managed by logrotate/journald per ADR‑014; keep rotated logs in support‑bundle.

### Examples
Create instance (success):
```json
{"schema_version":1,"ts":"2025-10-05T18:09:11.012Z","op_id":"01J9W8T5Z8C9S3R7PV0V4EZ3QK","command":"create-instance","args":{"instance":"prod-family"},"actor":{"type":"user","name":"ken"},"target":{"kind":"instance","name":"prod-family"},"planned_actions":[{"action":"create_dir","path":".../srv/prod-family/data"},{"action":"write_file","path":".../etc/systemd/system/prod-family-budgetapp.service"},{"action":"write_file","path":".../etc/nginx/sites-available/prod-family.conf"}],"result":{"status":"success","message":"Instance created and enabled","warnings":[],"errors":[],"changed":3,"backups":[]},"rc":0,"duration_ms":842,"lock_wait_ms":37}
```
Uninstall version (blocked by in‑use):
```json
{"schema_version":1,"ts":"2025-10-05T18:11:43.500Z","op_id":"01J9W8Y6Q2B7J1M4H0W2XZV9GS","command":"uninstall-version","args":{"version":"25.8.0"},"actor":{"type":"user","name":"ken"},"target":{"kind":"version","value":"25.8.0"},"planned_actions":[{"action":"remove_dir","path":".../srv/app/v25.8.0"}],"result":{"status":"error","message":"Version in use by instances: prod-family, test","errors":["in_use: prod-family","in_use: test"],"warnings":[],"changed":0,"backups":[]},"rc":2,"duration_ms":123}
```
Doctor (yellow: zstd missing):
```json
{"schema_version":1,"ts":"2025-10-05T18:15:00.004Z","op_id":"01J9W90A9V3M2KNS3BN4M6T9ZB","command":"doctor","args":{"json":true},"actor":{"type":"ci","name":"github-actions","session":"run-12345"},"target":{"kind":"system","scope":"health"},"planned_actions":[],"result":{"status":"warning","message":"zstd not found; backups will use gzip","warnings":["missing:zstd"],"errors":[],"changed":0,"backups":[]},"rc":0,"duration_ms":410}
```

## Consequences
- Stable, versioned structure that’s easy for operators and CI to parse.
- `rc`, `status`, and `changed` enable reliable assertions; `op_id` eases cross‑referencing with system logs.
- Redaction policy avoids leaking sensitive data while preserving usefulness.
- Minimal overhead; helpful signals like `lock_wait_ms` enable performance diagnostics (ADR‑027).

## Open Questions
- Default behavior for `context`: always include minimal info, or include only on non‑zero rc / `--verbose`?
- Do we cap the size of `planned_actions` to avoid noisy entries on bulk operations?
- Any need for a `trace_id`/`parent_id` if we later add nested operations?
