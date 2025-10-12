Backup Command Design & Implementation
======================================

Plan Status (Backups)
=====================

- **Owner:** Sprint 7 working session (2025-10-11)
- **Milestone:** Alpha foundations → Beta bridge
- **Related ADRs:** ADR-006, ADR-012, ADR-021, ADR-022, ADR-024, ADR-025, ADR-026, ADR-027, ADR-028

Objectives (Backups)
====================

1. Deliver a reliable ``abssctl backup create`` command that captures all
   instance-critical assets, produces a compressed archive, and records a durable
   registry entry.
2. Provide hooks so other commands (``version install|switch|uninstall``,
   ``instance delete``) can trigger backups via safety prompts (ADR-026).
3. Keep the workflow compatible with non-interactive automation (ADR-025) and
   the operations log schema (ADR-028).

Scope & Requirements Snapshot
=============================

- *Archive layout* (ADR-012, requirements §5.8):

  - Output root: ``/srv/backups/`` owned by ``actual-sync:root`` (0750).
  - Per-instance directory: ``/srv/backups/<instance>/``.
  - Archive name: ``YYYYMMDD-HHMMSS-<instance>-<shortid>.tar.{zst|gz}``.
  - Contents: instance data directory, rendered systemd service, nginx vhost,
    relevant registry metadata, optional extras (future hooks).

- *Index*: ``/srv/backups/backups.json`` is the source of truth. Each entry
  records identifiers, timestamps, actor, algorithm, checksum, archive size,
  free-text message, and a status flag (valid, missing, orphaned, etc.).

- *Compression*: default ``auto`` (ADR-021) → prefer zstd, fall back to gzip,
  allow explicit ``--compression {auto,zstd,gzip,none}`` and optional level.

- *Checksum*: generate SHA-256 for every archive; store alongside entry and as
  ``<archive>.sha256`` for quick verification.

- *Encryption*: deferred beyond v1 (ADR-022); design the index schema so future
  providers can insert encryption metadata without breaking compatibility.

- *Prompts & non-interactive* (ADR-025/026):

  - ``backup create`` itself runs without confirmation but honours ``--yes`` /
    ``ABSSCTL_ASSUME_YES`` if we later add prompts (e.g., overwrite target).
  - Other commands offering backups must accept ``--backup``/``--no-backup``.

- *Locks* (ADR-027):

  - Acquire global backup lock (prevents concurrent archives).
  - Acquire the per-instance lock to freeze mutations during capture.
  - When interacting with the versions registry (future switch integration),
    reuse ``mutate_versions`` after the backup completes to avoid deadlocks.

- *Operations log* (ADR-028):

  - Record ``command="backup create"``, planned actions (tar invocation), and
    result metadata including the archive identifier in ``result.backups``.

Data Flow
=========

1. Resolve configuration: backup root (defaults to ``/srv/backups``), state dir,
   runtime dir, compression defaults.
2. Acquire locks: ``locks.mutate_instances([instance])`` with
   ``include_global=True`` plus a dedicated ``locks.backup(instance)`` if we
   split responsibilities (implementation TBD). Lock manager must guarantee the
   same order for callers triggered via prompts.
3. Prepare paths:

   - Ensure ``/srv/backups/<instance>`` exists with correct ownership/mode.
   - Generate identifier ``20251011-1832-instance-abc123`` (timestamp + short
     ``secrets.token_hex`` or ``uuid4`` suffix).
   - Select compression algorithm & extension.

4. Stage archive:

   - Create temporary directory under backup root.
   - Mirror required files into staging (symlinks acceptable) or stream with tar
     ``--directory`` to avoid duplication.
   - Run ``tar`` with ``--zstd`` or ``-z`` (gzip) and capture exit codes +
     stderr for logging. For ``none`` compression, still use tar but omit flags.

5. Compute checksum:

   - Stream archive through SHA-256 while writing (preferred) or hash after the
     fact if streaming complexity is high initially.
   - Persist ``<archive>.sha256`` containing ``<digest>  <filename>``.

6. Write metadata:

   - Load ``backups.json`` via ``StateRegistry``-style helper dedicated to
     backups (new module, similar atomic write semantics).
   - Append entry:

     .. code-block:: json

        {
          "id": "20251011-1832-instance-abc123",
          "instance": "instance",
          "created_at": "2025-10-11T22:32:41Z",
          "created_by": {"user": "...", "session": "..."},
          "path": "/srv/backups/instance/20251011-1832-instance-abc123.tar.zst",
          "algorithm": "zstd",
          "compression_level": null,
          "size_bytes": 12345678,
          "checksum": {"algorithm": "sha256", "value": "<hex>"},
          "message": "Pre-upgrade safeguard",
          "status": "available",
          "metadata": {
            "data_only": false,
            "labels": ["pre-version-install"]
          }
        }

   - Use atomic write (tmp file → rename) and apply ``0640`` permissions.

7. Emit structured log entry referencing the new ID so downstream automation can
   correlate with prompted backups.

CLI Flags
=========

``backup create <instance>`` should support:

- ``--message/-m``: user-supplied note stored in index.
- ``--label``: repeatable key for grouping backups (e.g., ``--label pre-upgrade``).
- ``--data-only``: skip systemd/nginx assets when requested.
- ``--out-dir``: override default root (useful for testing).
- ``--compression`` / ``--compression-level`` per ADR-021.
- ``--json``: emit metadata of the new backup (id, path, checksum).
- ``--dry-run``: show planned sources and estimated size without creating files.

Locking & Concurrency Notes
===========================

- Backup command is inherently mutating; wrap the entire run in
  ``locks.mutate_instances([instance])`` with global lock enabled.
- If later we allow multiple backups in parallel (different instances), ensure
  the lock manager supports a dedicated ``backup`` lock keyed per instance to
  serialise with restores/prunes.
- Safety prompts in other commands must acquire locks in this order:
  ``mutate_versions`` (if needed) → ``mutate_instances`` → optional provider
  locks → call ``backup create`` inline (reusing the already-held instance lock)
  or spawn a helper that can detect the lock is already held.

File Ownership & Permissions
============================

- Backup directories and archives: ``actual-sync:root`` with ``0640`` mode to
  avoid accidental exposure of database dumps.
- ``backups.json`` index: same ownership/mode as archives; enforce via helper.
- Temporary files: ensure cleanup on failure to avoid filling disk.

Observability & Failure Handling
================================

- On success: report archive path, checksum, size, and compression algorithm on
  stdout (table + ``--json``).
- On partial failure (tar errors, checksum mismatch): delete staging artifacts,
  emit structured log ``status=error``, and exit with code 4 (align with existing
  CLI semantics).
- Surface actionable remediation (e.g., permission denied, insufficient space).
- Update ``doctor`` checklist to warn if backups index is missing or stale.

Testing Strategy (Backups)
==========================

- Unit tests for backup registry helpers (read/write/index merge, status flags).
- CLI tests using temporary directories with fake ``tar`` to validate flows,
  compression selection, and metadata accuracy.
- Integration tests (future): run on TurnKey Linux CI to ensure zstd auto-detect
  works and archives restore cleanly.

Open Questions (Backups)
========================

1. Should we snapshot PostgreSQL dumps separately for multi-instance hosts or
   rely on instance-level tar captures?
2. How much effort to stream the checksum during tar execution vs. post-pass?
3. Do we offer incremental backups in v1, or defer entirely to v1.x roadmap?
4. What is the retention policy default (e.g., keep latest N) if the operator
   never runs ``backup prune``?


Current Implementation Snapshot
===============================

- ``backup create`` now emits archives under the configured root, writes the
  checksum sidecar, and appends structured metadata to ``backups.json`` (id,
  checksum, algorithm, labels, user message).
- CLI options ``--message``, ``--label`` (comma-separated), ``--out-dir``,
  ``--compression`` / ``--compression-level``, ``--json``, and ``--dry-run`` are
  implemented per the plan. `backup list` / `backup show` expose registry
  contents, `backup verify` recomputes SHA-256 digests, and `backup prune`
  removes archives via ``--keep`` / ``--older-than`` policies.
- Version lifecycle commands (install/switch/uninstall) and `instance delete`
  automatically invoke the backup workflow when operators accept the safety
  prompt (or pass ``--yes``), tagging backups with their originating operation.
