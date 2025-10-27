====================================
Backup Restore Implementation Plan
====================================

Plan Status
===========

- **Owner:** Beta - Backup & Restore workstream (Oct 2025)
- **Milestone:** Beta — Basic Functions
- **Related ADRs:** ADR-012, ADR-021, ADR-022, ADR-024, ADR-025, ADR-026, ADR-027, ADR-028

Restore Objectives
==================

1. Deliver a safe, auditable ``backup restore`` workflow that rehydrates an instance
   from archives produced by ``backup create`` without leaving the system in a
   partially restored state.
2. Integrate with existing safety prompts so operators can capture a pre-restore
   backup and run the flow non-interactively (`--yes`, `--no-pre-backup`, `--json`).
3. Validate inputs aggressively (archive presence, checksum, disk space, permissions)
   and surface failures early with rollback to the pre-restore filesystem layout.
4. Record provenance (who restored, when, where) in both the backup index and the
   instance registry for future audits.

Scope Snapshot (Restore)
========================

- Source of truth: ``backups.json`` entry (path, checksum, algorithm, metadata) plus
  the companion ``.sha256`` file.
- Destination: default to ``<instance_root>/<instance>`` with an optional ``--dest``
  override for staging restores.
- Safety prompt: offer ``backup create`` pre-flight (respecting ``--yes`` /
  ``--no-pre-backup`` / ``--backup-message``) before mutating the live data.
- Locks: acquire the global + instance locks for the full restore lifecycle; reuse
  `_run_instance_backups(..., acquire_locks=False)` so the pre-restore backup runs
  under the same lock.
- System integration: stop systemd services when restoring into the live data dir,
  replace nginx/systemd assets when present in the archive, re-enable services,
  and restart previous state when appropriate.
- Registry/index: update instance metadata with restore timestamps and annotate the
  backup entry (`last_restored_at`, `last_restore_destination`, `restored_by`).

CLI Synopsis
============

::

   abssctl backup restore <BACKUP_ID>
       [--instance NAME]
       [--dest PATH]
       [--dry-run]
       [--json]
       [--no-pre-backup]
       [--backup-message TEXT]
       [--yes]

- ``--instance``: optional assert; command aborts if the backup targets another instance.
- ``--dest``: restore archive into an alternate directory instead of the live data dir.
- ``--dry-run``: emit the planned actions (and JSON payload) without touching the filesystem.
- ``--json``: return a structured payload `{plan, result}` for automation.

Detailed Workflow
=================

1. Resolve runtime context, load backup entry, verify checksum (`_compute_checksum`)
   and ensure archive + checksum file exist.
2. Gather pre-flight facts:
   - Confirm sufficient disk space at the destination root (archive size + 20% buffer).
   - Determine whether the target service is currently running/enabled (systemd provider).
   - Capture the archive’s compression algorithm (entry value or extension fallback).
3. Acquire global + instance locks, optionally take a pre-restore backup via the
   existing prompt helper.
4. Stage extraction:
   - Create an isolated staging directory and extract the archive with `tar`
     (`tar --zstd` / `tar -xzf` / `tar -xf` as appropriate).
   - Validate the payload structure (`<payload_root>/data`, optional service assets,
     `metadata/instance.json`, `metadata/instances.yml`).
5. Swap filesystem content atomically:
   - Rename the live data directory to ``<dir>.pre-restore-<timestamp>`` (when restoring
     into the live location) and restore from the staged payload.
   - Copy service assets (systemd unit, nginx site) with `.bak-<timestamp>` fallbacks and
     reinstate symlinks (`nginx enable`, `systemd enable`).
6. Post-restore reconciliation:
   - Update the instance registry with `paths`, `version`, `domain`, and metadata captured
     at backup time plus new `last_restored_at`/`last_restored_by`.
   - Restart the systemd unit when it was previously running; otherwise leave the service
     stopped but enabled.
   - Run `nginx -t` and reload when configs changed.
7. Cleanup & bookkeeping:
   - Remove temporary `.pre-restore-*` directories and `.bak-*` files after success.
   - When any step fails, roll back by restoring the `.pre-restore-*` directory and the
     `.bak-*` files before re-raising the error.
   - Update the backup index with `last_restored_at`, `last_restore_destination`,
     `restored_by`, and reset any previous `verification_error`.

Testing Strategy (Restore)
==========================

- CLI integration tests covering:
  - Dry-run JSON + console output (no filesystem mutations).
  - Successful restore into live data dir (data replaced, services restarted).
  - Alternate destination restores (no service stop/start).
  - Permission/disk-space failures with rollback.
- Targeted unit tests for helper utilities (archive extraction, disk-space calculation,
  rollback mechanics) via temporary directories.

Open Questions (Restore)
========================

1. Should we expose `--restart` / `--no-restart` toggles for post-restore service handling?
2. Do we need a `--data-only` restore (mirror of `backup create --data-only`) when
   operators want to skip service asset updates?
3. Longer term: surface a restore history (list) vs. a single `last_*` entry.

Reconciliation Objectives
=========================

1. Provide ``backup reconcile`` to highlight mismatches between the backup index and
   on-disk archives (missing files, orphaned archives, status drift).
2. Offer an optional `--apply` mode that updates index statuses for missing archives
   while producing actionable guidance for orphaned files.
3. Keep the command light-weight so operators can schedule it via cron/CI pipelines.

Scope Snapshot (Reconcile)
==========================

- Scan the backup root (`/srv/backups`) for ``*.tar`` / ``*.tar.gz`` / ``*.tar.zst`` archives.
- Classify entries:
  - **missing**: index entry references an archive that is absent on disk.
  - **orphaned**: archive exists on disk but has no index entry.
  - **mismatch**: index status is not `available` even though the archive is present.
- `--instance` filter to scope reconciliation to a single tenant.
- `--apply` updates index metadata for missing archives (set status `missing`,
  record `reconciled_at`) while leaving orphan handling manual for now.
- `--json` emits `{missing, orphaned, mismatched}` to feed dashboards.

Testing Strategy (Reconcile)
============================

- CLI tests covering:
  - Baseline report (no mismatches) returns empty categories.
  - Missing archive -> report + `--apply` updates index status/metadata.
  - Orphaned file -> reported with inferred instance/path metadata.
  - Instance filter limits scope to the selected tenant.

Next Iterations
===============

- Decide on automated orphan adoption (generate synthetic index entries with
  neutral status) vs. operator-driven clean-up.
- Fold reconciliation reporting into ``doctor`` once that command lands so health
  checks surface stale backups automatically.
