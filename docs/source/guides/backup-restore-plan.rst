====================================
Backup Restore Implementation Plan
====================================

Plan Status (Restore)
=====================

- **Owner:** Sprint 7 follow-on (2025-10-11)
- **Milestone:** Beta — Basic Functions
- **Related ADRs:** ADR-012, ADR-021, ADR-022, ADR-024, ADR-025, ADR-026, ADR-027, ADR-028

Objectives (Restore)
====================

1. Provide a safe, auditable ``backup restore`` workflow that can bring an instance
   back to a known-good state using archives produced by ``backup create``.
2. Integrate with existing safety prompts so operators can take a pre-restore backup
   before overwriting data.
3. Keep the workflow automation-friendly (``--dry-run``, ``--json``) while
   recording outcomes in ``operations.jsonl`` and the backup index.

Scope Snapshot
==============

- Restore sources: ``backups.json`` entry (archive path, algorithm, metadata) +
  companion checksum file.
- Destination defaults: instance data directory (``<instance_root>/<instance>``),
  with an override flag to restore into an alternate staging directory.
- Safety prompt: offers to create a fresh backup of the target instance prior to
  restore (respecting ``--yes`` / ``--no-pre-backup``).
- Locks: acquire ``mutate_instances([instance])`` with global lock enabled before
  touching on-disk state; reuse `_run_instance_backups` with `acquire_locks=False`
  so the pre-restore backup runs under the existing lock.
- Registry updates: set ``restored_at`` / ``restored_to`` (future fields) so
  operators can audit restores via ``backup show``.
- Observability: emit structured plan/results so automation can react, even while
  the actual file extraction remains a placeholder in this iteration.

CLI Design
==========

::

   abssctl backup restore <BACKUP_ID>
       [--instance NAME]
       [--dest PATH]
       [--dry-run]
       [--json]
       [--no-pre-backup]
       [--backup-message TEXT]
       [--yes]

- ``--instance``: optional guard; command fails if the backup entry maps to a
  different instance.
- ``--dest``: restore into an alternate directory (defaults to the instance's data dir).
- ``--dry-run``: emit plan only (no filesystem changes).
- ``--json``: return plan/result payload.
- ``--no-pre-backup`` / ``--backup-message`` / ``--yes`` mirror existing safety prompt options.

Data Flow (Initial Iteration)
=============================

1. Resolve configuration + registry.
2. Fetch backup entry by id, validate archive path exists, resolve instance.
3. Acquire locks (global + instance).
4. Offer pre-restore backup via safety prompt (optional skip).
5. Build restore plan:
   - archive path, checksum, target directory, data-only flag.
6. If ``--dry-run``: emit plan, exit success.
7. Otherwise:
   - (Placeholder) Print that restore logic is pending.
   - Update index metadata (``last_restore_at`` style field).
   - Record success in operations log with plan + metadata.
8. Future work (post-skeleton): extract archive into staging, validate checksum
   again, swap directories atomically, restart services as needed.

Testing Strategy (Restore)
==========================

- CLI tests covering:
  - dry-run JSON/TUI outputs.
  - Validation errors (missing backup id, mismatched instance).
  - Happy-path placeholder (ensures registry updates, logging occur).
- Unit coverage for registry `update_entry` path to add restore metadata.
- Follow-up once real restore lands: integration tests extracting files into a
  temporary directory and verifying instance state + service restart.

Open Questions (Restore)
========================

1. Should restore automatically restart services (systemd/nginx) or leave that
   to operators? Likely a flag (``--restart``) post-MVP.
2. Should restores support selective assets (data-only vs. full)? Mirrors backup
   data-only flag.
3. How should we capture restore provenance (actor, destination) in the index?
   Proposal: ``restores`` history list vs. single ``last_restored_*`` fields.
4. When ``backup restore`` targets an alternate directory, do we need a follow-up
   command to promote staging → active (link to future ``instance recover`` flow)?
