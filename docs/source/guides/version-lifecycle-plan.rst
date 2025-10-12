=====================================
Version Lifecycle Implementation Plan
=====================================

Plan Status
===========

- **Owner:** Alpha Foundations team (session 2025-10-08)
- **Milestone:** Alpha 4 → Alpha 5 bridge
- **Related ADRs:** ADR-009, ADR-011, ADR-013, ADR-015, ADR-017, ADR-026

Current State
=============

- CLI exposes ``version list`` (registry + optional npm merge) and a placeholder
  ``version check-updates`` command; install/switch/uninstall are not yet wired.
- ``StateRegistry`` persists ``versions.yml`` but the schema is loosely defined
  (strings or mappings); no helpers exist for mutation.
- Locking only covers instances/global resources; version-specific locks are not
  available.
- ``VersionProvider`` lists remote versions via npm and maintains an optional
  cache but does not install packages.
- Tests cover listing behaviour and logging, but there is no coverage for
  mutating the install root (`/srv/app`) or version registry.

Goals for Upcoming Iterations
=============================

1. **Implement install/switch/uninstall flows**

   - Install Actual versions under ``<install_root>/vX.Y.Z`` using npm (or a
     configurable command) with integrity checks and atomic directory handling.
   - Manage the ``<install_root>/current`` symlink on ``version switch`` with
     optional restart behaviour for instances bound to ``current``.
   - Prevent uninstall when instances depend on a version or it is the active
     ``current`` target (unless ``--force``).

2. **Safety prompts & backups**

   - Honour ADR-026: prompt for ``backup create`` before install/switch/uninstall
     unless ``--no-backup`` or global non-interactive flags are used.

3. **Registry & metadata**

   - Define a structured schema for ``versions.yml`` including installation path,
     installed timestamp, integrity metadata, and flags (e.g., ``default``).
   - Provide helper functions to add/update/remove version entries safely.

4. **Locking & concurrency**

   - Extend ``LockManager`` with a ``mutate_versions`` helper (global + per-version
     locks) to avoid concurrent installs/switches/uninstalls.

5. **Testing strategy**

   - Unit tests for registry helpers, lock acquisition, and error handling.
   - CLI tests using temporary directories and fake ``npm`` binaries to validate
     install/switch/uninstall flows without requiring network access.
   - Golden-file comparisons for generated metadata and symlink targets.

Version Lifecycle Roadmap
=========================

1. **Schema & helpers**

   - Establish a canonical ``versions.yml`` entry structure:
     ``{"version": "...", "path": "...", "installed_at": "...", "metadata": {...}}``.
   - Add registry helpers (e.g., ``get_version``, ``update_version``,
     ``remove_version``) with atomic writes.
   - Persist an ``integrity`` block per entry capturing npm ``shasum`` and the
     tarball digest (decoded from the npm integrity string) for audit trails.

2. **Lock extensions**

   - Introduce ``LockManager.mutate_versions(versions, include_global=True)`` that
     locks the global file and per-version lock files under ``runtime_dir``.

3. **Installer abstraction**

   - Implement an ``npm install`` wrapper that supports dry-run/testing via
     dependency injection or environment variables (e.g., ``ABSSCTL_FAKE_NPM``).
   - Verify installation success (directory exists, expected binaries) and record
     integrity info (SHA checksum or npm metadata).

4. **CLI command wiring**

   - Add ``version install`` (with ``--set-current``) that:
       * acquires locks → prompts for backup → installs version → updates registry
         → optionally calls ``version switch`` logic.
       * backup prompt now runs ``backup create`` for impacted instances when confirmed.
   - Add ``version switch`` (with ``--restart`` policy) that:
       * validates version exists → checks instances → flips symlink → restarts
         instances according to policy (placeholder acceptable initially).
       * safety prompt can trigger backups for instances bound to current/target versions.

   - Add ``version uninstall`` (with ``--force``) that:
       * ensures no dependencies → removes directory → updates registry.

5. **Logging & exit codes**

   - For each command, emit structured log steps (install, registry update,
     symlink change, restart) and map failures to ADR-013 codes.

6. **Testing**

   - Provide fixtures for fake install root directories and stubbed npm commands.
   - Cover success, idempotency, and failure paths (npm failure, version in use,
     lock contention).

Version Lifecycle Open Questions
================================

1. How strict should version string validation be (full SemVer vs. basic)? Evaluate
   before implementation to avoid blocking legitimate prereleases.
2. What integrity data should we record (npm shasum vs. tarball digest)? Determine
   during installer implementation. **Status:** npm ``_shasum`` and the tarball
   digest (decoded from ``_integrity``/``dist.integrity``) are now recorded and
   exposed via ``version list --json``.
3. How far should restart automation go in the first iteration (no-op, log-only,
   or restart via systemd provider)?
4. Should ``versions.yml`` track the ``current`` pointer explicitly, or is the
   filesystem symlink sufficient?
