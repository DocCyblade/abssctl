=====================================
Version Lifecycle Implementation Plan
=====================================

Plan Status
===========

- **Owner:** Alpha Foundations team (sessions 2025-10-08 → 2025-10-21)
- **Milestone:** Alpha 4 / Alpha 5 bridge (Delivered)
- **Related ADRs:** ADR-009, ADR-011, ADR-013, ADR-015, ADR-017, ADR-026

Delivered Outcomes
==================

- ``version install``/``switch``/``uninstall`` are wired with lock acquisition,
  safety prompts, structured logging, and integrity validation.
- ``StateRegistry`` now persists normalised entries via helper methods and
  captures npm integrity metadata for every install (shasum + tarball digest).
- ``LockManager`` exposes ``mutate_versions`` to serialise concurrent lifecycle
  operations.
- ``VersionInstaller`` wraps npm interactions, supports dry-run behaviour, and
  records installation metadata with retries/cleanup on failure.
- CLI tests exercise install/switch/uninstall success paths, backup prompts,
  symlink updates, registry mutations, and failure handling.

Beta Follow-Ups (Versions)
==========================

1. **Rolling restart automation**

   - Refine the ``--restart`` policies to coordinate with instance providers
     once doctor/health checks can confirm readiness.

2. **Cache management**

   - Consider an optional garbage-collection routine for stale npm caches or
     temporary install directories beyond what the installer already cleans.

3. **Restore & reconciliation**

   - Integrate version metadata with upcoming backup restore workflows to
     detect mismatches between the registry and filesystem.

Open Questions (Version Lifecycle)
==================================

1. Should we expose additional version metadata (e.g., release channel,
   changelog URL) in ``versions.yml`` for future doctor/support bundle output?
2. What level of automation is expected for downgrades during restore flows,
   and how should we surface warnings when instances reference versions that
   no longer exist on disk?
