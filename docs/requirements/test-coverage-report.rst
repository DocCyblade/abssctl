====================
Test Coverage Report
====================

Command
=======

The following command was executed on 2025-11-03 to collect statement/branch
coverage using the existing pytest suite::

   python -m pytest --cov=src/abssctl --cov-report=term-missing

Summary
=======

* Overall coverage: **78 %** (5,937 statements, 1,034 misses, 1,856 branches).
* Modules >= 85 %: ``doctor.engine`` (95 %), ``locking`` (96 %), ``providers.version_installer`` (89 %),
  ``doctor.models`` (89 %), ``providers.nginx`` (90 %), ``backups`` (86 %), ``tls`` (86 %),
  ``state.registry`` (86 %), ``providers.version_provider`` (85 %).
* Modules below target:

  - ``abssctl.cli`` – 75 %: version management paths are now exercised, but support-bundle,
    bootstrap, and broader error-reporting flows still lack coverage.
  - ``bootstrap`` helpers – 73 %–87 %: directory/service-account edge cases are partially
    covered but scenarios such as permission failures and discovery error handling remain.
  - ``logging`` – 80 %: rotation and JSONL failure paths are still untested.
  - ``ports`` – 82 %: error handling for port allocation conflicts needs coverage.

Risks and Follow-ups
====================

* Support-bundle and bootstrap error handling still lack regression tests; focus CLI
  expansion on those command paths next.
* Bootstrap modules require simulations of permission-denied and discovery
  failure scenarios to ensure we do not regress on constrained hosts.
* Logging and ports modules should receive targeted tests to confirm resilience
  when filesystem writes fail or the port registry is corrupted.

Mutation Testing
================

Ongoing mutation testing is now scoped to the highest-risk subsystems only:

1. ``abssctl.cli`` (backup helpers, doctor/doctor CLI payloads, support-bundle once added)
2. ``abssctl.doctor.engine`` / ``abssctl.doctor.probes`` (probe orchestration, context assembly)
3. ``abssctl.tls`` (inspector/validator)

These modules are exercised with ``mutmut`` using the targeted configuration recorded
in ``ops/mutation-results-raw.txt``. Mutation testing is **not** required for other
modules; rely on statement/branch coverage and focused unit tests instead. Before CI
integration, ensure the scoped suite runs under the timeout controls introduced via the
``mutation_timeout`` marker.

Next Steps
==========

1. Expand CLI coverage to include support-bundle flows, bootstrap error paths, and
   multi-error reporting.
2. Add failure-mode tests for bootstrap (directory permissions, discovery reconciliation)
   plus targeted scenarios for logging/ports resilience.
3. Pilot mutation testing with ``mutmut`` once the above additions land; record actionable
   mutation score and evaluate CI integration.

Beta2-1 Coverage Plan
=====================

Coverage Gap Inventory
----------------------

*(Historical notes retained for reference; all items addressed as of 2025-11-03.)*

- ``providers.version_provider`` lacks coverage for skip/cache environment behaviour, npm
  failures (missing binary, non-zero exit, malformed JSON), and cache refresh writes.
- ``abssctl.providers.version_installer`` tests cover happy path/failure cleanup but miss
  validation errors (blank version, existing directories), missing package directories, and
  integrity metadata parsing.
- CLI ``version install`` only exercises successful flows; duplicate installs, installer
  exceptions, and dry-run/set-current interactions remain unverified.
- CLI ``version switch`` lacks guards coverage for invalid restart modes, unregistered
  versions, missing install directories, and systemd failure propagation.
- CLI ``version uninstall`` is missing cases for unknown versions and verifying emitted error
  details when safety checks trigger.
- CLI update/list commands do not yet exercise the “no updates” path or graceful handling of
  remote version lookup failures.

Proposed Test Additions
-----------------------

1. **B2-1 – `providers.version_provider` resilience** *(Completed 2025-11-03)*
   - Assert ``ABSSCTL_SKIP_NPM=1`` short-circuits to ``[]`` without touching disk.
   - Exercise cache preference order (explicit cache path vs ``ABSSCTL_VERSIONS_CACHE``) and ensure
     malformed/missing cache payloads fall back cleanly.
   - Simulate ``npm`` missing/non-zero exit/malformed JSON to confirm the provider returns ``[]`` and
     does not write cache files.
   - Cover ``refresh_cache`` success path and cache write failure tolerance (mocking ``Path.write_text``).
2. **B2-2 – `providers.version_installer` validation & integrity** *(Completed 2025-11-03)*
   - Reject blank/whitespace version strings and existing target directories with ``VersionInstallError``.
   - Surface ``VersionInstallError`` when npm succeeds but the package directory is absent.
   - Validate dry-run metadata includes ``npm_args`` and that integrity parsing extracts npm/tarball
     details (including malformed integrity strings returning ``{}``).
3. **B2-3 – `version install` CLI error handling** *(Completed 2025-11-03)*
   - Attempt to install an already-registered version (expect rc=2 and no filesystem touch).
   - Bubble up ``VersionInstallError`` from the installer (rc=4, logged error step).
   - ``--dry-run --set-current`` should report deferred switch without altering the symlink.
   - ``--no-backup`` path records ``backup.skip`` and avoids prompting.
4. **B2-4 – `version switch` CLI guard rails** *(Completed 2025-11-03)*
   - Invalid ``--restart`` value exits with rc=2 and prints the validation error.
   - Unregistered target version triggers rc=2 via ``_switch_version``.
   - Missing install directory triggers rc=3 and surfaces the path in the message.
   - Simulate ``SystemdError`` during restart to ensure ``_provider_error`` converts it to rc=4.
5. **B2-5 – `version uninstall` CLI safety checks** *(Completed 2025-11-03)*
   - Unknown version (absent from registry) exits with rc=2 before filesystem mutation.
   - Confirm error messaging for “in use” guard includes sorted instance list.
   - Path-missing uninstall still succeeds (no ``filesystem.remove`` step) while registry entry drops.
6. **B2-6 – `version check-updates` CLI coverage** *(Completed 2025-11-03)*
   - Scenario where remote versions are identical to installed should emit the “up to date” message/JSON.
   - Remote lookup returning ``[]`` (without remote failure) should yield the “unable to fetch” status.
7. **B2-7 – `version list` CLI fallback paths** *(Completed 2025-11-03)*
   - Remote flag with provider raising ``FileNotFoundError`` (missing npm) should fall back to local entries
     and still exit 0.
   - Malformed cache JSON should degrade gracefully and continue listing registry versions.
