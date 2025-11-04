====================
Test Coverage Report
====================

Command
=======

The following command was executed on 2025-11-04 to collect statement/branch
coverage using the existing pytest suite::

   .venv/bin/python -m pytest --cov=src/abssctl --cov-report=term-missing

Summary
=======

* Overall coverage: **77 %** (5,930 statements, 1,087 misses, 1,854 branches).
* Modules >= 85 %: ``doctor.engine`` (95 %), ``locking`` (96 %), ``providers.nginx`` (90 %),
  ``doctor.models`` (89 %), ``backups`` (86 %), ``tls`` (86 %), ``state.registry`` (86 %).
* Modules below target:

  - ``abssctl.cli`` – 74 %: many command handlers and error paths remain untested,
    including version management flows, failure branches, and the support bundle
    placeholder.
  - ``bootstrap`` helpers – 73 %–87 %: directory/service-account edge cases are
    partially covered but scenarios such as permission failures and discovery
    error handling still lack tests.
  - ``logging`` – 80 %: rotation and JSONL failure paths not exercised.
  - ``ports`` – 82 %: error handling for port allocation conflicts needs coverage.
  - ``providers.version_provider`` – 39 %: the npm interaction layer is largely
    untested; only the happy path is executed today.

Risks and Follow-ups
====================

* Version management (5.4 requirements) is still backed by minimal tests;
  regression risk remains high until we add mocks for npm responses, failure
  modes, and cache invalidation.
* CLI error handling (prompts, safety prompts bypasses, support-bundle command)
  needs dedicated regression tests before beta freeze.
* Bootstrap modules require simulations of permission-denied and discovery
  failure scenarios to ensure we do not regress on constrained hosts.
* Logging and ports modules should receive targeted tests to confirm resilience
  when filesystem writes fail or the port registry is corrupted.

Mutation Testing
================

Mutation tests have not been executed yet. Suggested tooling: ``mutmut`` against
``abssctl.cli`` and ``abssctl.providers.version_provider`` once the above
coverage improvements land. Track runtime and actionable mutations before
making this part of CI.

Next Steps
==========

1. Backfill targeted tests for ``providers.version_provider`` (npm failures, cache
   refresh) and additional CLI command failure branches (e.g., ``switch-version``,
   ``uninstall-version``).
2. Add failure-mode tests for bootstrap (directory permissions, discovery
   reconciliation) and ports/logging modules.
3. Pilot mutation testing with ``mutmut``; record actionable mutation score and
   integrate into extended test suite if runtime is acceptable.
