================================
Mutating Command Test Strategy
================================

Test Strategy Status
====================

- **Owner:** QA/Engineering (session 2025-10-08)
- **Scope:** All CLI commands that mutate filesystem, registry, or system services.
- **Milestones:** Alpha foundations (current), Beta core features (target), RC hardening.

Why This Strategy Exists
========================

Read-only commands already have good coverage via CLI integration tests (see
``tests/test_cli.py``). As the CLI begins to manipulate systemd, nginx, the
registry, and on-disk application data, we need a deliberate strategy to keep
tests reliable, fast, and representative of real TurnKey Linux deployments.

Current Coverage Snapshot (Alpha Foundations)
=============================================

- CLI tests patch provider methods to focus on registry and logging side effects.
- Template rendering, locking primitives, and providers have unit tests exercising
  happy paths and error handling at a basic level.
- There is no simulation of systemctl/nginx binaries, no rollback verification,
  and no tests for dry-run/confirmation workflows (not yet implemented).

Testing Goals for Beta
======================

1. **Confidence** — Every mutating command should fail-fast in tests if it leaves
   the registry, runtime directory, or templates in an inconsistent state.
2. **Isolation** — Tests must run without root privileges or real systemd/nginx,
   relying instead on fakes and temporary directories.
3. **Determinism** — No external network or clock dependence; operations (e.g.,
   port allocation) should use seeded inputs.
4. **Coverage** — Exercise success paths, dry-run flows, and representative
   failure cases (validation errors, subprocess failures, lock timeouts).

Test Layers & Techniques
========================

Unit Tests
----------

- Fake ``subprocess.run`` to capture systemd/nginx invocations and assert
  specific argument sequences, environment variables, and error handling.
- Verify template context builders generate expected dictionaries for varying
  registry inputs (ports, TLS selections, version bindings).
- Validate locking behaviour around the new dry-run/non-interactive options and
  confirm metadata logging (e.g., ``lock_wait_ms``) is present.

Functional CLI Tests
--------------------

- Use temporary directories to emulate ``install_root``, ``runtime_dir``,
  ``state_dir``, and provider-specific paths. After each command, assert the
  filesystem contents match fixtures (golden files).
- Capture structured log output (``operations.jsonl``) to ensure commands record
  change counts, warnings, exit-code mappings, and rollback steps.
- Introduce helper fixtures that install fake ``systemctl``/``nginx`` scripts
  into ``PATH`` so CLI tests can exercise end-to-end flows without the real
  binaries (per ADR-009/ADR-010 expectations).

Rollback & Failure Scenarios
----------------------------

- Ensure ``instance create`` cleans up rendered artifacts and registry entries
  when validation (e.g., ``nginx -t``) fails.
- Simulate ``systemctl`` failures (non-zero exit) and assert commands emit
  helpful errors, rollback partial work, and exit with code 4 (ADR-013).
- Test lock contention by pre-acquiring locks and ensuring commands respect
  timeouts and logging.

Dry-Run & Confirmation Flows
----------------------------

- Once ``--dry-run`` and safety prompts land, add tests that assert no filesystem
  changes occur, while logs enumerate the planned actions.
- Cover both interactive (prompt) and ``--yes`` non-interactive modes so CI
  scripts can run confidently.

Tooling & Fixtures
==================

- Create reusable fixtures in ``tests/conftest.py`` for temporary directories,
  fake binaries, and registry bootstrap data.
- Add helpers to compare rendered templates against expected strings (tolerating
  whitespace in comments) to keep tests readable.
- Consider ``pytest`` markers (e.g., ``@pytest.mark.integration``) for heavier
  CLI runs so quick checks can skip them when needed.

CI Integration
==============

- Extend ``make quick-tests``/``make dist`` to ensure new tests run in GitHub
  Actions using the fake systemctl/nginx harness.
- Capture artifacts (logs, rendered templates) on CI failure to speed up
  debugging.

Testing Open Questions
======================

- How far should we simulate TurnKey-specific paths (e.g., real ``/etc/ssl``)
  versus using fixtures? Determine during Beta implementation.
- Do we require smoke tests on an actual TurnKey VM in CI (per ADR-030), or can
  that remain a release-candidate manual step? Needs an ADR update if automated.

Next Actions
============

1. Implement fake binary fixtures and retrofit existing CLI tests to use them.
2. Add golden-template assertions for the current ``instance create`` scaffolding.
3. Prepare regression tests for the forthcoming version install/switch commands.
4. Document any new fixtures/helpers in ``docs/source/guides/developer-guide.rst``.
