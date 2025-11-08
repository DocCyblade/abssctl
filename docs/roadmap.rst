============================
abssctl Roadmap TODO Tracker
============================

Purpose
=======

Maintain list of outstanding work needed to deliver
abssctl v1.0. Items are grouped by the milestones defined in
``docs/requirements/abssctl-app-specs.txt`` and the project README. Move
completed tasks into ``ops/session-log.txt`` when done.

Completed Phases
================

1. Planning — Spec draft and ADR set are stable; no additional scoping work
   remains for pre-v1 milestones.
2. Pre-Alpha — Repository scaffolding, packaging metadata, CI skeletons, and
   automation baselines were delivered.
3. Alpha 3–5 — Core features (structured logging, locking, templating,
   providers, ports registry, lifecycle commands) are implemented and tested.
4. Beta — Backup/TLS/doctor/system-init commands shipped together with
   idempotent test coverage and CLI safety flags.

Recently Completed Milestones
=============================

- Doctor auto-remediation (``doctor --fix``) now delivers real repair planning +
  execution, including dry-run previews, confirmation prompts, and regression
  tests documenting the guardrails.
- The support-bundle command ships with redaction, size limits, secure hand-off
  guidance, and CLI/JSON integration so operators can gather diagnostics on
  demand.
- Exit-code & error mapping was hardened across CLI surfaces (backups, doctor,
  support-bundle), aligning every failure path with ADR-013 semantics and
  updating docs/tests accordingly.

Roadmap to v1.0.0
=================

1. Mutation reliability closure

   a. Target the remaining TLS inspector/validator, doctor engine, and CLI
      survivor clusters with focused coverage; document intentional exclusion
      zones (e.g., direct OS calls) in ``docs/requirements/test-coverage-report.rst``.
   b. Finish timeout mitigation so the scoped mutmut suite can run in CI, and
      constrain mutation testing to the high-impact subsystems listed above.

2. Documentation packaging pipeline

   a. Generate Sphinx man pages in CI, ensure they ship in wheels/sdists, and
      provide ``abssctl docs man install|path`` helpers.
   b. Wire documentation builds into release artifacts (HTML/PDF/man) with
      checksum verification.

3. Shell completion management

   a. Add ``abssctl completion show|install|uninstall`` leveraging Typer’s
      completion hooks for bash/zsh/fish.
   b. Package completion scripts in the distribution and add smoke tests covering
      install/uninstall flows.

4. Admin & developer documentation final pass

   a. Finalise README, CHANGELOG, Admin Guide, Developer Guide, sudoers
      examples, and support matrix automation.
   b. Publish the release-notes template and update docs/requirements to reflect
      the frozen v1 feature set.
   c. Maintain the new Node compatibility source of truth (``docs/requirements/node-compat.yaml`` + rendered RST) via ``tools/list-sync-versions.py`` so operators always see the latest Actual/Node matrix.

5. Manual Integration Test Protocol (MITP) publication

   a. Publish MITP checklists + scripts, covering install, upgrade, backup,
      TLS, doctor, and support-bundle scenarios.
   b. Integrate critical MITP smoke tests into CI (or a nightly job) with
      documented pass/fail gating.

6. CI/CD release automation

   a. Extend CI to run packaging smoke tests, build support bundles, and stage
      release artifacts (wheel, sdist, manpage tarball, completion scripts).
   b. Add automation to push signed artifacts to staging buckets and validate
      installation on clean environments.

7. System validation & MITP execution

    a. Run the MITP on current TurnKey Linux Node.js appliances plus the ten
       supported back versions, updating the support matrix.
    b. Capture structured logs/support bundles for each run to aid future
       troubleshooting.

8. Release-candidate burn-in & rollback drills

    a. Perform extended burn-in on RC builds covering upgrade/rollback,
       backups, TLS, doctor, and support-bundle flows.
    b. Document gating criteria and residual risks, feeding results back into
       docs and CI dashboards.

9. GA launch & communications

    a. Final documentation sign-off, PyPI release from ``main``, tagged GitHub
       release (with artifacts), and docs site refresh.
    b. Execute the post-release communication plan: changelog highlights,
       support announcements, and next-maintenance schedule.
