============================
abssctl Roadmap TODO Tracker
============================

Purpose
=======

Outstanding work for abssctl v1.0, grouped by the milestones in
``docs/requirements/abssctl-app-specs.txt`` section 13. The current slice
is ``docs/PATH_FORWARD.md``. This file is the longer milestone list.

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
- Shell completion: ``abssctl completion show|install|uninstall`` for bash, zsh,
  fish, and PowerShell. Install never edits shell rc files.
- MITP checklist published at ``docs/source/guides/mitp.rst``.
- Bounded mutmut CI (``.github/workflows/mutation.yml``) mutates
  ``src/abssctl/exit_codes.py`` only, 20 minute cap. ``make mutmut-full`` stays
  local.
- Node compatibility source of truth: ``docs/requirements/node-compat.yaml``
  and the shipped copy, rendered by ``tools/list-sync-versions.py``. Preferred
  runtime for Actual 25.11+ and 26.x is Node 22.23.3.
- TestPyPI ``0.1.5a4``. Production PyPI remains ``0.1.3a1``.

Where the spec milestones stand
===============================

Section 13 of ``docs/requirements/abssctl-app-specs.txt``:

- Planning, Pre-Alpha, and Alpha are done.
- Beta core features are in the tree. The open Beta gap is version install:
  the CLI's npm prefix is not the tree ``tmp-personal-server/000-manual-install.sh``
  writes under ``/srv/app/v<version>`` (``package.json`` and
  ``build/bin/actual-server.js`` at the version root).
- RC quality work (support bundle, man pages, completion, MITP checklist) is
  in. The first appliance MITP, on ``nodeapp00`` for Actual 26.10.0, stopped
  at version install. Node 22.23.3 and ``system init`` succeeded.
- The Release milestone (burn-in on the current Actual release plus the ten
  prior versions, then GA) comes after that single MITP.

Near-term plan
==============

These two items match ``docs/PATH_FORWARD.md`` tracks V and M. One chat per
item.

1. Version install matches ``000-manual-install.sh``

   a. Declare ``packaging`` in ``pyproject.toml``. A clean ``0.1.5a4`` install
      exits on ``from packaging.version import ...``.
   b. Install by ``npm pack``, extract into ``/srv/app/v<version>``, then
      ``npm install --omit=dev --no-save`` in that directory, so
      ``package.json`` and ``build/bin/actual-server.js`` sit at the version
      root. Keep the provider, registry, and command tree.
   c. Cover that layout with tests. ``make quick-tests`` stays green.
   d. Leave production PyPI and the real server on the manual script.

2. One MITP on ``nodeapp00`` for Actual 26.10.0

   a. Restore snapshot ``clean-slate``. Install the fixed build, ``system init``,
      Node 22.23.3, ``version install 26.10.0``, one instance, systemd, and nginx.
   b. Record the result in the node-compat matrix.

Later
=====

3. Documentation release artifacts

   a. ``abssctl.1`` is built and shipped. HTML/PDF release artifacts are still
      open, with checksum verification.

4. Admin and developer documentation final pass

   a. README and ADR-005 describe beta and Node 22. Still open: CHANGELOG final
      pass, Admin Guide, Developer Guide, sudoers examples, and the frozen v1
      feature set in the requirements docs.

5. CI/CD release automation

   a. Packaging smoke tests, support-bundle builds, and staged artifacts
      (wheel, sdist, manpage tarball, completion scripts).
   b. Signed staging uploads and a clean-environment install check. GitHub
      tag publish to PyPI is the spec's RC publish hook; it is not wired to
      production PyPI yet.

6. Mutation survivor hunting

   a. Remaining TLS inspector/validator, doctor engine, and CLI survivor
      clusters, with exclusion zones recorded in
      ``docs/requirements/test-coverage-report.rst``. This stays off the
      default next step.

7. System validation across the support window

   a. MITP on the current Actual release plus the ten prior versions, updating
      the support matrix.
   b. Structured logs and support bundles for each run.

8. Release-candidate burn-in and rollback drills

   a. Extended burn-in on RC builds: upgrade/rollback, backups, TLS, doctor,
      and support-bundle.
   b. Gating criteria and residual risks written back into docs and CI.

9. GA launch

   a. Documentation sign-off, PyPI release from ``main``, tagged GitHub
      release, and docs site refresh.
   b. Changelog highlights, support announcements, and the next maintenance
      schedule.
