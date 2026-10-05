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
- Beta core features are in the tree. ``version install`` follows
  ``tmp-personal-server/000-manual-install.sh``: ``npm pack``, extract into
  ``/srv/app/v<version>``, then ``npm install --omit=dev --no-save``, so
  ``package.json`` and ``build/bin/actual-server.js`` sit at the version root.
  The appliance run that proves that tree is track M.
- RC quality work (support bundle, man pages, completion, MITP checklist) is
  in. One Actual 26.10.0 instance (``mitp``, port 6000) is running on
  ``nodeapp00`` through systemd and nginx on Node 22.23.3. The unit directory,
  instance ownership, and nginx include were set on the host; upgrade, backup,
  TLS verify, doctor, support bundle, and cleanup were not run.
- The Release milestone (burn-in on the current Actual release plus the ten
  prior versions, then GA) comes after that single MITP.

Near-term plan
==============

These items match ``docs/PATH_FORWARD.md``. One chat per item. The docs
reading, the version-install change, and one MITP on ``nodeapp00`` are done.

1. Check the published docs against the code and tests — read 2026-10-05

   ``docs/reviews/2026-10-05-docs-claims.md`` records each ready claim from
   that reading. Track V later made ``version install`` match the manual
   script. Overview and quickstart still describe doctor, restore, TLS, and
   support bundles as future work; those commands are implemented and tested.
   Those pages were left as published. That reading did not rewrite
   release-position text.

2. Version install matches ``000-manual-install.sh`` — done

   a. ``packaging`` is declared in ``pyproject.toml``.
   b. Install by ``npm pack``, extract into ``/srv/app/v<version>``, then
      ``npm install --omit=dev --no-save`` in that directory, so
      ``package.json`` and ``build/bin/actual-server.js`` sit at the version
      root. The provider, registry, and command tree stay as they are.
   c. Tests cover that layout. ``make quick-tests`` stays green.
   d. Production PyPI and the real server stay on the manual script. No
      TestPyPI upload in this slice.

3. One MITP on ``nodeapp00`` for Actual 26.10.0 — done

   a. Restored snapshot ``clean-slate``. Installed the fixed local wheel,
      ``system init``, Node 22.23.3, ``version install 26.10.0``, instance
      ``mitp`` on port 6000, systemd, and nginx. The Actual HTML is HTTP 200.
   b. Recorded in the node-compat matrix (status ``pass``, tested 2026-10-05).

Later
=====

4. Documentation release artifacts

   a. ``abssctl.1`` is built and shipped. HTML/PDF release artifacts are still
      open, with checksum verification.

5. Admin and developer documentation final pass

   a. README and ADR-005 describe beta and Node 22. Still open: CHANGELOG final
      pass, Admin Guide, Developer Guide, sudoers examples, and the frozen v1
      feature set in the requirements docs.

6. CI/CD release automation

   a. Packaging smoke tests, support-bundle builds, and staged artifacts
      (wheel, sdist, manpage tarball, completion scripts).
   b. Signed staging uploads and a clean-environment install check. GitHub
      tag publish to PyPI is the spec's RC publish hook; it is not wired to
      production PyPI yet.

7. Mutation survivor hunting

   a. Remaining TLS inspector/validator, doctor engine, and CLI survivor
      clusters, with exclusion zones recorded in
      ``docs/requirements/test-coverage-report.rst``. This stays off the
      default next step.

8. System validation across the support window

   a. Before that matrix, fold the ``nodeapp00`` host adjustments into the CLI:
      systemd units in ``/etc/systemd/system``, instance directories owned by
      ``actual-sync``, and nginx vhosts linked from ``/etc/nginx/sites-enabled``.
   b. MITP on the current Actual release plus the ten prior versions, updating
      the support matrix.
   c. Structured logs and support bundles for each run.

9. Release-candidate burn-in and rollback drills

   a. Extended burn-in on RC builds: upgrade/rollback, backups, TLS, doctor,
      and support-bundle.
   b. Gating criteria and residual risks written back into docs and CI.

10. GA launch

   a. Documentation sign-off, PyPI release from ``main``, tagged GitHub
      release, and docs site refresh.
   b. Changelog highlights, support announcements, and the next maintenance
      schedule.
