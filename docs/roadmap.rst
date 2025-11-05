============================
abssctl Roadmap TODO Tracker
============================

Purpose
=======

Maintain list of outstanding work needed to deliver
abssctl v1.0. Items are grouped by the milestones defined in
``docs/requirements/abssctl-app-specs.txt`` and the project README. Move
completed tasks into ``ops/session-log.txt`` when done.

Planning
========

- No open TODOs for this milestone. (Spec document has already been drafted.)

Pre-Alpha — Repo Bootstrap
==========================

- No open TODOs; scaffolding, packaging metadata, and CI skeletons are in place.

Alpha 3 — Foundations
=====================

- No open TODOs; structured logging, locking, templating, and trusted dev publishing
  capabilities are complete for this phase.

Alpha 4 — Core Features 1
=========================

- No open TODOs; version lifecycle commands, registry helpers, and update checks
  shipped as planned.

Alpha 5 — Core Features 2
=========================

- No open TODOs; systemd/nginx providers, instance lifecycle commands, and ports
  registry are fully delivered.

Beta — Basic Functions
======================

- [x] Implement port allocation and collision detection backed by ``ports.yml``,
  following ADR-015 (base port 5000, sequential strategy, locks).
- [x] Implement TLS subcommands (``tls verify``, ``tls install``,
  ``tls use-system``) including file validation, secure permissions, nginx
  reloads, and Let’s Encrypt detection (ADR-031).
- [x] Implement backup operations per §5.8 / ADR-012 / ADR-021 / ADR-022,
  including ``backup restore`` and ``backup reconcile``; ``backup create`` /
  ``list`` /
  ``show`` /
  ``verify`` /
  ``prune`` are in place with checksum handling and prompts.
- [x] Ensure all mutating commands honour ``--dry-run``, ``--yes``, backup
  prompt inventory (ADR-016/ADR-025/ADR-026), and emit consistent exit codes
  (ADR-013).
- [x] Deliver the ``doctor`` command with the ADR-029 probe catalogue (env,
  config, state, filesystem, ports, systemd, nginx, tls, app, disk), JSON
  output, and state reconciliation guidance that recommends
  ``abssctl system init --rebuild-state`` when mismatches are detected.
- [x] Ship the ``system init`` bootstrap command (interactive wizard plus
  unattended flags, discovery, and ``--rebuild-state`` support) so new or
  existing hosts can be prepared consistently.
- [x] Flesh out automated tests (unit/integration fakes) to cover the above
  Beta features and guard idempotency.

Release Candidate — Quality & Docs
==================================

- [ ] Extend ``doctor`` with ``--fix`` capabilities for safe migrations (state
  dir moves, permission repair, stale lock cleanup) per ADR-029/ADR-024.
- [ ] Implement the ``support-bundle`` command that collects configs, registry
  snapshots, logs, and probe output with redaction per ADR-012/ADR-014/ADR-028.
- [ ] Harden error handling and map failures to the formal exit-code taxonomy
  (ADR-013), including rich user messaging.
- [ ] Generate Sphinx man pages in CI, package them with the wheel/sdist, and
  implement ``abssctl docs man install``/``path`` commands per ADR-002/ADR-019.
- [ ] Implement shell completion management (``abssctl completion
  show|install|uninstall``) leveraging Typer’s completion support per ADR-020.
- [ ] Complete documentation sets: README, CHANGELOG, Admin Guide, Developer
  Guide, sudoers examples, and support matrix automation per §7 of the spec.
- [ ] Publish Manual Integration Test Protocol assets (scripts/checklists) and
  wire them into CI where feasible (ADR-030).
- [ ] Extend CI/CD to run packaging smoke tests, build support bundles, and
  stage release artifacts (wheels, manpage tarballs, completion scripts).

Release — v1.0.0
================

- [ ] Execute the MITP on a fresh TurnKey Linux Node.js v18 appliance across the
  current + 10 prior Actual releases, updating the support matrix.
- [ ] Perform burn-in testing for the release candidate builds, verifying
  upgrade/rollback, backups, TLS, and doctor/support-bundle across scenarios.
- [ ] Finalise documentation sign-off and publish GA artifacts (PyPI release
  from ``main``, tagged GitHub release with attachments, updated docs site).
- [ ] Share a post-release checklist (communication, changelog highlights,
  next-maintenance window) for operational hand-off.

Optional / Future Enhancements
==============================

- [ ] Explore automatic Let’s Encrypt certificate provisioning beyond v1 scope
  for future consideration.
- [ ] Investigate container-based distribution or alternative reverse proxy
  support after v1.0.
