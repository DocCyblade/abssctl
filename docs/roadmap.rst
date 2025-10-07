============================
abssctl Roadmap TODO Tracker
============================

Purpose
=======

Maintain list of outstanding work needed to deliver
abssctl v1.0. Items are grouped by the milestones defined in
``docs/requirements/abssctl-app-specs.txt`` and the project README. Move
completed tasks into ``session-log.txt`` when done.

Planning
========

- No open TODOs for this milestone. (Spec document has already been drafted.)

Pre-Alpha — Repo Bootstrap
==========================

- No open TODOs; scaffolding, packaging metadata, and CI skeletons are in place.

Alpha Builds — Foundations
==========================

- [x] Implement the structured logging subsystem per ADR-014/ADR-028 (human
  logs + ``operations.jsonl``) and integrate it with existing CLI commands.
- [x] Implement global and per-instance locking primitives per ADR-027 and
  ensure mutating commands acquire/release locks safely (with tests).
- [x] Introduce the template rendering engine for systemd and nginx assets
  (e.g., Jinja-based templates under ``src/abssctl/templates/``) per
  ADR-009/ADR-010.
- [x] Extend CI to publish dev builds to Test PyPI when tags matching ``v*.*.*-dev`` land (aligns
  with the "Alpha Builds" release engineering goal).

Beta Releases — Core Features
=============================

- [ ] Implement ``version install``, ``version switch``, and ``version
  uninstall`` flows that manage ``/srv/app/vX.Y.Z``, enforce integrity, update
  ``versions.yml``, and honour safety prompts (ADR-011/ADR-017/ADR-026).
- [ ] Replace the placeholder ``version check-updates`` logic with real npm
  metadata comparisons and JSON output.
- [ ] Build the systemd provider to render/manage per-instance units (create,
  enable/disable, start/stop/restart, logs) per ADR-009/ADR-010.
- [ ] Build the nginx provider to render vhosts, run ``nginx -t``, manage
  sites-available/sites-enabled symlinks, and handle HTTPS defaults/overrides
  with rollback (ADR-010/ADR-031/ADR-032).
- [ ] Implement ``instance create`` with end-to-end provisioning: directory
  layout, ``config.json``, port reservation, systemd unit, nginx vhost, optional
  auto-start, and rollback on failure.
- [ ] Implement the remaining instance subcommands: ``env``,
  ``start|stop|restart|enable|disable|status|logs``, ``set-fqdn``, ``set-port``,
  ``set-version``, ``rename``, and ``delete --purge-data``, incorporating
  ``--dry-run`` and safety prompts.
- [ ] Implement port allocation and collision detection backed by ``ports.yml``,
  following ADR-015 (base port 5000, sequential strategy, locks).
- [ ] Implement TLS subcommands (``tls verify``, ``tls install``,
  ``tls use-system``) including file validation, secure permissions, nginx
  reloads, and Let’s Encrypt detection (ADR-031).
- [ ] Implement backup operations per §5.8 / ADR-012 / ADR-021 / ADR-022,
  including ``backup create``, ``backup list``, ``backup show``,
  ``backup restore``, ``backup verify``, ``backup reconcile``, and
  ``backup prune`` with checksum handling and prompts.
- [ ] Ensure all mutating commands honour ``--dry-run``, ``--yes``, backup
  prompt inventory (ADR-016/ADR-025/ADR-026), and emit consistent exit codes
  (ADR-013).
- [ ] Deliver the initial ``doctor`` command with core probes (environment,
  ports, systemd/nginx status) as defined in ADR-029, returning structured JSON
  and summaries.
- [ ] Flesh out automated tests (unit/integration fakes) to cover the above
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
