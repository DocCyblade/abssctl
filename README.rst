======================================
abssctl — Actual Sync Server Admin CLI
======================================

.. image:: https://img.shields.io/badge/status-alpha-blue
   :alt: Project maturity badge showing Alpha status

``abssctl`` is a batteries-included command line tool that installs and manages
multiple Actual Budget Sync Server instances on the TurnKey Linux Node.js
appliance. The CLI owns the full lifecycle today: provisioning new instances,
performing upgrades or rollbacks, managing nginx and systemd integrations, and
producing backup archives for operators. Alpha milestone efforts continue to
iterate on the operational polish before Beta health checks and support bundles
arrive.

Project Facts
=============

- **Project name:** Actual Budget Multi-Instance Sync Server Admin CLI.
- **CLI executable:** ``abssctl`` (Actual Budget Sync Server ConTroL).

The project is currently in the **Alpha (core features)** phase. The repository
builds on the bootstrap work from Pre-Alpha and now includes structured logging,
global/per-instance locking, templated systemd/nginx providers, a ports
registry, full instance lifecycle commands, and end-to-end version management.

Key Objectives
==============

- Provide a predictable Python package that can be installed with ``pip`` or
  ``pipx`` and exposes an ``abssctl`` executable.
- Establish documentation sources in reStructuredText with Sphinx as the build
  system (see ``docs/source``).
- Enforce quality gates via linting, type checking, and tests in continuous
  integration.
- Capture all architectural decisions in ``docs/adrs`` and maintain living
  requirements under ``docs/requirements``.

Quick Start (Alpha Foundations)
===============================

.. note::
   The CLI is still stabilising APIs during Alpha. All lifecycle commands are
   available today (version install/switch/uninstall, instance
   create/enable/start/stop/restart/delete, etc.), but production deployments
   should continue to treat this release as a preview until the Beta hardening
   work (doctor/support-bundle/TLS restore flows) lands.

1. Create a Python 3.11 virtual environment stored in ``.venv`` with a prompt label ``dev`` and activate it::

      python3.11 -m venv .venv --prompt dev
      source .venv/bin/activate

2. Install the package in editable mode together with developer dependencies::

      pip install -e .[dev]

   This registers ``abssctl`` with your virtualenv so commands and tests import
   without needing to tweak ``PYTHONPATH``.

3. Run the basic quality checks::

      ruff check src tests
      mypy src
      pytest

   Tip: ``make quick-tests`` runs the trio above via the managed developer
   virtualenv. Use ``make docs`` to rebuild Sphinx HTML and ``make dist`` for
   the full lint/type/test/build pipeline.

4. Exercise the CLI::

      abssctl --help
      abssctl --version
      abssctl config show
      abssctl version list --json
      abssctl instance list --json
      abssctl ports list --json
      abssctl instance create demo --no-start --port 6000

Repository Layout
=================

- ``src/abssctl`` — Python package containing the Typer-based CLI scaffold.
- ``tests`` — Pytest suite covering CLI entry points and future modules.
- ``docs`` — Requirements, ADRs, Sphinx sources, and generated support matrix.
- ``tools`` — Utility scripts used during development (e.g., support matrix generator).

Configuration Basics
====================

The configuration loader follows ADR-023 precedence: built-in defaults,
``/etc/abssctl/config.yml``, environment variables prefixed with
``ABSSCTL_``, and finally CLI overrides such as ``--config-file``. Use
``abssctl config show`` (or ``--json``) to inspect the merged values and
confirm environment overrides are applied as expected.

Lifecycle commands are fully wired: ``abssctl version install|switch|uninstall``
manage ``/srv/app`` contents and record metadata/integrity, while
``abssctl instance create`` provisions directory scaffolding, reserves ports,
renders templates, and rolls back on failure. Instance mutators (enable/disable,
start/stop/restart, set-fqdn, set-port, set-version, rename, delete) update the
registry, invoke systemd/nginx helpers, and support ``--dry-run`` plus safety
prompts. Use ``--remote`` with ``version list`` to pull published versions from
npm when the CLI is available (falls back gracefully if ``npm`` is missing). All
commands accept ``--config-file`` so you can point at alternate configuration
sources when testing or operating multiple environments. The registry records
npm integrity metadata (``shasum`` plus tarball digest) for each install, and
``abssctl version list --json`` exposes that block so offline operators can
verify artifacts.

CLI Conventions
===============

- ``--dry-run`` is available on every mutating command; it prints the planned
  steps and records skipped actions in ``operations.jsonl`` without changing the
  system.
- Safety prompts share ``--no-backup`` (skip the recommendation),
  ``--backup-message`` (annotate the generated archive), and ``--yes``
  (auto-confirm prompts for non-interactive workflows).
- Exit codes follow ADR-013 across the tool: ``0`` success, ``2`` validation or
  user input issues, ``3`` environment errors (permissions, missing files,
  insufficient disk), and ``4`` provider/system failures (systemd/nginx/TLS).

Backups
=======

- ``abssctl backup create <instance>`` assembles instance data, rendered
  systemd/nginx assets, and registry metadata into a timestamped archive under
  ``/srv/backups/<instance>/`` (override via ``--out-dir``). Archives include a
  `.sha256` companion file and an entry in ``backups.json`` capturing checksum,
  compression algorithm, labels, and user-supplied message. ``--message``
  annotates the entry, ``--label`` (comma-separated) adds search-friendly tags,
  ``--dry-run`` previews the capture plan, and ``--json`` emits a
  machine-readable payload for tooling.
- ``abssctl backup list`` / ``abssctl backup show <id>`` read ``backups.json`` so
  operators can browse recent backups or drill into a specific archive via JSON.
- ``abssctl backup verify`` recomputes SHA-256 digests to highlight missing or
  corrupt archives.
- ``abssctl backup restore <id>`` verifies the archive checksum, extracts the
  payload, swaps the instance data directory, and rehydrates systemd/nginx
  assets (restarting services when they were previously running). ``--dry-run``
  previews the plan, and ``--dest`` supports staging restores.
- ``abssctl backup reconcile`` compares the backup index with on-disk archives,
  reporting missing entries, mismatched statuses, and orphaned files. Use
  ``--apply`` to tag missing entries directly in ``backups.json``.
- ``abssctl backup prune`` removes old backups using ``--keep`` / ``--older-than``
  policies (with ``--dry-run`` support) and updates the registry accordingly.
- Version lifecycle commands and ``instance delete`` honour safety prompts by
  creating real backups when accepted (``--yes`` auto-confirms, ``--no-backup``
  bypasses the safeguard). Install/switch/uninstall label backups with their
  preflight intent so operators can trace why an archive exists.

Roadmap & Specifications
========================

- Requirements & project plan: ``docs/requirements/abssctl-app-specs.txt``
- Milestone roadmap tracker: ``docs/roadmap.rst``
- Architecture Decision Records: ``docs/adrs``
- Support matrix source: ``docs/support/actual-support-matrix.yml``

Community & Licensing
=====================

The project is released under the MIT License (``LICENSE``). Contributions are
welcome—please review the developer guide skeleton under ``docs/source`` for the
expected workflow and coding standards as they evolve.

Branch Strategy
===============

- ``main`` — production-ready releases tagged for PyPI.
- ``dev`` — integration branch for upcoming development builds.
- ``dev-<label>`` — milestone integration branches (``dev-alphaN``, ``dev-betaN``,
  ``dev-1.2.0a1``); the current focus is ``dev-alpha5`` while we prepare the Beta
  health-check and restore work.
- Short-lived feature branches support focused working sessions.
- Release preparation uses ``release/<version>`` branches before tagging.
- Urgent fixes branch from ``main`` as ``hotfix/<version>`` (code) or
  ``docfix/<version>`` (documentation). Refer to ADR-034 for the full workflow.

Roadmap Snapshot
================

- **Pre-Alpha — Repo Bootstrap (complete):** scaffold layout, ``pyproject.toml``, docs
  skeleton, CI with lint/test.
- **Alpha Builds — Foundations:** CLI skeleton beyond placeholders, config
  loader, logging, state/lock primitives, template engine, read-only commands,
  JSON output plumbing. Publish dev builds to PyPI from tags on ``dev``.
- **Alpha Core Features (current):** Version install/switch/uninstall, ports
  registry, systemd/nginx providers, instance lifecycle subcommands, structured
  rollback handling, and expanded test coverage.
- **Beta Releases — Core Features:** TLS tooling, backup restore/reconcile, and
  the doctor CLI harness (structured JSON output, filters, exit-code mapping),
  plus support bundle groundwork. All updates become non-destructive or ship
  with migration hooks.
- **Release Candidate — Quality & Docs:** Support bundle, robust errors, man
  pages & completion, full docs & examples, CI integration tests on TurnKey
  Linux VMs. Automate PyPI release from GitHub actions.
- **Release — v1.0.0:** Burn-in testing across supported Actual versions,
  release on a green pipeline with documentation sign-off.
