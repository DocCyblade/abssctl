======================================
abssctl — Actual Sync Server Admin CLI
======================================

.. image:: https://img.shields.io/badge/status-alpha-blue
   :alt: Project maturity badge showing Alpha status

``abssctl`` is a planned, batteries-included command line tool that installs and
manages multiple Actual Budget Sync Server instances on the TurnKey Linux
Node.js appliance. The CLI will own the full lifecycle: provisioning new
instances, performing upgrades or rollbacks, managing nginx and systemd
integrations, and producing support bundles for operators.

Project Facts
=============

- **Project name:** Actual Budget Multi-Instance Sync Server Admin CLI.
- **CLI executable:** ``abssctl`` (Actual Budget Sync Server ConTroL).

The project is currently in the **Alpha (foundations)** phase. The repository
builds on the bootstrap work from Pre-Alpha and now focuses on wiring core
services: configuration, state management, and read-only workflows that unlock
future instance operations.

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
   The CLI is still stabilising APIs during Alpha. Initial commands focus on
   configuration and read-only inspection; mutating workflows arrive once the
   providers and state engine solidify.

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

4. Invoke the CLI skeleton::

      abssctl --help
      abssctl --version
      abssctl config show
      abssctl version list --json
      abssctl instance list --json

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

Read-only registry commands are now wired up: ``abssctl version list`` and
``abssctl instance list`` surface the contents of ``versions.yml`` and
``instances.yml`` respectively, while ``abssctl instance show <name>`` displays
details for a single instance. Use ``--remote`` with ``version list`` to pull
published versions from npm when the CLI is available (falls back gracefully if
``npm`` is missing). All commands accept ``--config-file`` so you can point at
alternate configuration sources when testing or operating multiple environments.

Roadmap & Specifications
========================

- Requirements & project plan: ``docs/requirements/abssctl-app-specs.txt``
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
- ``dev-alpha`` — working branch for the foundations milestone and experimental CLI work.
- Short-lived feature branches support focused working sessions.

Roadmap Snapshot
================

- **Pre-Alpha — Repo Bootstrap (complete):** scaffold layout, ``pyproject.toml``, docs
  skeleton, CI with lint/test.
- **Alpha Builds — Foundations:** CLI skeleton beyond placeholders, config
  loader, logging, state/lock primitives, template engine, read-only commands,
  JSON output plumbing. Publish dev builds to PyPI from tags on ``dev``.
- **Beta Releases — Core Features:** Version operations, instance lifecycle,
  systemd/nginx providers, doctor basics. All updates become non-destructive or
  ship with migration hooks.
- **Release Candidate — Quality & Docs:** Support bundle, robust errors, man
  pages & completion, full docs & examples, CI integration tests on TurnKey
  Linux VMs. Automate PyPI release from GitHub actions.
- **Release — v1.0.0:** Burn-in testing across supported Actual versions,
  release on a green pipeline with documentation sign-off.
