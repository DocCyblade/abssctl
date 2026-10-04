============
abssctl Home
============

Actual Budget Sync Server Control CLI (abssctl) Documentation Overview
======================================================================

.. meta::
   :description: Documentation hub for the abssctl CLI project.

Documentation version: |release|

Welcome to the documentation for ``abssctl``— the Actual Budget Sync Server admin
CLI. The Beta milestone delivers lifecycle management: configuration, registry
inspection, structured logging, locking, templated providers, ports, version
installs, instance control, doctor, backups, TLS, and support bundles.
Actual 25.11 and newer require Node.js 22. See the manual integration
checklist before calling a build ready for an appliance.

.. toctree::
   :maxdepth: 1
   :caption: Overview

   overview
   roadmap

.. toctree::
   :maxdepth: 1
   :caption: Getting Started

   guides/quickstart
   guides/developer-guide
   guides/mitp

.. toctree::
   :maxdepth: 1
   :caption: Implementation Plans

   guides/systemd-nginx-provider-plan
   guides/version-lifecycle-plan
   guides/backup-restore-plan
   guides/backup-command-plan
   guides/mutating-command-test-strategy
   guides/doctor-plan

.. toctree::
   :maxdepth: 1
   :caption: Reference

   reference/cli-commands
   man/abssctl
   requirements/abssctl-app-specs
   support/actual-support-matrix


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
