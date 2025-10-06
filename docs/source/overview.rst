========
Overview
========

``abssctl`` (Actual Budget Sync Server ConTroL) is a Python-based CLI that
orchestrates installation, configuration, and operations for multi-instance
Actual Budget Sync Server deployments on TurnKey Linux. The CLI sits between
operators and system services such as ``systemd``, ``nginx``, and the Actual npm
package, providing idempotent workflows and auditable state tracking.

Project Pillars
===============

- **Deterministic Deployments:** consistent filesystem layout, version pinning,
  and repeatable provisioning steps.
- **Operational Safety:** built-in validations, backup prompts, and dry-run
  support across mutating commands.
- **Observability:** structured logs, health-check probes, and diagnostic bundle
  generation.
- **Documentation First:** requirements, ADRs, and Sphinx-powered guides live in
  the repository to keep engineering and operations aligned.

Next Steps
==========

The Pre-Alpha milestone focuses solely on repository infrastructure. Alpha
builds will deliver functional commands for version management, instance
provisioning, and state inspection.

The first Alpha deliverable is ``abssctl config show``, which exposes the
effective configuration after merging defaults, ``/etc`` settings, and
environment overrides.
