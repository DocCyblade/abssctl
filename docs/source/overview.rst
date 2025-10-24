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
- **Operational Safety:** built-in validations (configurable TLS expiry and
  permission checks), backup prompts, and dry-run
  support across mutating commands.
- **Observability:** structured logs, health-check probes, and diagnostic bundle
  generation.
- **Documentation First:** requirements, ADRs, and Sphinx-powered guides live in
  the repository to keep engineering and operations aligned.

Current Status
==============

Alpha core features now include:

- ``abssctl config show`` and the full registry-backed command set
  (``version list``/``instance list``/``instance show``/``ports list``).
- Version lifecycle commands (install/switch/uninstall) with integrity
  recording, backup prompts, and lock coordination.
- Instance lifecycle provisioning (create/enable/disable/start/stop/restart/
  status/logs/env/set-fqdn/set-port/set-version/rename/delete) with transactional
  rollback and dry-run support.
- Structured logging, locking, templated provider integrations, and a ports
  registry that keeps assignments consistent across failures.
- A growing automated test suite covering success, dry-run, and failure cases.

Next Steps
==========

- Deliver TLS workflows (install/verify/use-system) and integrate certificate
  state into nginx contexts.
- Implement backup restore/reconcile flows to round out disaster recovery.
- Build the ``doctor`` and ``support-bundle`` commands on top of provider
  diagnostics.
- Harden integration tests and documentation ahead of the Release Candidate
  milestone.
