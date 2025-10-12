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

Alpha foundations now include ``abssctl config show``, read-only registry
commands (``version list``/``instance list``/``instance show``),
structured logging with JSONL operations, lock management, and templated
systemd/nginx provider scaffolds. The near-term focus is on:

- Finalising the provider implementation plan for systemd and nginx ahead of Beta.
- Bringing version lifecycle commands (install/switch/uninstall) online.
- Expanding automated tests that exercise mutating command flows and provider
  interactions.
