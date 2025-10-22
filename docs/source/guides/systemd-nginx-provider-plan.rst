=============================================
Systemd & Nginx Provider Implementation Plan
=============================================

Provider Plan Status
====================

- **Owner:** Alpha Foundations team (sessions 2025-10-08 → 2025-10-21)
- **Milestone:** Alpha 5 — Core Features (Delivered)
- **Related ADRs:** ADR-009, ADR-010, ADR-014, ADR-015, ADR-027, ADR-031, ADR-032

Plan Purpose
============

Document the delivered scope for the systemd and nginx providers and track the
remaining follow-up work targeted at the Beta milestone (health checks, TLS
automation, reconcile tooling).

Delivered Capabilities (Alpha 5)
================================

- Providers render templated units/sites into configurable directories, honour
  change detection, and trigger ``systemctl daemon-reload`` / ``nginx -t`` +
  reload when content changes.
- ``instance create`` performs end-to-end provisioning: directory scaffolding,
  port reservation, template rendering, validation, provider enablement, and
  transactional rollback on failure.
- Lifecycle commands (enable/disable/start/stop/restart/delete) respect locks,
  record structured steps, surface provider failures, and support ``--dry-run``.
- Ports registry integration ensures per-instance port metadata, history, and
  release on delete/rollback.
- Diagnostics helpers expose rendered paths, enablement flags, and journal log
  access for ``instance status`` and ``instance logs``.
- Tests cover provider behaviours (reload on change, validation rollback,
  dry-run output) and CLI lifecycle flows including failure handling.

Beta Follow-Ups (Providers)
===========================

1. **TLS-aware contexts**

   - Extend nginx context builders to incorporate certificate provisioning
     workflows (system certificates vs. instance-specific paths) once TLS
     commands land.

2. **Doctor & Support Bundle Integration**

   - Expose richer diagnostics (e.g., unit state, validation output) for doctor
     probes and bundle inclusion.
   - Capture provider health data in structured form for future ``doctor --json``
     responses.

3. **Runtime Optimisations**

   - Consider batching reloads when multiple instances change during scripted
     maintenance.
   - Evaluate configurable timeouts for systemd/nginx subprocesses so doctor can
     surface stalled calls explicitly.

4. **Testing Enhancements**

   - Introduce reusable fake binaries shared with upcoming doctor/support bundle
     tests to simulate more intricate failure scenarios.
   - Add golden-site assertions covering future TLS directives.

5. **Documentation & Developer Experience**

   - Document provider configuration knobs (paths, binaries) in README and the
     developer guide.
   - Provide troubleshooting tips (common systemctl/nginx errors) and describe
     how dry-run and logging help diagnose issues.
   - Capture the plan’s completion in the roadmap and session log; update ADRs
     if deviations from the original decisions are required.

Dependencies & Sequencing
=========================

- Port allocation registry (ADR-015) must provide unique ports before nginx
  contexts can finalise upstream blocks.
- Version lifecycle commands should populate ``versions.yml`` so new instances
  can bind to specific installs.
- Safety prompt inventory (ADR-026) and non-interactive mode support (ADR-025)
  influence how confirmations/dry-runs are exposed.
- CI enhancements may be required to fake systemd/nginx binaries for tests;
  evaluate lightweight stubs or harness scripts in ``tools/``.

Exit Criteria
=============

- ``instance create`` produces working systemd/nginx assets, validates them, and
  leaves the system in a consistent state (including service reloads).
- ``instance enable/disable/start/stop/restart/delete`` integrate with real
  services, update the registry, and log structured outcomes.
- Tests cover success/failure/rollback scenarios with high confidence.
- Documentation and roadmap entries match the delivered behaviour, and the
  session log records the completion status.
