=============================================
Systemd & Nginx Provider Implementation Plan
=============================================

Provider Plan Status
====================

- **Owner:** Alpha Foundations team (session 2025-10-08)
- **Milestone:** Beta — Core Features
- **Related ADRs:** ADR-009, ADR-010, ADR-014, ADR-015, ADR-027, ADR-031, ADR-032

Plan Purpose
============

Outline the work required to evolve the current provider scaffolds into the
fully-featured systemd and nginx integrations described in the requirements and
ADRs. The plan focuses on Beta deliverables so mutating commands (instance
create/enable/start/etc.) can safely manage real services on TurnKey Linux.

Current State (Alpha Foundations)
=================================

- Providers exist under ``src/abssctl/providers`` with template-backed render
  helpers and thin wrappers around ``systemctl``/``nginx`` invocations.
- ``instance create`` renders service and vhost files into the runtime overlay
  directory and registers the instance but does not yet apply changes to the
  live system.
- Locks, structured logging, and registry updates are wired in the CLI so the
  providers can be extended without changing command surfaces.
- Template contexts are minimal: ports, domains, and log paths all rely on
  placeholders instead of the final registry-driven values.
- Tests cover template rendering and command wiring but do not exercise real
  systemctl/nginx behaviours or failure paths.

Goals for Beta
==============

1. **Real system integration**

   - Render unit/vhost files into host directories (e.g. ``/etc/systemd/system``,
     ``/etc/nginx/sites-available``) with safe permissions.
   - Reload/validate services (`systemctl daemon-reload`, ``nginx -t`` +
     reload) only when changes occur and roll back on validation failure.

2. **Idempotent lifecycle operations**

   - Ensure enable/disable/start/stop/restart/delete honour ADR-016 safety
     guarantees, provide actionable logging, and map errors to exit codes.
   - Support ``--dry-run``/``--yes`` once the global non-interactive policy lands.

3. **Dynamic template contexts**

   - Inject instance-specific ports, domains, TLS configuration, and version
     bindings based on registry + config data.
   - Expose shared context builders so tests can validate rendered results.

4. **Observability & diagnostics**

   - Record operations in ``operations.jsonl`` with change counts and warnings.
   - Surface `systemctl status`/``journalctl`` helpers (planned CLI commands like
     ``instance logs``) to support troubleshooting.

5. **Robust testing story**

   - Use fakes/subprocess shims to simulate systemctl/nginx and verify command
     sequences without requiring real services.
   - Add golden-file tests for rendered templates with varying TLS/port inputs.

Implementation Roadmap
======================

1. **Template Context Enhancements**

   - Extend ``_build_systemd_context``/``_build_nginx_context`` to accept registry
     entries, selected ports, TLS cert paths, and log directories per ADR-031.
   - Store context builders in a dedicated module for reuse by tests and future
     commands (e.g. backup, doctor).

2. **Systemd Provider Completion**

   - Allow configuration of the systemd unit directory via ``AppConfig``.
   - Add support helpers: ``daemon_reload()``, ``show_status()``, ``journal_logs()``,
     and optional ``--dry-run`` mode that reports intended actions.
   - Wrap ``subprocess.run`` calls with structured error messages that include
     stdout/stderr, exit codes, and suggested remediation.
   - Implement change detection so rendering returns ``changed=True`` only when
     file content or permissions differ (TemplateEngine already supports this;
     ensure we propagate signals and skip reload if unchanged).
   - Update CLI flows (enable/start/stop/restart/delete) to call reload/status
     helpers and map failures to exit code 4 (systemd/nginx errors) per ADR-013.

3. **Nginx Provider Completion**

   - Expand context to include HTTP/HTTPS blocks, upstream definitions, and TLS
     selection logic (system cert vs instance-specific paths).
   - Integrate ``nginx -t`` validation prior to enabling/reloading. On failure,
     restore the previous config or remove partial artifacts and emit warnings.
   - Add ``reload()`` and ``test_config()`` wrappers that bubble up structured
     errors, including log file hints.
   - Support future commands by exposing methods to compute server block names,
     certificate paths, and log destinations.

4. **Instance Command Enhancements**

   - Wire dry-run and confirmation prompts into mutating commands; surface
     planned actions without executing system calls when dry-run is active.
   - For ``instance create``: after rendering, run validation (``nginx -t``) and
     reload systemd/nginx only when templates changed; ensure rollback if any step
     fails (remove newly created files, revert registry updates).
   - For ``instance delete``: add purge modes that conditionally remove data
     directories, ensure nginx/systemd reloads happen once at the end.

5. **Testing Strategy**

   - Introduce provider-specific unit tests that patch ``subprocess.run`` and
     assert command invocation sequences, handling of non-zero exits, and error
     messages.
   - Add integration-style tests for CLI commands using temporary directories for
     systemd/nginx paths; verify idempotency, rollback, and logging output.
   - Update doctor tests (once implemented) to consume provider status helpers.

6. **Documentation & Developer Experience**

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
