==============================
Doctor Command Implementation Plan
==============================

Plan Status
===========

- **Owner:** Beta – Observability workstream (Oct 2025)
- **Milestone:** Beta — Basic Functions
- **Related ADRs:** ADR-013, ADR-025, ADR-028, ADR-029, ADR-031

Objectives
==========

1. Deliver an actionable ``abssctl doctor`` command that inventories the
   environment, filesystem, registry, and provider state in line with
   ADR-029 (green/yellow/red severities and structured output).
2. Provide a JSON contract that CI and automation can consume while keeping the
   human-readable summary concise and prioritised.
3. Enforce ADR-013 exit codes (validation=2, environment=3, provider=4) derived
   from the most severe probe failure.
4. Set the foundation for a future ``--fix`` mode by cleanly separating probe
   collection, aggregation, and remediation steps.

Probe Catalogue
===============

The initial Beta release will implement the following probe categories. Each
probe returns ``status`` (green/yellow/red), ``message``, optional
``remediation``, and diagnostic metadata for JSON output.

Env & Dependencies
   - Python runtime, ``abssctl`` version, Linux distro.
   - Tooling availability: ``node``, ``npm``, ``tar``, ``gzip``, and ``zstd`` (warn if absent per ADR-021).
   - Provider binaries: ``nginx``, ``systemctl`` (fatal if missing).

Config & State
   - Parse the active configuration file (validation error if YAML invalid).
   - Confirm state directory structure (``/var/lib/abssctl/registry``) exists with expected ownership.
   - Ensure registry files (``instances.yml``, ``ports.yml``) round-trip decode and satisfy schema invariants.

Filesystem & Permissions
   - Critical directories: ``/etc/abssctl``, ``/var/lib/abssctl`` (and subdirs),
     ``/var/log/abssctl``, ``/run/abssctl``—check existence, owner, and mode.
   - TLS assets when enabled: key/cert/chain readability plus permissions (red when missing or unreadable, yellow when expiring <30 days).

Ports & Conflicts
   - For each registry entry ensure the configured port is either free or bound
     to the expected systemd unit PID.
   - Flag duplicates (validation error).

Systemd & Nginx
   - Check unit file presence, ``systemctl is-enabled``/``is-active`` per instance; map failures to red.
   - For nginx: config file presence, enabled symlink correctness, and
     ``nginx -t`` execution (red on failure).

Application Health
   - TCP probe to the upstream port (per instance) with configurable retries.
   - Optional HTTP GET (future enhancement) to validate back-end response.

Disk & Inodes
   - Calculate free percentage for the main filesystem hosting instance data
     and state (yellow <10%, red <5%).

Node Engine Compatibility
   - Compare installed Node.js version to the package ``engines.node`` value
     (yellow when below requirement).

Execution Model
===============

* Probe definitions will live in ``src/abssctl/doctor/probes.py`` as lightweight
  callables returning a structured ``ProbeResult`` dataclass.
* A coordinator will gather all probes, run them concurrently (``asyncio`` or
  ``concurrent.futures`` with a cap of 8 concurrent probes), and collate results.
* Timeouts: 5s for external commands, 1s connect/3s total for TCP/HTTP checks
  with two retries and jitter.
* Aggregation calculates the highest-severity outcome and maps it to the exit
  code precedence (provider/system=4 > environment=3 > validation=2 > success=0).

CLI Surface
===========

``abssctl doctor [--json] [--only category,...] [--exclude category,...] [--timeout-ms N] [--retries N] [--yes] [--fix]``\*

* ``--json``: emit ``{"probes": [...], "summary": {...}}`` for automation.
* ``--only``/``--exclude``: scope categories (env, config, fs, ports, systemd, nginx, tls, app, disk).
* ``--timeout-ms`` / ``--retries``: tweak global defaults (per ADR-029).
* ``--fix`` (future): gated scaffolding with ``--yes`` required; initially prints “Not yet implemented” and exits with success to avoid surprise behaviour.

Implementation Tasks
====================

1. **Data structures & wiring**
   - [x] Define ``ProbeResult`` (id, category, status, message, remediation, metrics).
   - [x] Create probe registry + execution harness returning ordered results.
   - [x] Implement aggregation + exit-code mapper following ADR-013 precedence.

2. **Probe implementations**
   - [ ] Build individual probes per ADR-029 using existing helpers (registry, providers, config).
   - [ ] Ensure probes never raise; capture exceptions and return ``status=red`` with diagnostic content.

3. **CLI Command**
   - [x] Add ``doctor`` Typer subcommand using the harness.
   - [x] Render concise console output grouped by category with severity labels.
   - [x] Support ``--json`` payloads mirroring ADR-028 structured logging.

4. **Testing**
   - [x] Harness tests covering aggregation, ordering, and failure capture.
   - [x] CLI integration tests verifying exit codes for success, environment, and provider failures.
   - [ ] JSON fixture assertions for the full probe catalogue once probes land.

5. **Documentation & Follow-up**
   - [x] Update CLI reference + README doctor sections with current behaviour.
   - [ ] Record probe catalogue + remediation guidance once probes are implemented; expand ``--fix`` behaviour in a future milestone (tie-in with ADR-029 safe actions).

Open Questions
==============

1. Should we expose per-probe timing/metrics in the human-readable output or
   keep them JSON-only?
2. How should the command behave when no instances exist (reporting green baseline vs. yellow “no instances” warning)?
3. What is the minimal ``--fix`` subset worth shipping in Beta, and how do we
   surface dry-run previews for fixes?
