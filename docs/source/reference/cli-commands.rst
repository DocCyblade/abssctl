====================
CLI Command Overview
====================

During the Alpha core-features milestone ``abssctl`` exposes full lifecycle
functionality for configuration inspection, registry-backed listings, version
management, and provider-driven instance provisioning. Structured logging
captures every invocation, and commands that mutate state acquire the
appropriate locks before touching the registry or calling out to system
services.

Config Commands
===============

``abssctl config show``
   Reads configuration from defaults, YAML, environment overrides, and CLI
   flags before rendering the merged result. Use ``--json`` to emit the values
   as machine-readable output; otherwise a Rich table is printed.

Version Commands
================

``abssctl version list``
   Normalises ``versions.yml`` entries and displays them in a table or JSON via
   ``--json``. Supplying ``--remote`` queries npm for the package declared in
   config (``@actual-app/sync-server`` by default) and merges the results with
   local registry entries, marking which versions are already installed. JSON
   output now includes the captured integrity block (npm ``shasum`` plus the
   tarball digest) for consumers that want to verify artifacts offline.

``abssctl version check-updates``
   Compares the installed versions against npm metadata, reporting the latest
   stable release and any upgrades available. The ``--json`` flag returns a
   structured payload (package, status, installed/latest versions, updates).

``abssctl version install <X.Y.Z> [--set-current] [--dry-run] [--no-backup] [--backup-message TEXT] [--yes]``
   Installs the requested Sync Server version beneath ``<install_root>/vX.Y.Z``
   and records metadata in ``versions.yml``. By default the command prompts the
   operator to run ``abssctl backup create`` before continuing; use
   ``--no-backup`` to skip or ``--yes`` to auto-confirm. ``--set-current``
   updates the ``current`` symlink after installation, while ``--dry-run``
   reports planned actions without touching the filesystem. Successful installs
   persist npm integrity details (``shasum`` and tarball digest) alongside the
   standard metadata so later audits can confirm the package contents.

``abssctl version switch <X.Y.Z> [--restart {none,rolling,all}] [--dry-run] [--no-backup] [--backup-message TEXT] [--yes]``
   Updates the ``current`` symlink to the chosen version. ``--dry-run`` reports
   the planned symlink change and restart policy without touching the
   filesystem, while successful runs restart affected instances according to
   the selected policy (``rolling`` by default). Safety prompts mirror
   ``version install``.

``abssctl version uninstall <X.Y.Z> [--dry-run] [--no-backup] [--backup-message TEXT] [--yes]``
   Removes an installed version once no instances depend on it. ``--dry-run``
   previews the deletion plan without dropping files or registry entries.
   Uninstalling the active ``current`` version is blocked. Prompts for a
   pre-flight backup unless ``--no-backup`` is supplied.

Ports Registry
==============

``abssctl ports list [--json]``
   Displays the reserved port set recorded in ``ports.yml``. JSON output is a
   stable list of ``{"name": ..., "port": ...}`` mappings that tooling can
   consume. The registry updates automatically when instances are created,
   deleted, or reassigned to a new port.

Instance Commands
=================

``abssctl instance list`` / ``abssctl instance show <name>``
   Read ``instances.yml`` from the registry directory, enrich entries with
   derived status information from the instance status provider, and present the
   results in a table or JSON. The ``show`` command exits with code 1 if the
   requested instance is missing.

``abssctl instance create <name>``
   Provisions directories under ``instance_root`` (data/runtime/state/logs),
   reserves or honours a chosen port, renders templated systemd and nginx
   assets using the configured templates, and registers the instance in
   ``instances.yml``. Validation includes filesystem conflict checks, registry
   duplication detection, and nginx config testing. Failures roll back
   directories, registry updates, and port reservations automatically. ``--port``,
   ``--domain``, ``--version``, ``--data-dir``, and ``--no-start`` customise the
   initial state.

``abssctl instance enable|disable <name>``
   Acquire the per-instance lock, validate the instance exists, then delegate to
   the systemd and nginx providers. ``enable`` creates the systemd enablement
   state and nginx symlink, while ``disable`` tears them down. ``--dry-run`` on
   either command reports planned actions without calling the providers. The
   registry entry is updated to reflect the new status and diagnostics snapshot.

``abssctl instance start|stop|restart <name>``
   Ensure the instance exists, then call the systemd provider to control the
   unit via ``systemctl``. ``--dry-run`` reports the intended systemd calls, and
   successful operations update registry metadata (timestamps, status flags).

``abssctl instance status <name> [--json]``
   Combines registry data, provider diagnostics, and ``systemctl status`` output
   to present the current state. JSON mode is suitable for automation, while the
   default table highlights registry status, systemd enablement, and nginx
   enablement.

``abssctl instance logs <name> [--lines N] [--since TS] [--follow]``
   Streams or samples the systemd journal for the instance using the provider's
   ``journalctl`` wrapper.

``abssctl instance env <name> [--json]``
   Emits environment variables and path helpers that scripts can source when
   interacting with the instance.

- ``abssctl instance set-fqdn <name> <domain> [--dry-run] [--no-backup] [--backup-message TEXT] [--yes]`` updates the instance domain, rewrites configuration, and records history in the registry.
- ``abssctl instance set-port <name> <port> [--dry-run] [--no-backup] [--backup-message TEXT] [--yes]`` reserves a new port, rewrites config, restarts the systemd unit, and updates the ports registry.
- ``abssctl instance set-version <name> <version> [--dry-run] [--no-backup] [--backup-message TEXT] [--yes]`` binds an instance to a specific installed version and restarts as needed.
- ``abssctl instance rename <name> <new-name> [--dry-run] [--no-backup] [--backup-message TEXT] [--yes]`` moves directories, updates registry metadata/history, and refreshes rendered provider assets.

All mutators honour locks, safety prompts, and support ``--dry-run`` to preview changes while recording skipped steps in the operations log.

``abssctl instance delete <name> [--purge-data] [--dry-run] [--no-backup] [--backup-message TEXT] [--yes]``
   Stops (best-effort), disables providers, removes rendered systemd/nginx
   assets, deletes registry entries, and releases reserved ports. ``--purge-data``
   removes the instance data directory, while ``--dry-run`` reports planned
   actions without changing state. When the operator accepts the safety prompt,
   the command runs ``backup create`` before proceeding.

TLS Commands
============

``abssctl tls verify [--instance NAME] [--cert PATH --key PATH --chain PATH] [--source {auto,system,custom,lets-encrypt}] [--json]``
   Validates certificate/key pairs from the registry or explicit paths. The
   command checks readability, owner/group/mode against configuration policy,
   certificate expiry, and key↔cert pairing. ``--instance`` inspects the
   registered TLS source for an instance, honouring ``--source`` overrides
   (``lets-encrypt`` requires a matching live certificate); manual verification
   requires ``--cert`` and ``--key``. ``--json`` emits a structured report
   suitable for automation; otherwise a Rich table summarises each check.

``abssctl tls install <name> --cert PATH --key PATH [--chain PATH] [--dry-run] [--yes]``
   Copies operator-provided TLS assets into the configured destinations (defaulting
   to sibling paths of the system certificate/key), enforcing secure permissions
   and creating timestamped backups of any overwritten files. Validation runs
   before copying; ``--dry-run`` previews the plan without touching the filesystem
   or registry, and ``--yes`` skips the interactive confirmation. Successful
   installs update the registry, re-render the nginx site with the new ``custom``
   material, validate via ``nginx -t``, and reload nginx when the configuration
   changes.

``abssctl tls use-system <name> [--dry-run]``
   Switches an instance back to the system TLS defaults after validating the
   configured certificate/key pair. The command re-renders the nginx site (with
   validation/reload) to pick up the restored system paths. ``--dry-run`` reports
   the planned registry update without persisting changes.

System Diagnostics & Backups
============================

``abssctl doctor`` and ``abssctl support-bundle``
   Placeholders that confirm the CLI wiring. These commands will gain real
   probes and bundle generation during the Beta milestone.

``abssctl backup create <instance> [--message TEXT] [--label LABELS] [--data-only] [--out-dir PATH] [--compression {auto,zstd,gzip,none}] [--compression-level N] [--json] [--dry-run]``
   Captures an instance snapshot beneath the configured backup root (defaults to
   ``/srv/backups``). Archives include instance data, rendered systemd/nginx
   assets, and registry metadata, plus a companion ``.sha256`` checksum file and
   an index entry in ``backups.json`` (algorithm, checksum, labels, user message).
   ``--dry-run`` previews the plan without touching the filesystem, while
   ``--json`` emits a machine-readable payload describing the plan/result. The
   ``--label`` option accepts a comma-separated list of tags.

   The version lifecycle commands (``version install|switch|uninstall``) honour
   their safety prompts by invoking the backup workflow automatically whenever
   the operator accepts (or uses ``--yes``). ``instance delete`` participates in the
   same safety-prompt flow. Use ``--no-backup`` to bypass the safeguards in automation.

``abssctl backup list [--instance NAME] [--json]``
   Reads ``backups.json`` and displays the known backups in a table or JSON. Use
   ``--instance`` to filter for a specific instance.

``abssctl backup show <ID> [--json]``
   Prints detailed metadata for a single backup entry, including checksum information
   and labels.

``abssctl backup verify [<ID>] [--all] [--json]``
   Recomputes SHA-256 checksums for the selected backup(s), updating the index with the
   verification status. ``--all`` verifies every entry in ``backups.json``.

``abssctl backup restore <ID> [--instance NAME] [--dest PATH] [--dry-run] [--json] [--no-pre-backup] [--backup-message TEXT] [--yes]``
   Restores the specified backup archive into the instance data directory (or an alternate
   ``--dest``). The command verifies the checksum, extracts the payload into a staging
   directory, atomically swaps the data directory, and rehydrates systemd/nginx assets when
   they were captured. Services are stopped during the swap and restarted if they were
   previously running. ``--dry-run`` previews the plan, while ``--json`` emits a structured
   payload showing actions taken. ``--no-pre-backup`` skips the optional safety prompt.

``abssctl backup reconcile [--instance NAME] [--apply] [--json]``
   Compares the backup index against on-disk archives, reporting missing entries, index
   status mismatches, and orphaned archives that lack metadata. ``--apply`` updates the
   index to mark missing archives and records a reconciliation timestamp. ``--json`` emits
   the findings for automation.

``abssctl backup prune [--instance NAME] [--keep N] [--older-than DAYS] [--dry-run] [--json]``
   Removes old backups according to simple retention policies. ``--keep`` retains the most
   recent ``N`` backups per instance, while ``--older-than`` prunes archives older than the
   specified number of days. ``--dry-run`` previews actions without deleting files.
