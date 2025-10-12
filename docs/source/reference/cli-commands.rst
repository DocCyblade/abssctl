====================
CLI Command Overview
====================

During the Alpha foundations milestone ``abssctl`` exposes real functionality
for configuration inspection, registry-backed listings, and provider-driven
instance scaffolding. Structured logging captures every invocation, and
commands that mutate state acquire the appropriate locks before touching the
registry or calling out to system services.

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

``abssctl version switch <X.Y.Z> [--restart {none,rolling,all}] [--no-backup] [--backup-message TEXT] [--yes]``
   Updates the ``current`` symlink to the chosen version. Instances bound to the
   active version are restarted according to the selected policy (``rolling`` by
   default). Safety prompts mirror ``version install``.

``abssctl version uninstall <X.Y.Z> [--no-backup] [--backup-message TEXT] [--yes]``
   Removes an installed version once no instances depend on it. Uninstalling
   the active ``current`` version is blocked. Prompts for a pre-flight backup
   unless ``--no-backup`` is supplied.

Instance Commands
=================

``abssctl instance list`` / ``abssctl instance show <name>``
   Read ``instances.yml`` from the registry directory, enrich entries with
   derived status information from the instance status provider, and present the
   results in a table or JSON. The ``show`` command exits with code 1 if the
   requested instance is missing.

``abssctl instance create <name>``
   Renders templated systemd and nginx assets using the configured template
   directory (defaults ship with the project), writes them under the runtime
   overlay (``<runtime_dir>/systemd`` and ``<runtime_dir>/nginx``), and
   registers the instance in ``instances.yml``. Attempts to create an existing
   instance surface a clear error and abort the operation.

``abssctl instance enable|disable <name>``
   Acquire the per-instance lock, validate the instance exists, then delegate to
   the systemd and nginx providers. ``enable`` creates the systemd enablement
   state and nginx symlink, while ``disable`` tears them down. The registry entry
   is updated to reflect the new status.

``abssctl instance start|stop|restart <name>``
   Ensure the instance exists, then call the systemd provider to control the
   unit via ``systemctl``. Status information in the registry is updated to
   ``running``/``stopped`` accordingly.

``abssctl instance delete <name>``
   Stops and disables the instance (best-effort on stop), removes rendered
   systemd/nginx assets, and deletes the registry entry. All steps are logged
   and performed under the instance mutation lock.

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
   Restores the specified backup archive back into an instance data directory. The current
   implementation validates the archive, records the intended destination, and captures
   metadata in the index; actual extraction will arrive in a later iteration. ``--dry-run``
   previews the plan, and ``--no-pre-backup`` skips the optional pre-restore safeguard.

``abssctl backup prune [--instance NAME] [--keep N] [--older-than DAYS] [--dry-run] [--json]``
   Removes old backups according to simple retention policies. ``--keep`` retains the most
   recent ``N`` backups per instance, while ``--older-than`` prunes archives older than the
   specified number of days. ``--dry-run`` previews actions without deleting files.
