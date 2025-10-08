====================
CLI Command Skeleton
====================

The Pre-Alpha release intentionally limits the CLI surface to scaffolding that
establishes naming conventions and grouping. Each command exits successfully
after printing a placeholder notice so automation can exercise the interface
without performing side effects.

Top-Level Options
=================

Example output::

   $ abssctl --help
   Usage: abssctl [OPTIONS] COMMAND [ARGS]...

   Actual Budget Multi-Instance Sync Server Admin CLI.

     This Pre-Alpha build ships with structural scaffolding only. Subcommands
     communicate planned responsibilities and will be fully implemented during
     the Alpha and Beta phases once the underlying APIs are ready.

   Options:
     -V, --version  Show the abssctl version and exit.
     --help         Show this message and exit.

Subcommands
===========

- ``abssctl doctor`` — future health checks covering Actual services, nginx,
  and systemd units.
- ``abssctl support-bundle`` — planned diagnostic archive generator.
- ``abssctl instance`` — namespace for instance lifecycle operations (``create``,
  ``list``, ``delete``, etc.).
- ``abssctl version`` — namespace for managing Actual Sync Server versions.
- ``abssctl backup`` — namespace for creating and reconciling instance backups.
- ``abssctl config`` — inspect configuration; ``config show`` is the first
  command wired to real functionality and supports ``--json`` output.

Aside from ``config show``, commands currently emit placeholder messages. Refer
to the requirements document for the eventual behaviour expectations.

Read-only commands:

- ``version list`` reads ``versions.yml`` from the configured state directory
  and prints the entries in a table or JSON. Supply ``--remote`` to include
  versions reported by ``npm view`` (when available) alongside local entries.
- ``instance list`` and ``instance show`` expose ``instances.yml`` contents;
  the latter exits with code 1 if the requested instance is missing and
  displays placeholder status/detail information while system probes are
  implemented.
- ``version check-updates`` is a placeholder that confirms configuration
  plumbing and will be replaced with real npm lookups later in Alpha.
