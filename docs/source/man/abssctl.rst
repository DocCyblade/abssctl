abssctl
=======

Synopsis
--------

**abssctl** [*OPTIONS*] *COMMAND*

Description
-----------

``abssctl`` installs and operates multiple Actual Budget sync-server instances
on a TurnKey Linux host. It installs ``@actual-app/sync-server`` from npm,
renders systemd and nginx, and records instance state under ``/var/lib/abssctl``.

Actual 25.11 and newer require Node.js 22 or newer. Use ``abssctl node ensure``
to install that runtime. ``abssctl`` does not talk to budget data; that is
``@actual-app/cli``.

Commands
--------

**version**
    Install, switch, uninstall, and list sync-server releases.

**instance**
    Create, start, stop, and reconfigure instances.

**backup**
    Create, verify, restore, and prune instance archives.

**tls**
    Verify and install certificates used by nginx.

**doctor**
    Run health probes and optional repairs.

**support-bundle**
    Collect a redacted diagnostic archive.

**node ensure**
    Install the Node.js version required by the selected Actual release.

**system init**
    Create the service account and directory layout.

**docs man**
    Print or install this manual page.

**completion**
    Show, install, or remove shell completion scripts.

Exit status
-----------

0
    Success.
2
    Validation or user input error.
3
    Environment error (permissions, missing tools, disk).
4
    Provider or system failure (systemd, nginx, TLS, tar).

See also
--------

docs/PATH_FORWARD.md, docs/requirements/abssctl-app-specs.txt
