# App purpose and how it runs

Date: 2026-10-05
Sources: `docs/requirements/abssctl-app-specs.txt`, `docs/roadmap.rst`, `docs/adrs/`, `docs/source/guides/`

abssctl is an admin CLI for one TurnKey Linux host. Its job is to install Actual Budget sync-server releases and keep several instances of that server running behind nginx, with systemd, TLS, backups, and a health check. The person it is written for is the admin on that appliance. A contributor is the secondary audience.

## What it is for

Section 0 of `docs/requirements/abssctl-app-specs.txt` defines one Python 3.11 command, `abssctl`, packaged for PyPI and pipx. v1 stays on the TurnKey Linux Node.js appliance (ADR-005). It does not migrate old data, issue Let's Encrypt certificates, run a web UI, or target other operating systems.

The success test in section 2 is time-to-value: from a clean appliance to one instance behind nginx in about five minutes, with `install-version`, `instance create`, and `instance start`. Re-running a command must be safe. Upgrade and rollback are supposed to be proven across the current Actual release and the ten before it. `doctor` reports pass or fail, and `support-bundle` collects a redacted archive.

The roadmap puts that proof at the Release milestone. Beta features are already in the tree. The open gate is one real MITP, then the wider burn-in.

## How an operator runs it

Mutating commands need root (ADR-005, ADR-007). Read-only commands can run unprivileged. Config is resolved in one order (ADR-023): CLI flags, then `ABSSCTL_*` environment variables, then `/etc/abssctl/config.yml`, then built-in defaults.

The intended first-run sequence, once `system init` is counted, is:

1. `abssctl system init` creates the `actual-sync` user, the directories, and `config.yml`. It can rediscover an existing host and rebuild the registry (ADR-035). Creating the user in a non-interactive run requires `--allow-create-user`.
2. `abssctl node ensure` installs the Node version the compatibility matrix records, using `n`. ADR-005's 2026-10-04 amendment says Actual 25.11 and newer need Node 22, preferred patch 22.23.3. Units then exec `/usr/local/bin/abssctl-node-run`, which picks that Node.
3. `abssctl install-version X.Y.Z` installs `@actual-app/sync-server` (ADR-017) into `/srv/app/vX.Y.Z`, checks npm integrity, and records the install. It leaves `/srv/app/current` alone unless `--set-current` is passed (ADR-011, section 5.1).
4. `abssctl instance create <name> --domain <fqdn>` makes the instance directory, writes `config.json`, reserves a port, renders a systemd unit and an nginx vhost, and starts the service.
5. Later: `switch-version` moves `current` and can restart instances bound to it; `instance set-version` pins one instance; `doctor` and `backup` cover health and safety.

`--dry-run` prints the plan and changes nothing. Interactive runs prompt before destructive work and offer a backup (ADR-026). Automation passes `--yes` or sets `ABSSCTL_ASSUME_YES=1` (ADR-025). `--json` is for read-only listings. Exit codes are stable (ADR-013): 0 success, 2 validation, 3 environment, 4 systemd or nginx failure.

## The objects it manages

Three things stay separate on disk (ADR-006, ADR-011, ADR-024):

- **A version** is one Actual release at `/srv/app/vX.Y.Z`. `/srv/app/current` is a symlink to the default release. Rollback is another `switch-version`, because older trees stay on disk until uninstall, and uninstall refuses while any instance still uses that version.
- **An instance** is one household's data at `/srv/<name>/`, with its own port, domain, and version binding. The binding is either `current` or a pinned `X.Y.Z`. User data never lives inside the version directory, so replacing a release does not replace the books.
- **Host state** is split by role. `/etc/abssctl/config.yml` is configuration. `/var/lib/abssctl/registry/instances.yml` and `ports.yml` are the registry. Locks are under `/run/abssctl/`. Logs and `operations.jsonl` are under `/var/log/abssctl/`. Backups are under `/srv/backups/`.

Ports start at 5000 and are handed out in order, recorded so two creates cannot take the same port (ADR-015, ADR-027).

## What one command does

ADR-004 makes the CLI Typer. ADR-009 keeps OS work in three providers: versions (npm), systemd, and nginx. A mutating command follows the same path:

1. Parse and validate the arguments.
2. Take locks in order: global `/run/abssctl.lock`, then `/run/abssctl/<instance>.lock`, then the provider (ADR-027). Wait is bounded, default 30 seconds.
3. If this is a dry run, print the plan and return.
4. If this is interactive and risky, prompt, including the backup offer.
5. The provider does the OS change. Registry writes are a temp file plus rename (ADR-008).
6. On failure, undo the partial work. For nginx that means write a temp file, `nginx -t`, then reload; a failed test leaves the live vhost in place (ADR-010, ADR-032).
7. Append a structured operation record and exit with the ADR-013 code.

`doctor` is the checker: Python, Node, npm, `tar`, `zstd`, the service user, permissions, ports, unit status, nginx syntax, instance TCP, and whether the registry matches disk. `--fix` repairs the safe cases, including moving old registries out of `/etc/abssctl/` (ADR-024, ADR-029). `support-bundle` packs a redacted snapshot of that state.

## How a live instance is served

systemd runs the unit as `actual-sync`, with umask 027 (ADR-007). The process is Node from `abssctl-node-run`, executing that version's Actual server with the instance `config.json`. The server listens on `127.0.0.1` and the reserved port.

nginx has one HTTPS vhost per instance. Certificate choice is fixed (ADR-031): a per-instance cert if one was installed, otherwise Let's Encrypt for that domain if it exists, otherwise the TurnKey pair `/etc/ssl/private/cert.pem` and `cert.key`. abssctl does not obtain certificates. It only verifies them, copies them when `tls install` is asked, and points nginx at them.

`start`, `stop`, `restart`, `enable`, `disable`, `status`, and `logs` are thin wrappers over systemd and journald.

## Two documents that no longer match the later decision

ADR-018 says abssctl only warns when Actual wants a newer Node and never installs Node. ADR-005's amendment and section 6 of the spec replace that: `node ensure` installs the matrix Node with `n`. The amendment is the current platform rule.

ADR-015 still mentions `ports.yml` under `/etc/abssctl/`. ADR-024 and section 4.2 put that file in `/var/lib/abssctl/registry/`. The later location is the one the design uses.
