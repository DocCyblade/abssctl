# ADR 0019: Manpage Build/Install Location

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** docs, build

## Context
We need abssctl(1) man pages that install cleanly on TurnKey Linux (Debian-based) and also work for pip/pipx users. Building manpages at install-time is brittle because it requires Sphinx on the target and write access to system manpaths. Pre-building in CI avoids those dependencies and lets us ship manpages as artifacts and as package data inside the wheel/sdist.

## Options Considered
- Build manpages in CI and ship in wheel (recommended)
- Generate manpages at install-time (brittle)

## Decision
Build manpages in CI and ship them prebuilt.

- Use Sphinx builder `man` in CI on tags (releases) and optionally on main snapshots. Generate at least `abssctl.1` (and additional pages as we add them).
- Include the generated `*.1` files in both the sdist and wheel under a package data directory, e.g. `abssctl/_man/`.
- Provide a helper command: `abssctl docs man install [--system|--user|--prefix PATH]`.
  - Default behavior: if running as root → install to `/usr/local/share/man/man1`; otherwise → install to `~/.local/share/man/man1`.
  - After copy: if `mandb` is available and we have permissions, run `mandb -q`; otherwise print a hint to run it.
- Also attach a release asset `manpages-abssctl-<version>.tar.gz` containing the same `*.1` files for downstream packagers.
- `abssctl docs man path` prints the source path of the embedded manpages to support custom workflows.

## Consequences
- No Sphinx required on end-user machines; faster, more reliable installs.
- Works with pipx/venv because manpages are copied explicitly to a manpath rather than relying on wheel layout.
- Slightly larger wheel due to embedded `*.1` files.
- Helper must guard paths/permissions and surface clear messages when running unprivileged.

## Open Questions
- Do we generate a single `abssctl(1)` page or additional subcommand pages (e.g., `abssctl-doctor(1)`)?
- Exact CLI surface for the helper: `abssctl docs man install` vs `abssctl man install`.
- Should `doctor` warn if `man abssctl` is not resolvable on PATH/MANPATH?
