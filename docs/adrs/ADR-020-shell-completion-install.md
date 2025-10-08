# ADR 0020: Shell Completion Installation

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** ux, shell

## Context
We want frictionless tab completion for Bash (TKL default), Zsh (macOS default), Fish, and PowerShell without silently editing user dotfiles. The solution must work for pipx/venv installs and for system packages, and be safe-by-default.

## Options Considered
- Typer built-in installer (recommended)
- Manual copying into /etc/bash_completion.d

## Decision
Introduce a `abssctl completion` command group backed by Typer/Click completion.

**Commands**
- `abssctl completion show [--shell bash|zsh|fish|powershell]` → print completion script to stdout.
- `abssctl completion install [--shell ...] [--user|--system] [--path PATH] [--write-rc|--rc-file PATH]`:
  - **bash**: copy to `/etc/bash_completion.d/abssctl` (system) or `~/.local/share/bash-completion/completions/abssctl` (user).
  - **zsh**: copy to `/usr/local/share/zsh/site-functions/_abssctl` (system) or `~/.zfunc/_abssctl` (user); print fpath/`compinit` hints.
  - **fish**: copy to `/usr/share/fish/vendor_completions.d/abssctl.fish` (system) or `~/.config/fish/completions/abssctl.fish` (user).
  - **powershell**: print instructions; when `--write-rc` is passed, append to `$PROFILE`.
- `abssctl completion uninstall [--shell ...] [--user|--system]` → remove installed file(s).

**Behavior**
- Auto-detect shell from `$SHELL` when `--shell` is omitted (fallback: bash on Linux, zsh on macOS).
- Safe-by-default: never modify RC files unless `--write-rc` or `--rc-file` is specified; otherwise print clear instructions.

**Packaging**
- Ship pre-generated completion templates in the wheel/sdist under `abssctl/_completions/` for offline installs.
- Downstream packagers (e.g., Debian/TurnKey) may install system-wide into standard completion paths during packaging.

## Consequences
- Works on TKL (bash) and macOS (zsh) with minimal steps.
- No silent dotfile edits; explicit flags control writes.
- Friendly to pipx/venv installs and to distro packages.
- Negligible package-size increase for bundled completion templates.

## Open Questions
- Provide a Homebrew formula snippet to auto-install zsh completions on macOS?
- Should `doctor` surface a friendly tip when completion isn’t detected?
