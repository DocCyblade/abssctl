# ADR 0021: Backup Compression & Dependencies

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** backups, perf

## Context
TurnKey Linux images are Debian-based. On stock TKL/Debian, `tar` and `gzip` are always present; `zstd` (Zstandard) is in the main repos and commonly available, and GNU tar supports it via `--zstd` when the `zstd` package is installed. We want a default that uses fast, modern compression when available, but still works out-of-the-box on minimal appliances without extra packages.

## Options Considered
- zstd default (recommended)
- gzip fallback only if zstd absent

## Decision
Default to **auto** compression strategy.

- Prefer **zstd** (`tar --zstd`) when `zstd` is installed and supported; emit archives as `.tar.zst`.
- Otherwise fall back to **gzip** (`tar -z`) and emit `.tar.gz`.
- Support `--compression {auto,zstd,gzip,none}` (default: `auto`).
- Optional `--compression-level N` applies to zstd/gzip where supported; omit if not provided.
- `abssctl doctor` checks for `tar` and `zstd`; if `zstd` is missing, mark **YELLOW** with a performance tip but do **not** fail.
- The backup index records `algorithm: zstd|gzip|none` so restores are deterministic.

## Consequences
- Works on stock TKL appliances without requiring zstd; faster when zstd is present.
- Clear file extensions reflect the actual algorithm used.
- Slightly more code to handle multiple algorithms and extensions.
- Doctor surfaces actionable advice instead of hard failures.

## Open Questions
- Do we also offer `xz` as an optional algorithm (slower, higher ratio)?
- Should we expose zstd default level or keep upstream default?
- Any operator policy to force gzip for maximum compatibility?
