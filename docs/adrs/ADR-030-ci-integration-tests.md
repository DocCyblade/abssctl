# ADR 0030: CI Integration Tests on TKL

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** ci, testing

## Context
We must validate real workflows against a TKL VM image.

## Options Considered
- On-tag + nightly matrix (recommended)

## Decision
Adopt a Manual Integration Test Protocol (MITP) for each RC and release tag.

### Environment
- Base image: **TurnKey Linux Node.js v18** (Debian-based), fresh install.
- Network: NAT or bridged; allow SSH access; no external DNS required.
- Accounts: root/sudo; create service user handled by `doctor --fix` as needed.

### Versions under test
Test **current upstream** plus the **previous 10 releases** (rolling window of 11 total). **Exclude pre-releases entirely** (alpha/beta/rc). If fewer than 11 stable releases exist after a major bump, test all available stable versions since that bump.

- Source of truth: npm dist-tags and semver release tags for `@actual-app/sync-server` (ADR-017).
- Node engines mismatches are **warnings** per ADR-018 (we do not upgrade Node automatically).

### Re-test cadence
- Run MITP on **our own schedule** aligned with **release candidates** and **final releases** (not on every upstream patch).
- Trigger ad-hoc MITP runs for high-severity upstream security fixes or critical bugfixes that impact deployments.

### Test checklist (execute in order)
1. **Doctor baseline**: `abssctl doctor --json` → expect green/yellow (zstd may be missing per ADR-021).
2. **Install versions**: `abssctl install-version <ver>` for both target versions.
3. **Create instances**: create `test` and `prod-family`; verify ports assigned and registry entries present under `/var/lib/abssctl/registry` (ADR-024).
4. **Systemd lifecycle**: `start/stop/restart` each instance; confirm `systemctl is-active` and logs.
5. **Nginx config**: enable vhost(s), run `nginx -t`; `curl http://127.0.0.1:<port>` or vhost if resolvable.
6. **TLS verify** (if enabled): `abssctl tls verify`; check file perms and expiry warnings.
7. **Switch version**: move one instance to the other installed version; confirm service bounce and health.
8. **Backups**: `abssctl backup create <instance> --compression auto`; confirm `.tar.zst` or `.tar.gz` and index entry.
9. **Restore**: stop instance; restore from the backup; verify data and service health after start.
10. **Uninstall guards**: attempt to uninstall an in-use version → expect block; after switching off, uninstall succeeds.
11. **Delete instance**: exercise prompt policy; in CI-style, use `--yes` + `--backup` or `--no-backup` (ADR-025/026).
12. **Doctor --fix migrations**: if legacy state is placed under `/etc/abssctl`, run `doctor --fix` and verify migration to `/var/lib/abssctl/registry` with compat symlinks (ADR-024).
13. **Logs & operations**: verify `/var/log/abssctl/operations.jsonl` entries per ADR-028 (rc/status/changed/lock_wait_ms present).

### Artifacts to capture
- `abssctl support-bundle` output (attach to release/RC notes).
- `operations.jsonl` slice covering the test window.
- `abssctl doctor --json` report (before and after `--fix`).

### Support matrix tracking
Maintain a living record of supported Actual versions in `docs/support/actual-support-matrix.md` (human table) and `docs/support/actual-support-matrix.yml` (machine-readable). Each row includes:
- version (X.Y.Z)
- release_date (YYYY-MM-DD)
- engines_node (from npm metadata)
- tested_on (date/time)
- result (pass|warn|fail) and notes

The support window is **current + 10 prior releases**. When a new release is added, drop the oldest beyond that window and mark it **EOL** in the matrix. Include the matrix files in the support-bundle.

## Consequences
- Slower than automated CI but provides deterministic, auditable coverage before releases.
- Clear go/no-go gate for tags: release only after the checklist passes.
- Artifacts help future debugging and enable a smoother transition to CI later.
- Maintains a clear, rolling **support window** (current + 10 previous) with auditable records.

## Open Questions
- None
