# ADR 0029: Doctor Probe Policy

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** healthcheck

## Context
Doctor runs a catalog of environment, filesystem, service, and application checks. We need clear timeouts/retries, concurrent execution, a stable severity model (green/yellow/red), predictable exit codes (ADR-013), and tightly scoped `--fix` behavior, so operators and CI can rely on `doctor` without surprises.

## Options Considered
- Timeout defaults + severity mapping (selected)

## Decision
Define concrete probes, timeouts, severity mapping, exit-code rules, and safe `--fix` actions.

### Probe catalog (what we check)
- **Env & deps:** Python and `abssctl` version; OS release; `node`, `npm`, `tar`, `gzip`; **`zstd`** (warn if missing; see ADR-021); `nginx`; `systemctl`.
- **Config & state:** parse `/etc/abssctl/config.yml`; verify **state dir** (ADR-024); load `/var/lib/abssctl/registry/{instances.yml,ports.yml}` and schema version.
- **State sanity:** unique instance names; unique/available ports; coherent registry.
- **FS & perms:** required dirs exist with expected owner/group/modes: `/etc/abssctl` (root, read-mostly), `/var/lib/abssctl/registry` (actual-sync), `/var/log/abssctl`, `/run/abssctl`.
- **Ports & conflicts:** ensure each instance port is free or bound by the expected service PID.
- **systemd:** unit files present; `systemctl is-enabled` / `is-active` per instance.
- **nginx:** vhost files present; enabled symlink correct; **`nginx -t`** passes (no reload in doctor).
- **TLS (if enabled):** cert/key files exist and are readable; expiry <30d ⇒ **yellow**; expired ⇒ **red**. (Never log PEM contents.)
- **App health (per instance):** TCP connect to upstream port; optional HTTP GET expecting 2xx/3xx if configured. Optionally probe local vhost.
- **Disk/inodes:** free <10% ⇒ **yellow**; <5% ⇒ **red**.
- **Node engines:** if upstream `engines.node` > system Node ⇒ **yellow** (ADR-018).

### Timeouts, retries, concurrency
- **Exec probes** (`nginx -t`, `systemctl`, etc.): timeout **5s** each.
- **TCP/HTTP probes:** connect **1s**, total **3s**, **2 retries** with exponential backoff (jittered).
- **Parallelism:** run independent probes concurrently (cap **8** at a time).

### Severity mapping (green / yellow / red)
- **GREEN:** passed.
- **YELLOW (warn, rc=0):** non-fatal: missing `zstd`; Node engines mismatch; TLS expires <30d; disk/inodes <10%; instance stopped but enabled; using defaults.
- **RED (error, rc≠0):** fatal: invalid YAML; missing required tool (`tar`, `node`, `nginx`, `systemctl`); duplicate/occupied ports; `nginx -t` fails; systemd unit failed; TLS expired/missing when enabled; blocking permissions; disk/inodes <5%.

### Exit codes (ADR-013 precedence)
Choose the **worst** present: **provider/system (4)** > **environment (3)** > **validation (2)** > **success (0)**.
- **0**: only green/yellow findings.
- **2**: validation/config errors (bad YAML, duplicate ports, registry schema mismatch).
- **3**: environment/dependency missing (tool not found, unreadable paths).
- **4**: provider/runtime errors (`nginx -t` fails, systemd failing, port in use by foreign PID).

### `--fix` remediation (safe & non-destructive)
Allowed:
- Create **service user** `actual-sync` if missing.
- Create missing dirs (`/var/lib/abssctl/registry`, `/var/log/abssctl`, `/run/abssctl`) with correct owner/modes.
- Migrate legacy state from `/etc/abssctl` → `/var/lib/abssctl/registry` with **read-only** compat symlinks (ADR-024).
- Normalize file perms (0600 TLS keys; 0640 files; 0750 dirs).
- Write default skeleton config files **only if absent**.
Not allowed:
- Changing ports, modifying nginx templates, reloading nginx, restarting services, installing packages, or upgrading Node. Print precise next-step commands instead.

### Output & flags (ties to ADR-028)
- Emit a summary and, with `--json`, per-probe objects: `{id, category, status, message, remediation?}`.
- Include `duration_ms`, `lock_wait_ms`, and aggregated **status**; compute `rc` via rules above.
- Useful flags: `--json`, `--fix`, `--timeout-ms N`, `--retries N`, `--only env,config,fs,ports,systemd,nginx,tls,app,disk`, `--yes`.

### Defaults/thresholds
- TLS expiry **<30 days** ⇒ yellow; **expired** ⇒ red.
- Disk/inodes free **<10%** ⇒ yellow; **<5%** ⇒ red.
- TCP/HTTP: **1s connect**, **3s total**, **2 retries**.
- Exec probes: **5s timeout** each.

## Consequences
- Predictable, quick `doctor` runs with actionable output and clear rc mapping.
- No surprise system changes; `--fix` is limited to safe file/perm/state adjustments.
- CI can rely on consistent warnings (yellow) vs failures (red) for gating.
- Operators get precise remediation steps without risking service disruption.

## Open Questions
- None
