# ADR 0031: TLS Defaults & Cert Handling

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** tls, nginx

## Context
TKL provides default cert/key paths; instances may override.

## Options Considered
- TKL defaults + per-instance override (recommended)

## Decision
Use TKL default cert/key by default; support per-instance overrides; validate file perms; reload nginx on change.

## Consequences
- N/A

## Open Questions
- Document the exact TKL cert/key paths and permissions in code and docs

# ADR 0031: TLS Defaults & Cert Handling

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** tls, nginx

## Context
TurnKey Linux (TKL) appliances ship a pre-made certificate/key pair referenced by the default nginx configuration:

```
ssl_certificate      /etc/ssl/private/cert.pem;
ssl_certificate_key  /etc/ssl/private/cert.key;
```

We don’t yet know whether TKL’s Let’s Encrypt integration overwrites those files or instead uses `/etc/letsencrypt/live/<domain>/{fullchain.pem,privkey.pem}` symlinks. **abssctl must work in both cases** without assuming a particular behavior: detect available certs, validate them, and wire nginx accordingly. abssctl does **not** mint certificates; it only verifies, optionally installs/copies when explicitly asked, and configures nginx.

## Options Considered
- TKL defaults + Let’s Encrypt detection + per-instance override (selected)
- Require custom-provided certs for every instance (rejected: too much friction)
- Auto-obtain certificates (rejected for v1: out of scope for abssctl)

## Decision
Adopt a conservative, detection-first TLS strategy.

### Certificate source order
1. **Per-instance custom paths** (if configured).
2. **Let’s Encrypt live certs** for the instance `server_name` if present:
   `/etc/letsencrypt/live/<domain>/fullchain.pem` and `/etc/letsencrypt/live/<domain>/privkey.pem`.
3. **TKL system defaults**:
   `/etc/ssl/private/cert.pem` and `/etc/ssl/private/cert.key`.

We do **not** assume Let’s Encrypt updates the system defaults; we detect and prefer LE if present.

### Nginx configuration and reload policy
- For each instance vhost:
  - `ssl_certificate` → full chain (`fullchain.pem` or equivalent).
  - `ssl_certificate_key` → private key.
- Always run `nginx -t` before enabling or reloading (see ADR‑032 for rollback). On success, `systemctl reload nginx`.

### Permissions and groups
- Private keys: **0640** owned by `root:ssl-cert` (or **0600 root:root** if group model not available).
- Cert/chain: **0644**.
- Ensure nginx worker user (typically `www-data`) is a member of `ssl-cert`; `doctor` shows **YELLOW** if not and prints the `usermod -aG ssl-cert www-data` hint (no automatic group edits).

### abssctl commands
- `abssctl tls verify [--instance X] [--cert PATH --key PATH --chain PATH]`  
  Validates existence, readability, key↔cert match, expiry (<30d **yellow**, expired **red**), and permissions. Never prints PEM bodies.
- `abssctl tls install --instance X --cert PATH --key PATH [--chain PATH]`  
  Copies files into standard locations (e.g., `/etc/ssl/private/abssctl-<X>.key`, `/etc/ssl/private/abssctl-<X>.pem`) with correct modes; updates vhost; `nginx -t`; reload on success. Prompts unless `--yes`. Keeps timestamped backups of any overwritten files.
- `abssctl tls use-system --instance X`  
  Switches back to system defaults (auto-detects LE vs TKL defaults as per order above).

### Configuration shapes
Global (`/etc/abssctl/config.yml`):
```yaml
tls:
  enabled: true
  system:
    cert: /etc/ssl/private/cert.pem
    key:  /etc/ssl/private/cert.key
  lets_encrypt:
    live_dir: /etc/letsencrypt/live
```
Per-instance (registry):
```yaml
instances:
  prod-family:
    tls:
      source: auto          # auto|system|custom
      cert: /path/to/fullchain.pem   # when source=custom
      key:  /path/to/privkey.pem     # when source=custom
      chain: /path/to/chain.pem      # optional
```
`source: auto` prefers LE for `server_name` if present; else falls back to TKL defaults.

### Doctor checks (tie to ADR‑029)
- Presence/readability of configured cert/key paths.
- Key ↔ cert match.
- Expiry thresholds (<30d **yellow**, expired **red**).
- Permissions and `ssl-cert` group membership.
- Nginx vhost actually points to the same paths we validated (compare rendered config with expected).

## Consequences
- Works out-of-the-box on TKL using the system defaults.
- Preferentially uses Let’s Encrypt when present without guessing how TKL manages the defaults.
- Clear verification and install workflows; minimal risk by validating `nginx -t` before reload.
- Permissions model aligns with Debian conventions; no secret material printed to logs.

## Open Questions
- Confirm TKL’s exact behavior when enabling Let’s Encrypt: does it update `/etc/ssl/private/cert.pem|cert.key` or only manage `/etc/letsencrypt/live`? We’ll detect either way but document the observed behavior.
- Confirm nginx worker user/group on TKL (assumed `www-data:www-data`); adjust doctor hints if different.
- Optional hardening: document recommended cipher suites and OCSP stapling once baseline is stable.