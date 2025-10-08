# ADR 0032: Nginx Rollback Plan

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** nginx, reliability

## Context
Failed nginx -t should not leave sites broken.

## Options Considered
- Atomic write + test-before-enable (recommended)

## Decision
Test config with nginx -t; only then update symlinks and reload; if failure, revert any temp files and keep current state.

## Consequences
- N/A

## Open Questions
- None

# ADR 0032: Nginx Rollback Plan

- **Date:** 2025-10-05
- **Status:** Accepted
- **Authors:** Ken Robinson
- **Deciders:** Ken Robinson
- **Consulted:** Project collaborators
- **Tags:** nginx, reliability

## Context
Nginx config changes must be **validated before they affect traffic**. Debian/TKL layout loads vhosts from `/etc/nginx/sites-enabled/` and keeps sources in `/etc/nginx/sites-available/`. Writing a bad vhost or enabling it without validation can break the whole server on reload. We need a **test‑before‑apply** flow with **automatic rollback** so the running config stays stable if a change is invalid.

## Options Considered
- Atomic write + test‑before‑enable (selected)
- Shadow config tree with custom master `nginx.conf` for testing (rejected as complex/risky)

## Decision
Apply an **enable/disable/update** workflow that always validates with `nginx -t` **before** a reload and guarantees rollback without impacting live traffic.

### General rules
- Never reload until `nginx -t` reports **syntax is ok** and **test is successful**.
- Always keep a **timestamped backup** of any vhost file we modify.
- Use **atomic renames** for file replacement (`*.new` → final) to avoid half‑written configs.
- Use instance‑scoped locks when touching vhost files/symlinks (see ADR‑027).
- Log planned actions and results in `operations.jsonl` (ADR‑028).

### File locations & naming
- Source vhost: `/etc/nginx/sites-available/<instance>.conf`
- Enabled symlink: `/etc/nginx/sites-enabled/<instance>.conf` → `../sites-available/<instance>.conf`
- Backup on edit: `/etc/nginx/sites-available/<instance>.conf.bak-<opid>`
- Temp file during edit: `/etc/nginx/sites-available/<instance>.conf.new`

### Operations
#### 1) Enable a vhost (create or enable)
1. **Write** candidate to `sites-available/<instance>.conf` (or validate existing content).
2. **Create symlink**: `sites-enabled/<instance>.conf` → `../sites-available/<instance>.conf` (if not already present).
3. **Test**: run `nginx -t -q`.
   - On **success** → **reload**: `systemctl reload nginx` and finish.
   - On **failure** → **rollback**: remove the new symlink; if we created/overwrote the file in step 1, restore from backup; **no reload**.

#### 2) Disable a vhost
1. **Remove symlink** `sites-enabled/<instance>.conf` (leave source file intact).
2. **Test**: `nginx -t -q`.
   - On **success** → **reload** and finish.
   - On **failure** (unexpected) → **rollback**: restore the symlink; **no reload**.

#### 3) Update a vhost file in place
1. **Backup** existing: copy to `*.bak-<opid>`.
2. **Write** new content to `*.conf.new` and **atomically rename** over `*.conf`.
3. **Test**: `nginx -t -q`.
   - On **success** → **reload** and finish.
   - On **failure** → **rollback**: move backup back over `*.conf`; **test again** to ensure baseline is valid; **no reload**.

### Failure handling & visibility
- Capture `nginx -t` stderr/stdout in the operation result; surface the first error line to the user.
- If rollback itself fails (e.g., filesystem error), mark operation **error (rc=4)** and print manual recovery steps.

### Permissions & hygiene
- Ensure vhost files are mode **0644**, owned by `root:root`.
- Symlinks should be **relative** (Debian style) to keep paths portable across chroots/backups.

### Concurrency (ADR‑027)
- Acquire per‑instance lock before touching its vhost; acquire a brief **global nginx lock** before creating/removing symlinks and before `reload` to serialize nginx‑wide steps.

### Why this is safe
- Creating/removing a symlink or replacing a file on disk does **not** change the running config until reload; thus validation can safely precede reload.
- On any failure, we revert filesystem changes and exit without reload—live traffic remains on the last known‑good configuration.

## Consequences
- Strong safety guarantees with simple, Debian‑conformant mechanics.
- Slightly more I/O (backups and temp files) but far less risk of outages.
- Clear operator experience: every change either reloads cleanly or is fully rolled back.

## Open Questions
- None