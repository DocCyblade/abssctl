# Node Compatibility Tracking Plan

Last updated: 2025-11-08 15:10 UTC (commit TBD)  
Owner: AI/Doc

## Goals

1. Maintain a single source of truth for supported Node.js versions and their compatibility with Actual Sync Server releases (latest ≥10 versions per spec).
2. Enforce the required Node version on every instance (manual + abssctl-managed) using a wrapper around `n`.
3. Provide scripting + documentation so operators can refresh the matrix, install the right Node runtime, and understand manual server impacts.

## Work Items

### A. Compatibility Data

1. Create `docs/requirements/node-compat.yaml` with:
   - `node_versions`: list of supported majors/minors, minimum patch, ADR reference.
   - `actual_versions`: entries `{ version, release_date, node_major, status, tested_at }`.
2. Add automation (`tools/list-sync-versions.py`) that:
   - Fetches the latest releases from npm or GitHub.
   - Ensures the YAML always contains the latest 10–12 entries, marking new ones `status: untested`.
3. Update `docs/requirements/test-coverage-report.rst` (or a dedicated “Compatibility Matrix” doc) to render the YAML into a human-readable table.
4. Update the roadmap / spec to note that the YAML is the authoritative list.

### B. Node Enforcement Wrapper

1. Build `/usr/local/bin/abssctl-node-run` (checked into `tools/abssctl-node-run.sh`):
   - Reads `REQUIRED_NODE` from environment (e.g. `/etc/default/abssctl-node`).
   - Runs `n "$REQUIRED_NODE"` (expecting `n` preinstalled) and execs `node "$@"`.
   - Handles missing `n` with a helpful error (point to docs).
2. Add `abssctl node ensure` (or reuse manual script) to preinstall the required Node versions via `n` so services don’t download on each start.
3. Update systemd unit templates (and manual script) to use:
   ```
   EnvironmentFile=/etc/default/abssctl-node
   ExecStart=/usr/local/bin/abssctl-node-run /srv/app/current/server.js ...
   ```
4. Document the wrapper in `tmp-personal-server/README-context.md` and the compatibility doc (operators can bump Node by editing `/etc/default/abssctl-node` + running `abssctl node ensure`).
5. Add doctor probe(s) that compare `node --version` to the YAML and warn/error if the host is out of compliance.

### C. Manual Server Impact

1. `000-manual-install.sh` must:
   - Install `n` (if not already present) or ensure it is available to `actual-sync`.
   - Drop `/etc/default/abssctl-node` with `REQUIRED_NODE` set to the YAML’s supported version.
   - Install the wrapper script and update systemd units to call it.
2. Update `manual-server-spec.md` + provisioning plan to mention the wrapper + `n` usage so the manual environment matches automation.

## Open Questions

- Where should the YAML live long-term? (Currently targeting `docs/requirements/`.)
- Should we store historical compatibility data (older than the “latest 10”)?
- How do we want to package `n` on TurnKey appliances? (Manual install vs bundling in abssctl.)
- Do we need a lightweight ADR summarizing the enforcement approach, or is the compatibility doc + roadmap entry sufficient?

## Next Steps

1. Draft the YAML schema and script outline.
2. Prototype the wrapper + unit changes on the manual server script.
3. Wire doctor probe + doc updates.
4. Roll into abssctl CLI once validated on the manual host.
