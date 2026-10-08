# abssctl path forward (milestone story)

Version: 1.2.0
Date: 2026-10-08
Branch: `dev-beta1-redux` (cut from `dev-beta1`, not from `dev`)

GitHub Issues are the queue. [`NEXT_STEPS.md`](NEXT_STEPS.md) is the catch-up snapshot of the next three. This file is the milestone story, not a second checkbox list. Start a chat from [`CURSOR_WORKFLOW.md`](CURSOR_WORKFLOW.md). Finished tracks stay in [`PATH_FORWARD_DONE.md`](PATH_FORWARD_DONE.md) as history.

The working tip stays `dev-beta1-redux` until the clean-`dev` squash at the end of `v0.2.0a1` ([#22](https://github.com/DocCyblade/abssctl/issues/22)). Issue branches and PRs target that milestone branch, not `main` ([#23](https://github.com/DocCyblade/abssctl/issues/23), ADR-034).

`dev` is not the base. Its only unique local commit is a `mutants/` dump. Do not merge that commit. Promote this branch to `dev` with a squash only when a slice is ready.

Finished tracks (W, N, Q, P, S, D, V, M, H, T, R) are in [`PATH_FORWARD_DONE.md`](PATH_FORWARD_DONE.md). Track S stopped at version install; tracks V and M closed that gap.

## Where we are (spec §13)

`docs/requirements/abssctl-app-specs.txt` section 13, and the same list in `docs/roadmap.rst`:

| Spec milestone | Position |
|---|---|
| Planning, Pre-Alpha, Alpha | Done. Scaffold, CLI foundations, and the PyPI project exist. |
| Beta — core features | In the tree (version ops, instances, systemd/nginx, doctor). `version install` follows `000-manual-install.sh`: `package.json` and `build/bin/actual-server.js` at `/srv/app/v<version>`. |
| RC — quality and docs | Support bundle, man pages, completions, and the MITP checklist are in. One Actual 26.10.0 instance is running on `nodeapp00` through systemd and nginx. Upgrade, backup, TLS verify, doctor, support bundle, and cleanup were not part of this run. |
| Release — v1.0.0 | Later. Burn-in across the current Actual release plus the ten prior versions, then GA. Production PyPI is still `0.1.3a1`. |

Docs reading 2026-10-05 (`docs/reviews/2026-10-05-docs-claims.md`) found `version install` partial. Track V closed that layout gap in the tree. Overview and quickstart still describe doctor, restore, TLS, and support bundles as unfinished.

Leave the production server and production PyPI alone. Test guests an agent may use are `docs/TESTING_ACCESS.md`. VM 9011901 (`nodeapp00`) is not in that set. Do not merge the `mutants/` checkpoint on local `dev`.

## Open

No track is in progress. Mutation survivor hunting stays local and on demand.

### Later (spec Release, and local quality work)

- Mutation survivor hunting beyond the bounded `exit_codes.py` CI job.
- MITP on the current Actual release plus the ten prior versions. npm must be >= 10.9.9; Actual 26.6.0 does not install below that.
- RC burn-in, production PyPI publish, and GA.

### Left from track R

The `test-nodeapp02` takeover is done. Doctor still exits 4. The write-up is track R in [`PATH_FORWARD_DONE.md`](PATH_FORWARD_DONE.md).

- `nginx-sites` is red. The provider looks for `/run/abssctl/nginx/sites-available/abssctl-<name>.conf`. The live sites are `/etc/nginx/sites-available/abssctl-<name>.conf`.
- `tls-system-cert` is red. `/etc/ssl/private/cert.pem` and `cert.key` are mode `0400`. The test sites use `/root/ssl/`.
- `app-instance-status` is yellow. Discovery left the domain unset, and `versions.yml` is empty.
