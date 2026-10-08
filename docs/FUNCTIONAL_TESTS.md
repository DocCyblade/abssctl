# Functional test procedure

Version: 1.0.0
Date: 2026-10-08
Audience: core devs and Cursor agents
Companion: [`TESTING_ACCESS.md`](TESTING_ACCESS.md), [`GITHUB_WORKFLOW.md`](GITHUB_WORKFLOW.md), [`source/guides/mitp.rst`](source/guides/mitp.rst)

This is the checklist for bounded guest passes and for each milestone’s **Dev final review**. It does not change product code. Production hosts and production PyPI stay untouched. VM 9011901 (`nodeapp00`) is out of scope.

## Two uses

| Use | Who runs it | Depth | Outcome |
|---|---|---|---|
| Bounded functional pass | An agent or a core dev, one chat per GitHub issue | Only the steps the open issue needs | Each failure becomes a Backlog issue. The chat that found it does not fix unrelated bugs. |
| Dev final review | Core devs only | Full pass for the milestone (below) | The review issue stays open until a core dev says the pass succeeded. An agent does not close it. |

Say **core devs** in issues and notes. Do not name one person.

## Guests

Only the three guests in [`TESTING_ACCESS.md`](TESTING_ACCESS.md). SSH hosts: `test-nodeapp01`, `test-nodeapp02`, `test-nodeapp03`. Use the `test*a` / `test*b` / `test*c` FQDNs from that file, not production names.

| Guest | Prefer when |
|---|---|
| `test-nodeapp02` | Default for a fresh TurnKey Node.js 18 install path (`system init` → `instance create`). |
| `test-nodeapp03` | Debian 13 / missing `n` / missing Python 3.11 behavior the issue calls for. |
| `test-nodeapp01` | Production-like layout only. Still use `test*a-abssctl-test.krajr.net`. |

Do not run `tmp-personal-server/000-manual-install.sh` or `000-test-install.sh` unless a core dev asked for that in the chat.

## Snapshots and cleanup

1. Before any destructive step (rollback, re-init, wipe of `/srv`, delete of instances you did not create in this chat), create a named snapshot only if a core dev asked. Otherwise roll back only to the baseline snapshot named in [`TESTING_ACCESS.md`](TESTING_ACCESS.md) when the task says to reset that guest.
2. After a rollback, wait 30–45 seconds, start the guest, then SSH.
3. Before the chat ends, restore the guest to the baseline snapshot named in TESTING_ACCESS when the pass was destructive or left the guest dirty. Leave the guest as you found it when the pass was read-only.
4. Do not delete snapshots.

## Secrets and evidence

Record enough to file or close an issue. Do not copy private keys, API tokens, passwords, or the contents of `~/.config/proxmox/cursor-ai.env` into the repo or into chat.

Safe evidence:

- Command lines and exit codes.
- Short stdout/stderr slices (redact host-specific secrets if any appear).
- `abssctl doctor --json` (paths and probe names are fine).
- Unit names, ports, instance names, Actual and Node versions.
- HTTP status from `curl` to a test FQDN (not response bodies that might include session material).
- Paths to a local support-bundle archive on the guest or workstation; do not commit the archive.

When filing a failure: title is the bug; body has what was run, exit code, guest hostname, package/git version under test, and an evidence path if one exists. Labels and milestone follow [`GITHUB_WORKFLOW.md`](GITHUB_WORKFLOW.md). Show a draft first if this chat is not the one that will file it (capture-todo skill).

## What “pass” means by milestone

| Milestone | Pass means |
|---|---|
| `v0.2.0a1` | On a fresh allowed guest: `system init`, `node ensure`, `version install`, and `instance create` succeed; the instance unit is active; `doctor` is not red because of abssctl’s own paths (units under a durable systemd dir, nginx sites on disk where the provider looks, install layout with `build/bin/actual-server.js`). |
| `v1.0.0rc1` | The MITP checklist in [`source/guides/mitp.rst`](source/guides/mitp.rst) completed end-to-end on an allowed guest. Operator docs match the CLI for the commands exercised. |
| `v1.0.0` | MITP for the current Actual release plus the ten prior stable releases (eleven total; no pre-releases). npm >= 10.9.9. Record results per version (see Evidence for version burn-in). |

## Bounded functional pass (agents or core devs)

Run only what the open issue requires. Typical happy path for `v0.2.0a1` on `test-nodeapp02` after rollback to `base-tkl-nodejs-v18` when the task says to reset:

1. **Install the CLI under test.** Wheel or editable install from the commit. `abssctl --version` matches that commit.
2. **Bootstrap.** `abssctl system init` with the flags the issue or quickstart uses (`--defaults --yes` or `--allow-create-user` as documented for that guest). Service user and state dirs exist.
3. **Node.** `abssctl node ensure --yes`. Runtime via the wrapper is Node 22+; npm >= 10.9.9 before installing Actual 26.6.0+.
4. **Version.** `abssctl version install <ver>` (default under test: `26.10.0` unless the issue names another). Tree has `package.json` and `build/bin/actual-server.js` under the version prefix. Switch `current` if the issue requires it.
5. **Instance.** `abssctl instance create <name> --port <port>` using a free test port and a `test*b` (or matching guest letter) FQDN when nginx is in scope. `systemctl is-active abssctl-<name>` is `active`.
6. **Smoke.** `abssctl instance status <name>` agrees. If nginx is in scope, the vhost returns the Actual UI HTML (HTTP 200).
7. **Doctor.** `abssctl doctor --json`. Fail the pass if a probe is red because abssctl wrote units, vhosts, or app paths the probes cannot see.

Stop at the first failure that blocks the issue’s claim. File that failure; do not expand into a full MITP unless the issue is the Dev final review.

## Dev final review (core devs)

Each milestone has an issue titled `Dev final review: <milestone>`. Core devs own it. Use this section as the checklist. An agent may prepare a guest or gather logs only if a core dev asked in that chat. An agent does not mark the review issue Done.

### Shared preconditions

- Root SSH to an allowed guest from [`TESTING_ACCESS.md`](TESTING_ACCESS.md).
- Commit or wheel under test; `make quick-tests` green on that commit before the appliance pass.
- Baseline snapshot known; restore plan agreed before destructive steps.
- Wildcard TLS files may be used from `/root/ssl/` on the guest. Do not copy the key off the guest into the repo or chat.

### Checklist for `v0.2.0a1`

Run the bounded happy path above on at least one fresh guest (`test-nodeapp02` unless core devs choose otherwise). Pass only if:

1. Init, Node ensure, version install, and instance create all exit 0.
2. The instance unit stays active (not `203/EXEC`, not crash loop).
3. Doctor is not red for abssctl-owned unit paths, nginx site paths, or the version install layout.
4. Evidence retained (commands, versions, doctor JSON) without secrets.

Optional second guest (`test-nodeapp03` or `test-nodeapp01`) only if core devs want a matrix note; failures there still become Backlog issues.

### Checklist for `v1.0.0rc1`

Run every step in [`source/guides/mitp.rst`](source/guides/mitp.rst) in order on an allowed guest (not production, not `nodeapp00`):

1. Install the CLI.
2. Bootstrap (`system init`).
3. Node ensure.
4. Server install and switch (`version install` / `version switch`).
5. Instance create; unit active; status agrees.
6. nginx proxies to the instance; Actual UI HTML returned.
7. Upgrade / rollback between two supported Actual releases.
8. Backup create, verify, restore.
9. TLS verify; HTTPS when enabled.
10. Doctor green (or explained); `doctor --fix --dry-run` changes nothing.
11. Support bundle with default redaction (no raw secrets in the manifest).
12. Instance delete removes unit, site, and registry row.

Fail the review if any step exits non-zero, the UI does not load, or doctor reports a red probe that `--fix` cannot explain. Operator docs for the commands above must match behavior observed on the guest.

### Checklist for `v1.0.0`

For each of the eleven Actual versions (current stable plus ten prior stables):

1. Install that version with `abssctl version install`.
2. Point a test instance at it (create or `instance set-version`).
3. Confirm unit active and UI HTTP 200 on the test FQDN.
4. Run backup create/verify once per version or once per review with a noted sample set if core devs scope a shorter backup sample; restore at least once in the review.
5. Record pass/fail and Node/npm versions.

npm must be >= 10.9.9 for the whole burn-in. Prefer Node 22.23.3 via `abssctl node ensure`. Update the support / compat notes the project already maintains (`docs/requirements/node-compat.yaml` and regenerate with `python3 tools/list-sync-versions.py` when that is part of the review). Do not invent a second matrix file in this pass.

## Evidence for version burn-in

Per Actual version under test, keep a short row somewhere durable (issue comment, review issue body, or the existing compat YAML):

- Actual version
- Node version and npm version
- Guest hostname
- Result: pass / fail
- Notes (exit code, failing command, doctor probe name)
- Date

No keys. No tokens. No certificate private material.
