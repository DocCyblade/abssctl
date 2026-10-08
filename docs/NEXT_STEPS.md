# Next steps

Active milestone: `v0.2.0a1`

GitHub is the queue. This file is a snapshot. If it disagrees with the Ready column, rewrite it from GitHub. Project board columns are not readable with the current token scopes, so these are the next three open `v0.2.0a1` product issues after the branching-docs work ([#23](https://github.com/DocCyblade/abssctl/issues/23)). Related squash gate [#22](https://github.com/DocCyblade/abssctl/issues/22) waits until end of milestone.

1. [#3](https://github.com/DocCyblade/abssctl/issues/3) — Install `abssctl-node-run` so new units do not exit `203/EXEC`.
2. [#4](https://github.com/DocCyblade/abssctl/issues/4) — Store nginx vhosts on disk, not under `/run`.
3. [#5](https://github.com/DocCyblade/abssctl/issues/5) — `system init` writes `/etc/abssctl/config.yml` without `--rebuild-state`.

## Prompt for the first issue

```text
Fix GitHub issue #3. gh issue view 3 --comments.

Read @AGENTS.md, @docs/CURSOR_WORKFLOW.md, @docs/GITHUB_WORKFLOW.md,
and @docs/adrs/ADR-034-repo-management-and-branching.md.
Read @docs/TESTING_ACCESS.md when the task touches a host.
Branch off tip of dev-beta1-redux (e.g. issue/3-abssctl-node-run).
PR base: dev-beta1-redux. Do not PR to main. Do not tag. Do not push unless I ask.
Gate: make quick-tests. Docs changes also run make docs.
```
