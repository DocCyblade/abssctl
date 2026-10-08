# Next steps

Active milestone: `v0.2.0a1`

GitHub is the queue. This file is a snapshot. If it disagrees with the Ready column, rewrite it from GitHub. Project board columns are not readable with the current token scopes, so these are the next three open `v0.2.0a1` issues after [#2](https://github.com/DocCyblade/abssctl/issues/2).

1. [#3](https://github.com/DocCyblade/abssctl/issues/3) — Install `abssctl-node-run` so new units do not exit `203/EXEC`.
2. [#4](https://github.com/DocCyblade/abssctl/issues/4) — Store nginx vhosts on disk, not under `/run`.
3. [#5](https://github.com/DocCyblade/abssctl/issues/5) — `system init` writes `/etc/abssctl/config.yml` without `--rebuild-state`.

## Prompt for the first issue

```text
Fix GitHub issue #3. gh issue view 3 --comments.

Read @AGENTS.md and @docs/CURSOR_WORKFLOW.md.
Read @docs/TESTING_ACCESS.md when the task touches a host.
Branch: dev-beta1-redux. Do not tag. Do not push unless I ask.
Gate: make quick-tests. Docs changes also run make docs.
```
