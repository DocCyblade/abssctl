# Next steps

Active milestone: `v0.2.0a1`

GitHub is the queue. This file is a snapshot. If it disagrees with the Ready column, rewrite it from GitHub. Project board columns are not readable with the current token scopes, so these are the next three open `v0.2.0a1` product issues after [#5](https://github.com/DocCyblade/abssctl/issues/5) (`system init` writes `config.yml`; this chat). Related squash gate [#22](https://github.com/DocCyblade/abssctl/issues/22) waits until end of milestone.

1. [#6](https://github.com/DocCyblade/abssctl/issues/6) — Discovery must ignore `/srv/app` and `/srv/backups`.
2. [#7](https://github.com/DocCyblade/abssctl/issues/7) — `instance list` and `create` must not say running on 203/EXEC.
3. [#8](https://github.com/DocCyblade/abssctl/issues/8) — `doctor --fix` output must match the repairs it applied.

## Prompt for the first issue

```text
Fix GitHub issue #6. gh issue view 6 --comments.

Read @AGENTS.md, @docs/CURSOR_WORKFLOW.md, @docs/GITHUB_WORKFLOW.md,
and @docs/adrs/ADR-034-repo-management-and-branching.md.
Read @docs/TESTING_ACCESS.md when the task touches a host.
Branch off tip of dev-beta1-redux (e.g. issue/6-discovery-ignore-srv-app).
PR base: dev-beta1-redux. Do not PR to main. Do not tag. Do not push unless I ask.
Gate: make quick-tests. Docs changes also run make docs.
```
