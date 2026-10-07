# Next steps

Active milestone: `v0.2.0a1`

GitHub is the queue. This file is a snapshot. If it disagrees with the Ready column, rewrite it from GitHub. Nothing is in Ready yet, so these are the first three Backlog issues on `v0.2.0a1`.

1. [#2](https://github.com/DocCyblade/abssctl/issues/2) — Write the functional test procedure. The checklist for guest passes and for each Dev final review.
2. [#3](https://github.com/DocCyblade/abssctl/issues/3) — Install `abssctl-node-run` so new units do not exit `203/EXEC`.
3. [#4](https://github.com/DocCyblade/abssctl/issues/4) — Store nginx vhosts on disk, not under `/run`.

## Prompt for the first issue

```text
Fix GitHub issue #2. gh issue view 2 --comments.

Read @AGENTS.md and @docs/CURSOR_WORKFLOW.md.
Read @docs/TESTING_ACCESS.md, @docs/GITHUB_WORKFLOW.md, and @docs/source/guides/mitp.rst.
Branch: dev-beta1-redux. Do not tag. Do not push unless I ask.
Gate: make quick-tests. Docs changes also run make docs.
Write the procedure only. No product code changes.
```
