# Cursor / AI workflow for abssctl

Version: 2.0.0
Audience: core devs, using Cursor Agent on this repo
Companion: [`GITHUB_WORKFLOW.md`](GITHUB_WORKFLOW.md), [`PATH_FORWARD.md`](PATH_FORWARD.md), [`NEXT_STEPS.md`](NEXT_STEPS.md)

## 1. Why this exists

Earlier chats bootstrapped from `ops/ai-directives.txt` and appended `ops/session-log.txt` every turn. Those files are an archive. GitHub Issues are the queue. Cursor keeps a thread per chat.

## 2. Source of truth

| Need | File | How to use in chat |
|---|---|---|
| The one task | GitHub issue | `gh issue view N` — one chat, one issue |
| Where the versions are going | `docs/PATH_FORWARD.md` | Milestone story. Not the checkbox list. |
| What to do after time away | `docs/NEXT_STEPS.md` | Next three issues and a prompt for the first |
| This workflow | `docs/CURSOR_WORKFLOW.md` | `@` once per new chat if needed |
| Issues, board, tags | `docs/GITHUB_WORKFLOW.md` | `@` when filing, releasing, or catching up |
| Product spec | `docs/requirements/abssctl-app-specs.txt` | Cite it; `@` only the section you are changing |
| One decision | matching file under `docs/adrs/` | `@` that ADR |
| Which VMs an agent may use | `docs/TESTING_ACCESS.md` | `@` when the task touches a host |
| Always-on brief | `AGENTS.md` | Applied automatically; keep it short |

Never paste the spec or a pile of ADRs into the prompt.

## 3. When to start a new chat

Start a new chat when any of these is true:

1. You switch GitHub issues.
2. The current chat finished its issue and `make quick-tests` is green.
3. The thread is long and the agent is re-asking basics.
4. You change modes: plan, implement, debug a live appliance, or cut a release.

Stay in the same chat while iterating the same issue (test failed, fix, re-run `make quick-tests`).

## 4. Chat types

| Type | Mode | Attach |
|---|---|---|
| Implement | Agent | The issue plus the module under change |
| Docs-only | Agent | The issue plus the few docs being edited |
| Release | Agent | `docs/GITHUB_WORKFLOW.md` only. New chat. |
| Ask | Ask | Nothing, or one file |
| Appliance debug | Agent | One instance’s logs plus the one provider |

## 5. Handoff template

```text
Fix GitHub issue #N. gh issue view N --comments.

Read @AGENTS.md and @docs/CURSOR_WORKFLOW.md.
Branch: dev-beta1-redux. Do not tag. Do not push unless I ask.
Gate: make quick-tests. Docs changes also run make docs.
Spec: docs/requirements/abssctl-app-specs.txt — cite, do not paste.
```

When the issue is done, rewrite `docs/NEXT_STEPS.md` from the Ready column. If Ready has fewer than three issues, fill from Backlog in the same milestone. Then stop. A core dev opens a new chat for the next issue.

## 6. Definition of done

1. The change matches the GitHub issue.
2. `make quick-tests` passes. If Sphinx docs changed, `make docs` passes.
3. `docs/NEXT_STEPS.md` matches GitHub. If they disagree, GitHub wins.
4. Commit, push, and open a pull request only when a core dev asks. The pull request body contains `Fixes #N`.
5. Do not file a new issue or push a tag unless this chat was asked to, and only after the core dev has reviewed the draft.
