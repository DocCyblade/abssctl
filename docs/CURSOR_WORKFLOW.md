# Cursor / AI workflow for abssctl

Version: 1.0.0
Audience: Ken, using Cursor Agent on this repo
Companion: [`PATH_FORWARD.md`](PATH_FORWARD.md) (the living TODO)

## 1. Why this exists

Earlier chats bootstrapped from `ops/ai-directives.txt` (the "Albert" ritual) and appended `ops/session-log.txt` every turn. That file is an archive. Cursor already keeps a thread per chat, and `@` replaces `ops/ai-large-message.txt`.

## 2. Source of truth (open these, do not paste them whole)

| Need | File | How to use in chat |
|---|---|---|
| Where we are / what’s next | `docs/PATH_FORWARD.md` | `@PATH_FORWARD.md` — checkboxes are the TODO list |
| This workflow | `docs/CURSOR_WORKFLOW.md` | `@` once per new chat if needed |
| Product spec | `docs/requirements/abssctl-app-specs.txt` | Cite it; `@` only the section you are changing |
| One decision | matching file under `docs/adrs/` | `@` that ADR |
| Milestone list | `docs/roadmap.rst` | `@` when the slice changes the roadmap |
| Always-on brief | `AGENTS.md` | Applied automatically; keep it short |

Never paste the spec or a pile of ADRs into the prompt.

## 3. When to start a new chat

Start a new chat when any of these is true:

1. You switch PATH_FORWARD steps (compatibility matrix → live install is a new chat).
2. The current chat finished its slice and `make quick-tests` is green.
3. The thread is long and the agent is re-asking basics.
4. You change modes: plan, implement, or debug a live appliance.

Stay in the same chat while iterating the same slice (test failed → fix → re-run `make quick-tests`).

## 4. Chat types

| Type | Mode | Attach |
|---|---|---|
| Plan | Plan, then Agent | PATH_FORWARD + the one ADR or spec section |
| Implement | Agent | PATH_FORWARD + the module under change |
| Docs-only | Agent | PATH_FORWARD + the few docs being edited |
| Ask | Ask | Nothing, or one file |
| Appliance debug | Agent | One instance’s logs + the one provider — not the whole tree |

## 5. Handoff template

```text
abssctl handoff. Read @docs/PATH_FORWARD.md and @docs/CURSOR_WORKFLOW.md.

Repo: Python package src/abssctl/, CLI abssctl. Gate: make quick-tests.
Spec: docs/requirements/abssctl-app-specs.txt — cite, do not paste.
Installs @actual-app/sync-server. Actual 25.11+ needs Node >= 22.

Current step: <PATH_FORWARD id>
Task: <one sentence>
Done so far: <bullets or "see commit <hash>">
Do next: <bullets from PATH_FORWARD>
Constraints: commit only if I ask; do not redesign providers/registry/commands; keep make quick-tests green.

Attach:
@<the module or doc for this slice>
```

When a step finishes, update PATH_FORWARD checkboxes in that chat, then open a new chat for the next step.

## 6. Definition of done

1. The slice matches the PATH_FORWARD boxes you claimed.
2. `make quick-tests` passes. If docs changed, `make docs` passes.
3. PATH_FORWARD checkboxes for that slice are updated.
4. Commit only when asked.
