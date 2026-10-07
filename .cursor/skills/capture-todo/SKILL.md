---
name: capture-todo
description: >-
  Drafts a GitHub issue for work that is outside the current abssctl chat.
  Use when a core dev says remember this, add a todo, file that, or when
  the chat hits a bug or follow-up that is not the open issue. Shows the
  draft and waits for them to say post it.
---

# Capture a todo

Out-of-scope work becomes a GitHub issue on `DocCyblade/abssctl`. It does not go in the chat, in `ops/`, or in `docs/PATH_FORWARD.md`.

## When to start

- A core dev says "remember this", "add a todo", or "file that".
- The work in front of you is outside the current issue.

## Draft first

Show the draft in the chat before any `gh` write. Include:

- Title
- Body (what was seen, what to do next, evidence path if one exists)
- Labels: `todo` for a reminder, `bug` or `docs` or `release` when the kind is already clear
- Milestone, or "none" when you do not know which version it belongs to

That draft is the text that would be posted. Do not run `gh issue create` yet.

If they change the wording, show the revised draft and wait again. Post only after they say to post it.

## After they say post

1. Create the issue with the draft they accepted.
2. Reply with the issue number and URL.
3. Stay on the original task. Do not implement the new issue in this chat.
4. Do not rewrite `docs/NEXT_STEPS.md` for a new Backlog issue. Rewrite it only when the new issue is one of the next three Ready items.

Do not include private keys, API tokens, or certificate bodies. Do not move project board cards.
