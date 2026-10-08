# GitHub workflow for abssctl

Version: 1.1.0
Audience: core devs
Companion: [`PATH_FORWARD.md`](PATH_FORWARD.md) (milestone story), [`NEXT_STEPS.md`](NEXT_STEPS.md) (catch-up snapshot), [`FUNCTIONAL_TESTS.md`](FUNCTIONAL_TESTS.md) (guest passes and Dev final review), [`adrs/ADR-034-repo-management-and-branching.md`](adrs/ADR-034-repo-management-and-branching.md) (branching)

GitHub Issues on `DocCyblade/abssctl` are the queue. PATH_FORWARD explains the milestones. NEXT_STEPS is a snapshot of the next three issues and a prompt for the first. If NEXT_STEPS and GitHub disagree, GitHub wins and the agent rewrites NEXT_STEPS.

## Branching and pull requests

ADR-034 is the policy. Until the `v0.2.0a1` clean-`dev` squash ([#22](https://github.com/DocCyblade/abssctl/issues/22)):

| Rule | Practice |
|---|---|
| Active tip | `dev-beta1-redux` |
| Issue branches | Off the tip of that milestone branch (e.g. `issue/N-<slug>`) |
| PR base | The same milestone branch. Never a casual PR to `main`. |
| Merge into milestone | Prefer squash |
| Into cleaned `dev` | Only at slice or milestone boundaries (#22) |
| Into `main` | Only via `release/*`, `hotfix/*`, or `docfix/*` |

## Day-to-day loop

1. A test failure becomes an issue. Title is the bug. Body has what was run, the exit code, and an evidence path if one exists. No keys, no tokens. Labels: `bug`, `docs`, `release`, or `todo`. The milestone is the version target.
2. A core dev reviews it. If it is wrong, close it. If it is right, it stays in the milestone and on the board in Backlog until a core dev moves it to Ready. Ready is the signal to start work. No agent starts from an issue that is still in Backlog.
3. A core dev opens a new Agent chat and pastes the handoff from [`CURSOR_WORKFLOW.md`](CURSOR_WORKFLOW.md). One chat, one issue.
4. The agent branches off `dev-beta1-redux`, edits, runs `make quick-tests` (and `make docs` when Sphinx docs change), and stops. Commit, push, and a pull request only when the core dev in that chat asks. The PR base is `dev-beta1-redux`. The body contains `Fixes #N`. Prefer squash-merge into the milestone branch.
5. A core dev merges. GitHub closes the issue.
6. That chat rewrites [`NEXT_STEPS.md`](NEXT_STEPS.md) from the board before it stops.

## Board

One GitHub Project named `abssctl`, grouped by milestone. Columns: Backlog, Ready, In Progress, In review, Done.

- Backlog is the inbox. Accepted work that is not next lives here.
- Ready means a core dev reviewed it and it is next. Opening a chat moves it to In Progress.
- In Progress means a chat is working on it.
- In review means a pull request is open. Done means it merged.

Core devs move the cards. The agent does not.

## Milestones

| Title | Meaning |
|---|---|
| `v0.2.0a1` | A fresh TurnKey guest can `system init`, `node ensure`, `version install`, and `instance create`, and the unit stays up. Doctor is not red because of abssctl’s own directories. |
| `v1.0.0rc1` | The MITP checklist has been run. Operator docs match the CLI. |
| `v1.0.0` | Current Actual release plus the ten before it, then GA. Production PyPI stays `0.1.3a1` until then. |

Each milestone ends with an issue titled `Dev final review: <milestone>`. Core devs own that issue. It is a full manual pass using [`FUNCTIONAL_TESTS.md`](FUNCTIONAL_TESTS.md). It stays in Backlog until the other issues in the milestone are Done. An agent does not implement it and does not close it. A failure during the pass becomes a new Backlog issue. The review issue closes only when a core dev says the pass succeeded.

Bounded guest passes (agents or core devs) also follow [`FUNCTIONAL_TESTS.md`](FUNCTIONAL_TESTS.md). File each failure as a Backlog issue with the milestone a core dev names.

## Remembering work that is not this chat

A side note does not go in the chat, in `ops/`, or in PATH_FORWARD. It becomes an issue, and only after a core dev has reviewed the draft.

The capture skill is [`.cursor/skills/capture-todo/SKILL.md`](../.cursor/skills/capture-todo/SKILL.md). It starts when a core dev says "remember this", "add a todo", or "file that", or when the agent notices work outside the current issue. The agent shows the title, body, labels, and milestone. That text is what would be posted. It does not run `gh issue create` until a core dev says to post it. The current chat does not implement the new issue.

## Release

Open a new Agent chat. Do not reuse the chat that fixed an issue. The release skill is [`.cursor/skills/release/SKILL.md`](../.cursor/skills/release/SKILL.md).

1. Say which channel. Examples: "Cut a TestPyPI tag for the current version." "Tag main for production PyPI." "Publish the docs site."
2. The agent reads `__version__` in `src/abssctl/__init__.py` and replies with the exact tag, the branch it must be on, and the workflow that will run. It does not create the tag.
3. The core dev checks that tag. If it is wrong, they say so. If it is right, they say push.
4. Only that word authorizes `git tag` and `git push` of that one tag. The skill refuses a production tag from `dev-beta1-redux`, and it refuses a second tag in the same breath.
5. GitHub Actions uploads. The agent reports the URL. It does not approve the `publish-release` environment. A core dev does that in GitHub when the tag is a production release.

| Channel | Tag | Branch | Workflow |
|---|---|---|---|
| TestPyPI | `v<version>-dev` | `dev-beta1-redux` is allowed | [`.github/workflows/publish-dev.yml`](../.github/workflows/publish-dev.yml) |
| Production PyPI | `v<version>` with no `-dev` | `main` only. `origin/main` must be an ancestor of the tag. | [`.github/workflows/publish-release.yml`](../.github/workflows/publish-release.yml), environment `publish-release` |
| GitHub Pages | `docs-v<version>` | `main` only | [`.github/workflows/docs-build.yml`](../.github/workflows/docs-build.yml) deploys https://doccyblade.github.io/abssctl/ |

The package version and the tag’s PEP 440 part must match. CI checks this with `tools/validate_tag_version.py`. ADR-033 is the policy.

`docs-build.yml` also triggers on `v*.*.*`, then the validate step exits because the tag is not `docs-v*`. A normal release tag does not update the site today. Publishing the site is a separate `docs-v*` tag on `main`.
