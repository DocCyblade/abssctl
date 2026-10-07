---
name: release
description: >-
  Cuts an abssctl git tag for TestPyPI, production PyPI, or GitHub Pages.
  Use when a core dev asks to release, tag, publish, TestPyPI, PyPI, or
  update the docs site. Shows the exact tag and waits for the word push.
---

# Release

Read `docs/GITHUB_WORKFLOW.md` and `src/abssctl/__init__.py`. Do not create a tag or push until the core dev in this chat says push.

## Before any tag

1. Read `__version__`. The tag's PEP 440 part must match it. Do not invent a version.
2. Say which channel they asked for. If they did not name one, ask. Do not guess production.
3. Reply with the exact tag, the branch it must be on, and the workflow file. Stop.

| Channel | Tag | Branch | Workflow |
|---|---|---|---|
| TestPyPI | `v<version>-dev` | `dev-beta1-redux` is allowed | `.github/workflows/publish-dev.yml` |
| Production PyPI | `v<version>` with no `-dev` | `main` only | `.github/workflows/publish-release.yml` |
| GitHub Pages | `docs-v<version>` | `main` only | `.github/workflows/docs-build.yml` |

Refuse a production tag or a docs tag when the current branch is not `main`. Refuse a second tag in the same request. A `v<version>` tag does not update https://doccyblade.github.io/abssctl/. Say that when they ask for a production release.

## After they say push

1. Confirm the tag string one last time in the same reply as the push.
2. Create that one tag on the allowed branch and push only that tag.
3. Watch the GitHub Actions run and report the URL.
4. Do not approve the `publish-release` environment. Tell the core dev that approval is in GitHub.

Do not change version files, workflow files, or product code in this chat unless they ask for that as a separate step before the tag.
