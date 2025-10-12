# ADR 034: Repository Management & Branching Workflow

- **Date:** 2025-10-08
- **Status:** Proposed
- **Authors:** Codex (with guidance from DocCyblade)
- **Deciders:** Project maintainers
- **Consulted:** Release engineering reviewers
- **Tags:** workflow, branching, releases, documentation

## Context

The project now has automation for trusted publishing (ADR-033), milestone
planning in the session log, and growing contributor activity. We need a
documented branching and release workflow that aligns with our CI/CD pipelines,
tag policy, and expectations around documentation and hotfixes.

Requirements gathered from recent sessions:

- Use `dev` as the integration branch with milestone-specific branches (e.g.
  `dev-alpha4`) that collect work before being squashed back into `dev`.
- Produce release artifacts via tagged commits that pass through GitHub Actions
  environments (`publish-dev`, `publish-release`), using the tag formats from
  ADR-033.
- Keep documentation updates in the same change set when possible, but allow
  follow-up doc-only fixes with a clear versioning story.
- Ensure hotfixes and docfixes do not drift from the canonical history and that
  version/changelog bumps propagate back into `dev`.

## Options Considered

- **A. Ad-hoc branching per contributor.** Allow developers to pick any base
  (e.g., `main`, `dev`, or older milestone branches) and merge as needed.
- **B. One long-lived integration branch (`dev`) with feature branches merged
  directly, no milestone branches.**
- **C. Structured milestone branches off `dev`, release branches off `dev` for
  stabilization, plus hotfix/docfix workflows branching from `main`.**

## Decision

Adopt **Option C** with the following conventions:

1. **Long-lived branches**
   - `main`: production history; every tag intended for PyPI or docs publishing
     is created on `main`.
   - `dev`: next-release integration branch; all milestone work merges here
     before promotion.

2. **Milestone branches**
   - Named `dev-<label>` where `<label>` reflects the milestone phase, e.g.
     `dev-alpha4`, `dev-beta1`, `dev-1.2.0a1`. Teams may optionally use sprint
     identifiers (`dev-sprint-2025w42`) after GA, but the branch MUST originate
     from `dev`.
   - Contributors branch from the active milestone branch (e.g.,
     `feature/<slug>` → `dev-alpha4`) and merge back via PR.
   - Milestone branches are periodically rebased onto `dev` to minimize merge
     debt.
   - When the milestone is ready, squash-merge `dev-<label>` back into `dev`
     with a comprehensive commit message; then delete the milestone branch.

3. **Release preparation**
   - Cut `release/<version>` from `dev` once the milestone is feature-complete.
   - Only stabilization work (bug fixes, version bumps, changelog updates)
     happens on the release branch.
   - Merge `release/<version>` into `main` using a merge commit; tag the merge
     `v<version>` (e.g., `v1.4.0`) to trigger the `publish-release` workflow.
   - Merge the same `release/<version>` branch back into `dev` so changes such
     as version bumps and docs updates stay in sync.

4. **Trusted publishing alignment**
   - Dev snapshots (`v*.*.*-dev`) are tagged from `dev` once milestone commits
     land, leveraging the `publish-dev` environment.
   - Docs releases (`docs-v*`) follow ADR-033 and should reference the most
     recent package version published from `main`.

5. **Hotfix workflow**
   - Branch `hotfix/<version>` from `main`.
   - Apply the fix, update changelog/version, and merge back to `main` (merge
     commit or fast-forward). Tag `v<version>` (e.g., `v1.4.1`).
   - Merge the hotfix back into `dev` (fast-forward or merge) to keep branches
     aligned.

6. **Docfix workflow**
   - Branch `docfix/<version>` from `main` for documentation-only corrections
     after a release.
   - Apply updates, run `make docs`/`make dist` checks, and merge back to `main`.
   - Tag the result with a post-release identifier (`v<version>.postN`) that
     satisfies PEP 440; run the release workflow so PyPI/docs stay in sync.
   - Merge the docfix branch into `dev` as well.

7. **Merge hygiene**
   - All PRs must pass `make quick-tests` locally and the CI `make dist` job.
   - Squash commits are preferred when merging feature branches into milestone
     branches; release/hotfix/docfix merges retain history (no squashing).

## Consequences

- Provides a predictable flow from feature work → milestone integration → release
  tagging → post-release maintenance.
- Preserves CI expectations; the tag formats already enforced by ADR-033 continue
  to work without modification.
- Contributors have clear instructions on which branch to target and how to
  handle documentation updates before/after release.
- Requires maintainers to diligently merge hotfix/docfix branches back into
  `dev` to avoid version drift.
- Introduces more branch types (`release/`, `hotfix/`, `docfix/`), so repository
  tooling (e.g., branch protection rules) must be updated accordingly.

## Alternatives Considered (Details)

- **Ad-hoc branching:** Discarded because it leads to ambiguous release history
  and complicates trusted publishing (tags might not align with automated
  workflows).
- **No milestone branches:** Rejected for now; the team prefers a staging area
  where larger milestones can settle before merging to `dev`.

## Related

- Supersedes: None
- Superseded by: None
- References:
  - ADR-009 system architecture
  - ADR-033 versioning & tagging policy
  - Session log entry: 2025-10-08 Alpha 4 Session
