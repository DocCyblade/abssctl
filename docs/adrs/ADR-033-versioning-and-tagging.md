# ADR 0033: Versioning & Tag Naming Strategy

- **Date:** 2025-10-07
- **Status:** Accepted
- **Authors:** DocCyblade, Codex AI Partner
- **Deciders:** abssctl maintainers
- **Consulted:** abssctl collaborators
- **Tags:** release-engineering, ci, packaging

## Context

The project currently mixes several conventions for package versions and Git
tags:

- Python packaging metadata (``src/abssctl/__init__.py``) uses [PEP 440](https://peps.python.org/pep-0440/)
  identifiers such as ``0.1.0a4``.
- Dev/TestPyPI automation expects Git tags shaped like ``v*.*.*-dev``.
- Documentation snapshots use ``docs-v<version>`` tags.

Without an agreed policy we risk mismatched version numbers, confusing tag
names, repeated uploads to PyPI/TestPyPI, and fragile CI triggers (manual
approvals, release automation, docs publishing).

We need a single strategy that:

1. Keeps package versions compliant with PEP 440 and SemVer expectations.
2. Makes Git tags unambiguous for humans and automation (CI, release notes,
   docs publishing).
3. Supports multiple release channels (dev/TestPyPI, pre-release, GA).

## Options Considered

- **A. Tag == version (``v<pep440>`` everywhere).**  
  Simplifies mapping, but offers no separate namespace for TestPyPI/dev
  artifacts and complicates doc-only tags.

- **B. Channel-specific prefixes (``dev/<version>``, ``docs/<version>``).**  
  Distinct namespaces but deviates from industry norms, makes automation
  globbing harder, and pollutes `git tag` listings.

- **C. PEP 440 for package metadata + ``v``-prefixed tags with channel suffixes.**  
  Use ``v<pep440>`` for release-quality tags, ``v<pep440>-dev`` for TestPyPI
  promotion, and ``docs-v<pep440>`` for Sphinx snapshots.

## Decision

Adopt option **C** with the following rules:

### Package version (PEP 440 source of truth)

- ``src/abssctl/__init__.py`` defines ``__version__``; every tag must point to a
  commit whose version matches the tag’s PEP 440 payload.
- Version progression follows SemVer semantics:
  - GA releases: ``MAJOR.MINOR.PATCH`` (e.g., ``1.0.0``).
  - Pre-release cadence: ``aN`` (alpha), ``bN`` (beta), ``rcN`` (release
    candidate) appended to the GA anchor (e.g., ``1.0.0a1``).
  - Optional dev builds rely on ``.devN`` only for local experiments that are
    **not** tagged/published.

### Git tagging scheme

- **Release / Pre-release tags:** ``v<version>`` (e.g., ``v1.0.0``,
  ``v1.0.0rc1``, ``v0.2.0a3``). These drive production PyPI publishes and the
  changelog.
- **Dev/TestPyPI tags:** ``v<version>-dev``. The ``<version>`` fragment must
  match the PEP 440 version in ``__version__``. Each dev publish increments
  the underlying pre-release identifier (``aN``/``bN``/``rcN``) to avoid
  duplicate uploads.
- **Docs tags:** ``docs-v<version>`` for Sphinx-only rebuilds and publishing.
  The referenced commit must share the same ``__version__`` value.

### CI / Automation implications

- ``publish-dev.yml`` listens for ``v*.*.*-dev`` tags and pushes wheels/sdists
  to TestPyPI using trusted publishing.
- Future release workflows will watch ``v*`` (no ``-dev`` suffix) for PyPI GA
  promotion.
- Documentation workflows continue to monitor ``docs-v*``.

## Consequences

- **Consistency:** Humans and automation can infer the package version from the
  tag, reducing confusion during incident response and release notes drafting.
- **TestPyPI discipline:** Every dev publish requires bumping the pre-release
  counter, guaranteeing unique uploads and clean rollback.
- **Docs clarity:** Documentation tags remain separate yet clearly tied to the
  package version.
- **Migration cost:** Existing tags remain but future tags must follow this
  policy. CI globs or environment rules referencing earlier patterns might need
  minor adjustments.

## Alternatives Considered (Details)

- **Option A** forces us to reuse the same tag namespace for dev and GA and
  prevents dry-run/dev-only releases.
- **Option B** introduces unfamiliar naming (``dev/1.2.3``) that complicates
  tooling and user expectation.

## Related

- Supersedes: N/A
- Superseded by: N/A
- References: `.github/workflows/publish-dev.yml`, `pyproject.toml`,
  `src/abssctl/__init__.py`, TestPyPI trusted publishing setup,
  [PEP 440](https://peps.python.org/pep-0440/).
