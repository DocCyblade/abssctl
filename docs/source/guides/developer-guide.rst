Developer Guide (WIP)
=====================

This guide captures engineering processes and expands as the project marches
through Alpha and beyond.

Repository Standards
--------------------

- Follow the architecture decisions recorded in ``docs/adrs``.
- Use type hints and keep ``mypy`` clean under the ``strict`` settings defined
  in ``pyproject.toml``.
- Write tests alongside features; prefer ``pytest`` parametrisation to cover
  edge cases.
- Keep documentation updates in the same change set so Sphinx builds stay
  accurate.

Coding Workflow
---------------

1. Fork the repository or create a feature branch from ``dev``.
2. Create a Python 3.11 virtual environment stored in ``.venv`` with a prompt label ``dev`` and activate it::

      python3.11 -m venv .venv --prompt dev
      source .venv/bin/activate

3. Run ``pip install -e .[dev]`` to install dependencies. This editable install
   ensures ``abssctl`` is importable in tests and CLI executions without
   tweaking ``PYTHONPATH``.
4. Implement your changes following the roadmap priorities.
5. Run linting, typing, tests, and Sphinx builds::

      ruff check src tests
      mypy src
      pytest
      sphinx-build -b html docs/source docs/_build/html

6. Open a pull request targeting ``dev`` and request review.

Testing Registry Data
---------------------

- Commands such as ``version list`` and ``instance list`` read from
  ``<state_dir>/registry/versions.yml`` and ``instances.yml``. During testing,
  create these files under a temporary ``state_dir`` (see the CLI tests for an
  example helper) to simulate installed versions or provisioned instances.
- JSON flags (``--json``) make assertions easier when validating command
  output in automated tests.
- ``version list --remote`` uses the npm CLI when available. During testing you
  can avoid network access by setting ``ABSSCTL_VERSIONS_CACHE`` to a JSON file
  containing an array of version strings or by exporting ``ABSSCTL_SKIP_NPM=1``.

Open Questions
--------------

- Release engineering automation will be defined once the PyPI project name is
  secured.
- Integration test strategy on TurnKey Linux appliances is captured in
  ``docs/adrs/ADR-030-ci-integration-tests.md``.
