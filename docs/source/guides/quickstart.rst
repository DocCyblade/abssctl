Quick Start
===========

.. note::
   This guide describes the developer preview workflow while the CLI is in
   Pre-Alpha. Production-ready steps arrive alongside the Alpha milestone once
   commands manipulate real system resources.

Environment Setup
-----------------

1. Install Python 3.11 or newer on your workstation.
2. Create a Python 3.11 virtual environment stored in ``.venv`` with a prompt label ``dev`` and activate it::

      python3.11 -m venv .venv --prompt dev
      source .venv/bin/activate

3. Install the package in editable mode together with development extras::

      pip install -e .[dev]

4. Verify the CLI skeleton::

      abssctl --help
      abssctl --version

Quality Gates
-------------

Run the default checks locally before opening a pull request::

   ruff check src tests
   mypy src
   pytest

What Comes Next?
----------------

- Alpha introduces real subcommands for managing Actual Sync Server versions
  and instances.
- Beta adds health checks, support bundles, and template rendering.
- Release Candidate focuses on documentation polish and large-scale testing on
  TurnKey Linux appliances.
