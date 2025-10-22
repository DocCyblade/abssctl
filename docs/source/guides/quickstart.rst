Quick Start
===========

.. note::
   This guide covers the developer preview workflow during the Alpha
   core-features milestone. All lifecycle commands are available, but doctor
   probes, restore automation, and support bundles are still under active
   development.

Environment Setup
-----------------

1. Install Python 3.11 or newer on your workstation.
2. Create a Python 3.11 virtual environment stored in ``.venv`` with a prompt label ``dev`` and activate it::

      python3.11 -m venv .venv --prompt dev
      source .venv/bin/activate

3. Install the package in editable mode together with development extras::

      pip install -e .[dev]

4. Exercise the CLI end-to-end::

      abssctl --help
      abssctl --version
      abssctl config show
      abssctl version list --json
      abssctl instance list --json
      abssctl ports list --json
      abssctl instance create demo --no-start --port 6000
      abssctl instance delete demo --purge-data --yes --no-backup

Quality Gates
-------------

Run the default checks locally before opening a pull request::

   ruff check src tests
   mypy src
   pytest

You can run the same trio via ``make quick-tests`` which uses the managed
development virtual environment. Additional convenience targets include
``make docs`` for rebuilding Sphinx HTML and ``make dist`` for the full
lint/type/test/build pipeline.

What Comes Next?
----------------

- Remaining Alpha polish focuses on deeper diagnostics, lifecycle logging
  refinements, and backup restore scaffolding.
- Beta adds TLS workflows, doctor health checks, support bundle assembly, and
  restore/reconcile automation.
- Release Candidate focuses on documentation polish and large-scale testing on
  TurnKey Linux appliances.
