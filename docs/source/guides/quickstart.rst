Quick Start
===========

.. note::
   This guide covers the developer preview workflow during the Alpha foundations
   milestone. Core infrastructure (configuration, registry access, logging,
   locking, template rendering) is in place while mutating commands and provider
   integrations continue to expand.

Environment Setup
-----------------

1. Install Python 3.11 or newer on your workstation.
2. Create a Python 3.11 virtual environment stored in ``.venv`` with a prompt label ``dev`` and activate it::

      python3.11 -m venv .venv --prompt dev
      source .venv/bin/activate

3. Install the package in editable mode together with development extras::

      pip install -e .[dev]

4. Verify the CLI skeleton and read-only commands::

      abssctl --help
      abssctl --version
      abssctl config show
      abssctl version list --json
      abssctl instance list --json

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

- Remaining Alpha work finalises provider behaviour (systemd/nginx) and
  wires version lifecycle commands to real installers.
- Beta adds health checks, support bundles, and deeper template-driven
  provisioning and reconciliation.
- Release Candidate focuses on documentation polish and large-scale testing on
  TurnKey Linux appliances.
