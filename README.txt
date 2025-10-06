Project: Actual Budget Multi‑Instance Sync Server Admin CLI
CLI executable: abssctl (Actual Budget Sync Server ConTroL)

Status: Planning

App Specs Doc will be located at doc/requirements/abssctl-app-specs.txt once approved and finalized

Production builds in main and tagged
Development builds in dev and tagged
Working sessions are sub branches


Roadmap Phases:

Phases

Planning — Finalize abssctl-app-specs.txt spec document

Pre-Alpha — Repo Bootstrap (Pre-Alpha)
- Create scaffold layout, add pyproject.toml, .gitignore, docs skeleton, CI with lint/test.

Alpha Builds — Foundations
- CLI skeleton, config loader, logging, state/lock, template engine, read‑only commands, JSON output plumbing. Setup PiPy project, Github CI auto publish to PyPi via tags to dev

Beta Releases — Core Features
- Version ops (list/install/switch), instance lifecycle, systemd/nginx providers, doctor basics. Once Beta builds are pushed to PyPi all updates need to be non-distructive or have hooks to update existing installs.

Release Candidate — Quality & Docs (RC)
- Support bundle, robust errors, man pages & completion, full docs & examples, CI integration tests on TKL VM. Setup githib CI auto publish to PyPi

Release — v1.0.0 (RC → GA)
- RC burn‑in on a clean TKL image across 3 Actual versions; GA on green pipeline + docs sign‑off.
