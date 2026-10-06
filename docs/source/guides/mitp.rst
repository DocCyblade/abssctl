=========================================
Manual Integration Test Protocol (MITP)
=========================================

Run this checklist on a TurnKey Linux Node.js appliance (or a Debian host with
systemd and nginx) before promoting ``dev-beta1-redux``. Record the Actual
version, Node version, and pass/fail in
``docs/requirements/node-compat.yaml`` (``tested_at`` / ``notes``) and
regenerate the packaged copy with ``python3 tools/list-sync-versions.py``.

Preconditions
=============

- Root or sudo.
- ``python3.11``, ``make quick-tests`` already green on the commit under test.
- ``nginx`` and ``systemd`` installed.
- ``n`` available so ``abssctl node ensure`` can install Node 22+.
- ``npm`` >= 10.9.9. Actual 26.6.0 does not install on an older npm.
- Empty ``/srv/app`` and no leftover ``abssctl-*`` units from a prior attempt.

Checklist
=========

1. **Install the CLI.** ``pip install`` the wheel under test, or ``pip install -e .``
   on a checkout of the commit. ``abssctl --version`` prints the package version.
2. **Bootstrap.** ``abssctl system init --defaults --yes``. Service user and
   ``/srv``, ``/var/lib/abssctl``, and ``/var/log/abssctl`` exist.
3. **Node.** ``abssctl node ensure --yes``. ``node --version`` via the wrapper
   is 22 or newer.
4. **Server install.** ``abssctl version install 26.10.0``.
   ``/srv/app/v26.10.0/.../build/bin/actual-server.js`` exists.
   ``abssctl version switch 26.10.0`` points ``current`` at that tree.
5. **Instance.** ``abssctl instance create mitp --port 6000``.
   ``systemctl status abssctl-mitp`` is active. ``abssctl instance status mitp``
   agrees.
6. **nginx.** The vhost answers on the instance domain (or the hosts-file
   name) and proxies to ``127.0.0.1:6000``. The Actual UI HTML is returned.
7. **Upgrade / rollback.** Install the previous supported Actual release,
   ``abssctl instance set-version`` to it, confirm the UI still loads, then
   switch back to 26.10.0.
8. **Backup.** ``abssctl backup create mitp --yes``. ``abssctl backup verify``
   matches the checksum. ``abssctl backup restore`` on a stopped instance
   brings the same UI back.
9. **TLS.** ``abssctl tls verify`` reports the configured certificate.
   With TLS enabled, nginx listens on the HTTPS port.
10. **Doctor.** ``abssctl doctor --json`` exits 0 when the instance is healthy.
    ``abssctl doctor --fix --dry-run`` prints a plan and changes nothing.
11. **Support bundle.** ``abssctl support-bundle --out /tmp`` writes an archive
    whose manifest has no raw secrets (default redaction).
12. **Cleanup.** ``abssctl instance delete mitp --yes`` removes the unit, the
    site, and the registry row.

Fail the run if any step exits non-zero, if the UI does not load, or if
``doctor`` reports a red probe that ``--fix`` cannot explain.
