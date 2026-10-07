# Testing access

Version: 1.0.0
Date: 2026-10-06
Audience: Cursor agents working in this repo

This file is the list of guests an agent may use. Secrets stay on the workstation. Do not copy token secrets, private keys, or passwords into the repo or into chat.

## How to reach a guest

SSH config on the workstation already has one `Host` per guest (`test-nodeapp01`, `test-nodeapp02`, `test-nodeapp03`). Each uses `User root` and `IdentityFile ~/.ssh/id_ed25519.cursors.key`.

```bash
ssh test-nodeapp01
```

Proxmox API credentials are in `~/.config/proxmox/cursor-ai.env` (`PROXMOX_URL`, `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET`). The API is `https://10.111.111.9:8006`. All three guests are on node `node-2hpza`, pool `AI-Testing`.

The token can audit, configure, start, stop, snapshot, and roll back these three VMIDs. It cannot see other VMs. It does not have clone. Do not delete snapshots. Roll a guest back only when the task says to.

## Power

Snapshots were taken while the guest was powered off. The live VM is often stopped. After a rollback, wait 30–45 seconds, then start the VM, then SSH.

Start with `POST /api2/json/nodes/node-2hpza/qemu/<vmid>/status/start`.

Checked 2026-10-06: each guest started, accepted root SSH, and was shut down again. They were stopped at the end of that check.

## Guests

Use the test FQDNs below. Production names (the `*-budgetapp.krajr.net` set in `tmp-personal-server/000-manual-install.sh`) do not work for live testing. Do not run that production script on these guests.

| | test-nodeapp01 | test-nodeapp02 | test-nodeapp03 |
|---|---|---|---|
| VMID | 8011901 | 8010902 | 8010903 |
| IP | 10.10.7.99 | 10.10.7.98 | 10.10.7.97 |
| MAC | BC:24:11:E4:B3:CA | BC:24:11:E4:B3:CB | BC:24:11:E4:B3:CC |
| SSH host | `test-nodeapp01` | `test-nodeapp02` | `test-nodeapp03` |
| FQDN | `test-nodeapp01.internal.servers.krajr.net` | `test-nodeapp02.internal.servers.krajr.net` | `test-nodeapp03.internal.servers.krajr.net` |
| Test FQDNs (CNAME to the FQDN) | `test1a-abssctl-test.krajr.net`, `test2a-abssctl-test.krajr.net`, `test3a-abssctl-test.krajr.net` | `test1b-abssctl-test.krajr.net`, `test2b-abssctl-test.krajr.net`, `test3b-abssctl-test.krajr.net` | `test1c-abssctl-test.krajr.net`, `test2c-abssctl-test.krajr.net`, `test3c-abssctl-test.krajr.net` |
| Based on | Clone of the production server (`tkl-nodejs-v18`) | Fresh `tkl-nodejs-v18` after `apt update` / `apt upgrade` | Fresh `tkl-nodejs-v19` after `apt update` / `apt upgrade` |
| Snapshot | `clone-base` | `base-tkl-nodejs-v18` | `base-tkl-nodejs-v19` |
| VLAN | 107 (`vmbr0`) | 107 (`vmbr0`) | 107 (`vmbr0`) |

`test-nodeapp01` is a copy of production as of the snapshot date. Live testing on that guest still uses the `test*a-abssctl-test.krajr.net` names.

## What an agent may do

- Power these three guests on and off, SSH in as root, and install this tree’s wheel.
- Roll back to the snapshot named above when the task says to reset that guest.
- Create a snapshot only when Ken asks.

## What an agent may not do

- Touch the production server or production PyPI.
- Use any VM other than the three in the table. VM 9011901 (`nodeapp00`) is not in this token’s scope.
- Delete snapshots, clone a guest, or roll back unless the task says so.
- Run `tmp-personal-server/000-manual-install.sh` here. That script builds the production budget sites.
- Run `tmp-personal-server/000-test-install.sh` again unless the task says to. It already ran on `test-nodeapp02` on 2026-10-06 (test1b, test2b, test3b on ports 5110–5112; Actual 25.11.0; Node 22.23.3). nginx uses `/root/ssl/`. Rolling that guest back to `base-tkl-nodejs-v18` removes that layout and the abssctl registry written afterward. `test-nodeapp01` already has the family sites.

## Observed at the snapshots (2026-10-06)

`abssctl` was not installed. Guest hostnames are the short names; the FQDNs above are DNS.

| Guest | Image | Python | Node | npm | `n` | nginx |
|---|---|---|---|---|---|---|
| test-nodeapp01 | `turnkey-nodejs-18.0-bookworm-amd64` (Debian 12) | 3.11.2 | v22.0.0 | 10.9.9 | present | 1.22.1 |
| test-nodeapp02 | `turnkey-nodejs-18.0-bookworm-amd64` (Debian 12) | 3.11.2 | v20.9.0 | 10.1.0 | present | 1.22.1 |
| test-nodeapp03 | `turnkey-nodejs-19.0-trixie-amd64` (Debian 13) | 3.13.5 (`python3.11` absent) | v20.19.2 | 9.2.0 | absent | 1.26.3 |

Node v22.0.0 on `test-nodeapp01` is not the runtime to serve Actual with: 22.11.0 segfaults in `better-sqlite3`, and 22.23.3 is the preferred Node. npm must be >= 10.9.9 before Actual 26.6.0. `test-nodeapp02` and `test-nodeapp03` are below that npm. `test-nodeapp03` has no Python 3.11 and no `n`.

From this Mac on 2026-10-06, all nine `test*a` / `test*b` / `test*c` names resolve to the guest FQDN and the address in the table.

The three guests were rolled back to the snapshots above on 2026-10-07 and left running with TestPyPI `abssctl` 0.1.5a6 at `/opt/abssctl` (`/usr/local/bin/abssctl`). Each needed `python3-venv` before `python3 -m venv` would succeed. `0.1.5a5` is also on TestPyPI and does not start (`import click` fails under Typer 0.27).

- `test-nodeapp01`: family instances andrew, julia, robinson, and test were backed up under `/srv/backups` and deleted. `test1a`, `test2a`, and `test3a` are running on ports 5110–5112 (Node 22.23.3, Actual 25.11.0 at `/srv/app/current`) and nginx returns HTTP 200 for their `test*a-abssctl-test.krajr.net` names.
- `test-nodeapp02`: `system init --allow-create-user`, `node ensure` (Node 22.23.3, npm 10.9.9), and `version install 26.10.0` succeeded. `test1b` was created on port 5110 at `/srv/test1b` (default instance root `/srv`). The unit crash-loops with `203/EXEC` because `/usr/local/bin/abssctl-node-run` is not installed. nginx returns HTTP 502. `doctor` exits 4.
- `test-nodeapp03`: `system init --allow-create-user` succeeded. `node ensure` exits 3 because `n` is not on PATH. No Actual version or instance was created.

The snapshot table above is still the powered-off baseline.

## TLS

Each guest has the wildcard certificate in `/root/ssl/`:

- `/root/ssl/star.krajr.net.pem`
- `/root/ssl/star.krajr.net.key`

Subject `CN=*.krajr.net`, SAN `*.krajr.net` and `krajr.net`, valid through 2026-12-16. That covers the test FQDNs. Do not copy the key into the repo or into chat.

TurnKey nginx reads `/etc/ssl/private/cert.pem` and `/etc/ssl/private/cert.key` (`/etc/nginx/snippets/ssl.conf`). On `test-nodeapp01` those paths are the wildcard certificate. On `test-nodeapp02` and `test-nodeapp03` they are still the appliance self-signed `nodejs` certificate. Use the files in `/root/ssl/` when a test site needs the public wildcard. `tmp-personal-server/000-test-install.sh` points its nginx sites at those two files.
