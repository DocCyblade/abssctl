#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ABSSCTL_NODE_ENV_FILE:-/etc/default/abssctl-node}"
N_BIN="${ABSSCTL_NODE_MANAGER_BIN:-n}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

if [[ -z "${REQUIRED_NODE:-}" ]]; then
  echo "abssctl-node-run: REQUIRED_NODE is not set in $ENV_FILE" >&2
  exit 2
fi

if ! command -v "$N_BIN" >/dev/null 2>&1; then
  echo "abssctl-node-run: '$N_BIN' not found. Install 'n' or adjust ABSSCTL_NODE_MANAGER_BIN." >&2
  exit 3
fi

NODE_PATH="$("$N_BIN" which "$REQUIRED_NODE" 2>/dev/null || true)"
if [[ -z "$NODE_PATH" ]]; then
  echo "abssctl-node-run: installing Node $REQUIRED_NODE via $N_BIN." >&2
  "$N_BIN" install "$REQUIRED_NODE"
  NODE_PATH="$("$N_BIN" which "$REQUIRED_NODE")"
fi

if [[ -z "$NODE_PATH" ]]; then
  echo "abssctl-node-run: unable to locate Node binary for $REQUIRED_NODE via $N_BIN." >&2
  exit 4
fi

exec "$NODE_PATH" "$@"
