#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  agent_sleep_unix_vm_test.sh --bin <lockbox> [--work-dir <dir>] [--sleep-command <cmd>] [--no-sleep]

Runs a real Lockbox session-agent sleep test inside a Linux or macOS VM.

The script:
  1. Creates an isolated vault, lockbox, agent socket directory, and agent log.
  2. Unlocks the lockbox so the session agent caches the content key.
  3. Verifies the cache is visible before sleep.
  4. Runs the OS sleep command unless --no-sleep is passed.
  5. After resume, verifies the cache was cleared and the agent log contains
     "suspend requested; cleared".

Default sleep command:
  Linux: sudo systemctl suspend
  macOS: pmset sleepnow

For Multipass, --no-sleep is useful because guest suspend can wedge the
Multipass manager. It still verifies the Linux logind delay inhibitor.
USAGE
}

LOCKBOX_BIN=
WORK_DIR="${TMPDIR:-/tmp}/lockbox-agent-sleep-test"
SLEEP_COMMAND=
NO_SLEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      LOCKBOX_BIN="${2:?missing value for --bin}"
      shift 2
      ;;
    --work-dir)
      WORK_DIR="${2:?missing value for --work-dir}"
      shift 2
      ;;
    --sleep-command)
      SLEEP_COMMAND="${2:?missing value for --sleep-command}"
      shift 2
      ;;
    --no-sleep)
      NO_SLEEP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$LOCKBOX_BIN" ]]; then
  echo "--bin is required" >&2
  usage >&2
  exit 2
fi

case "$(uname -s)" in
  Linux)
    DEFAULT_SLEEP_COMMAND="sudo systemctl suspend"
    ;;
  Darwin)
    DEFAULT_SLEEP_COMMAND="pmset sleepnow"
    ;;
  *)
    echo "unsupported Unix platform: $(uname -s)" >&2
    exit 2
    ;;
esac

SLEEP_COMMAND="${SLEEP_COMMAND:-$DEFAULT_SLEEP_COMMAND}"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/agent" "$WORK_DIR/vault"

export LOCKBOX_PASSWORD="test-lockbox-password"
export LOCKBOX_VAULT_PASSWORD="test-vault-password"
export LOCKBOX_SESSION_AGENT_DIR="$WORK_DIR/agent"
export LOCKBOX_SESSION_AGENT_LOG="$WORK_DIR/agent.log"
export LOCKBOX_VAULT_DIR="$WORK_DIR/vault"

"$LOCKBOX_BIN" vault init >/dev/null
"$LOCKBOX_BIN" create "$WORK_DIR/test.lbox" >/dev/null
"$LOCKBOX_BIN" unlock "$WORK_DIR/test.lbox" >/dev/null

before="$("$LOCKBOX_BIN" vault sessions --format tsv)"
if ! grep -q '^unlocked' <<<"$before"; then
  echo "expected lockbox to be cached before sleep; sessions output:" >&2
  echo "$before" >&2
  exit 1
fi

if ! grep -q 'sleep watcher started' "$LOCKBOX_SESSION_AGENT_LOG"; then
  echo "agent log did not show a running sleep watcher" >&2
  cat "$LOCKBOX_SESSION_AGENT_LOG" >&2
  exit 1
fi

if [[ "$(uname -s)" == "Linux" ]] && command -v systemd-inhibit >/dev/null 2>&1; then
  if ! systemd-inhibit --list --no-pager | grep -q 'lockbox.*sleep.*Clear cached lockbox keys'; then
    echo "logind delay inhibitor is not registered" >&2
    systemd-inhibit --list --no-pager >&2
    exit 1
  fi
fi

if [[ "$NO_SLEEP" -eq 1 ]]; then
  echo "prepared: cache is populated and sleep watcher is active"
  echo "log: $LOCKBOX_SESSION_AGENT_LOG"
  exit 0
fi

echo "sleeping now; resume the VM if the hypervisor does not do it automatically"
sh -c "$SLEEP_COMMAND"
sleep 5

after="$("$LOCKBOX_BIN" vault sessions --format tsv)"
if [[ "$after" != "empty" ]]; then
  echo "expected cache to be empty after resume; sessions output:" >&2
  echo "$after" >&2
  cat "$LOCKBOX_SESSION_AGENT_LOG" >&2
  exit 1
fi

if ! grep -q 'suspend requested; cleared' "$LOCKBOX_SESSION_AGENT_LOG"; then
  echo "agent log did not show a suspend cache clear" >&2
  cat "$LOCKBOX_SESSION_AGENT_LOG" >&2
  exit 1
fi

echo "pass: cache cleared on sleep"
echo "log: $LOCKBOX_SESSION_AGENT_LOG"
