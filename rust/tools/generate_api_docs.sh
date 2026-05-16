#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo doc -p lockbox_core --no-deps

cat <<'MSG'
Generated lockbox_core API docs:
  target/doc/lockbox_core/index.html
MSG
