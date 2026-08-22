#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export FOCUS71=1
LOG=/tmp/focus71.log
pkill -f 'focus71_pubkey_kangaroo.py' 2>/dev/null || true
sleep 1
: >"$LOG"
nohup env FOCUS71=1 python3 -u "$ROOT/scripts/focus71_pubkey_kangaroo.py" >>"$LOG" 2>&1 &
echo "FOCUS71 pid=$! log=$LOG"
tail -n 5 "$LOG" || true
