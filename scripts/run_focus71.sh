#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export FOCUS71=1
LOG=/tmp/focus71.log
SESSION=focus71
pkill -f 'mempool_pubkey_watch.py' 2>/dev/null || true
pkill -f 'sweep_continue.py' 2>/dev/null || true
pkill -f 'focus71_pubkey_kangaroo.py' 2>/dev/null || true
sleep 1
mkdir -p /tmp/sweep_prepared
: >"$LOG"
TMUX=(tmux)
[[ -f /exec-daemon/tmux.portal.conf ]] && TMUX=(tmux -f /exec-daemon/tmux.portal.conf)
"${TMUX[@]}" has-session -t "=$SESSION" 2>/dev/null && "${TMUX[@]}" kill-session -t "$SESSION" 2>/dev/null || true
"${TMUX[@]}" new-session -d -s "$SESSION" -c "$ROOT" -- \
  bash -lc "export FOCUS71=1; python3 -u '$ROOT/scripts/focus71_pubkey_kangaroo.py' >>'$LOG' 2>&1"
sleep 1
echo "FOCUS71 ok log=$LOG"
tail -n 15 "$LOG" || true
