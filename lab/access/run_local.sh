#!/usr/bin/env bash
# 越权靶场本地启动（标准库，零依赖）
#
#   ./run_local.sh up      启动七个变体（8200-8206）
#   ./run_local.sh down    停止
#   ./run_local.sh status  健康状态
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
LOG=logs
mkdir -p "$LOG"

VARIANTS="a0_vulnerable:8200 a1_truefix:8201 a2_list_only:8202 a3_uuid:8203 a4_partial:8204 a5_vertical:8205 a6_write_silent:8206"
PORTS="8200 8201 8202 8203 8204 8205 8206"

up() {
  down >/dev/null 2>&1 || true
  echo "启动七个越权变体 ..."
  for spec in $VARIANTS; do
    variant=${spec%%:*}
    port=${spec##*:}
    VARIANT="$variant" PORT="$port" nohup "$PY" app.py >"$LOG/$variant.log" 2>&1 &
    echo $! >"$LOG/$variant.pid"
  done

  fail=0
  for port in $PORTS; do
    ok=0
    for _ in $(seq 1 80); do
      if curl -sf -m 1 "http://127.0.0.1:$port/healthz" -o /dev/null 2>/dev/null; then ok=1; break; fi
      sleep 0.1
    done
    if [ "$ok" = 1 ]; then echo "  ok   :$port"; else echo "  FAIL :$port  (见 $LOG/)"; fail=1; fi
  done
  [ "$fail" = 0 ] || exit 1
  echo
  echo "越权靶场就绪。下一步：python3 ../../tools/retest_demo.py --lab access"
}

down() {
  for f in "$LOG"/*.pid; do
    [ -e "$f" ] || continue
    kill "$(cat "$f")" 2>/dev/null || true
    rm -f "$f"
  done
  pkill -f "$PWD/app.py" 2>/dev/null || true
}

status() {
  for port in $PORTS; do
    if curl -sf -m 1 "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
      echo "  :$port up"
    else
      echo "  :$port down"
    fi
  done
}

case "${1:-up}" in
  up) up ;;
  down) down; echo "已停止" ;;
  status) status ;;
  *) echo "用法: $0 {up|down|status}"; exit 1 ;;
esac
