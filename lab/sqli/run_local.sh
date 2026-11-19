#!/usr/bin/env bash
# 本地启动六个变体 + 一个边缘网关（不依赖 Docker，标准库即可）
#
#   ./run_local.sh up      启动全部
#   ./run_local.sh down    停止全部
#   ./run_local.sh status  查看健康状态
#   ./run_local.sh reset   down + up
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
LOG=logs
mkdir -p "$LOG"

# variant:port —— 顺序即 v0..v5，注意 8004 留给边缘网关
VARIANTS="v0_vulnerable:8000 v1_truefix:8001 v2_version_only:8002 v3_waf_only:8003 v4_blacklist:8005 v5_partial:8006 v6_broken:8007"
PORTS="8000 8001 8002 8003 8004 8005 8006 8007"

up() {
  down >/dev/null 2>&1 || true
  rm -f lab.db
  echo "启动六个变体 ..."
  for spec in $VARIANTS; do
    variant=${spec%%:*}
    port=${spec##*:}
    VARIANT="$variant" PORT="$port" DB_PATH="$PWD/lab.db" \
      nohup "$PY" app.py >"$LOG/$variant.log" 2>&1 &
    echo $! >"$LOG/$variant.pid"
  done
  ORIGIN=http://127.0.0.1:8003 EDGE_PORT=8004 \
    nohup "$PY" edge.py >"$LOG/edge.log" 2>&1 &
  echo $! >"$LOG/edge.pid"

  echo "等待就绪 ..."
  fail=0
  for port in $PORTS; do
    ok=0
    for _ in $(seq 1 80); do
      if curl -sf -m 1 "http://127.0.0.1:$port/healthz" -o /dev/null 2>/dev/null; then
        ok=1
        break
      fi
      sleep 0.1
    done
    if [ "$ok" = 1 ]; then
      echo "  ok   :$port"
    else
      echo "  FAIL :$port  (见 $LOG/)"
      fail=1
    fi
  done
  [ "$fail" = 0 ] || exit 1
  echo
  echo "靶场就绪。下一步：python3 ../../tools/retest_demo.py"
}

down() {
  for f in "$LOG"/*.pid; do
    [ -e "$f" ] || continue
    pid=$(cat "$f")
    kill "$pid" 2>/dev/null || true
    rm -f "$f"
  done
  # 兜底：清掉可能残留的进程
  pkill -f "$PWD/app.py" 2>/dev/null || true
  pkill -f "$PWD/edge.py" 2>/dev/null || true
  rm -f lab.db
}

status() {
  for port in $PORTS; do
    if curl -sf -m 1 "http://127.0.0.1:$port/healthz" 2>/dev/null; then
      echo "  :$port up"
    else
      echo "  :$port down"
    fi
  done
  # 8008 故意不启动：它代表"网络不可达"这一例，down 才是预期状态
  if curl -sf -m 1 "http://127.0.0.1:8008/healthz" 2>/dev/null; then
    echo "  :8008 up  (注意：不可达用例应保持 down)"
  else
    echo "  :8008 down (预期)"
  fi
}

case "${1:-up}" in
  up) up ;;
  down) down; echo "已停止" ;;
  reset) up ;;
  status) status ;;
  *) echo "用法: $0 {up|down|reset|status}"; exit 1 ;;
esac
