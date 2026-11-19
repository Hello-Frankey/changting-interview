#!/usr/bin/env bash
# 调用 OctoBus 能力（经 capproxy）。
#
# 用法：
#   ./cap.sh ListTickets '{"lab":"all"}'
#   ./cap.sh Judge '{"case_id":"SQLI-005"}'
#   ./cap.sh ValidateReport '{"case_id":"SQLI-005","verdict":"UNFIXED","pattern":"bypassable_filter","evidenceIds":["..."],"explanation":"..."}'
#
# 环境变量由 agent-compose 注入，无需手动设置：
#   CAP_GRPC_TARGET  capproxy 地址
#   CAP_TOKEN        本沙箱的能力令牌
#
# 说明：这里刻意不把 capset / instance 写死成不可改的形式——
# 如果以后换了 capset，只改下面两行。

set -euo pipefail

method="${1:?用法: cap.sh <Method> [json-body]}"
body="${2:-{\}}"

: "${CAP_GRPC_TARGET:?缺少 CAP_GRPC_TARGET（不在 agent-compose 沙箱里？）}"
: "${CAP_TOKEN:?缺少 CAP_TOKEN}"

CAPSET="${RETEST_CAPSET:-retest-agent}"
INSTANCE="${RETEST_INSTANCE:-retest-dev}"

exec grpcurl -plaintext \
  -H "x-capability-sandbox-token: ${CAP_TOKEN}" \
  -H "x-octobus-capset: ${CAPSET}" \
  -H "x-octobus-instance: ${INSTANCE}" \
  -d "${body}" \
  "${CAP_GRPC_TARGET}" "retest.v1.RetestService/${method}"
