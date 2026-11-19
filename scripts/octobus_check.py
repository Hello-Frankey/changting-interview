#!/usr/bin/env python3
"""本地端到端验证：OctoBus 三层链路 + MCP 调用 + 报告守卫。

它做的事和部署到服务器上完全一致，只是把目标换成本机：
  1. 起一个 --dev 模式的 OctoBus daemon（临时数据目录）
  2. service import  → 导入 retest-capabilities
  3. instance create → 绑定 repoRoot
  4. capset create + add-instance --no-all-methods + select-method（显式选方法）
  5. capset add-token
  6. MCP：tools/list → tools/call Judge → tools/call ValidateReport（诚实 / 撒谎各一次）
  7. 断言并清理

用法
----
  # 需要本机能执行 octobus（PATH 里，或用 OCTOBUS_BIN 指定）
  OCTOBUS_BIN=/tmp/obtest/node_modules/.bin/octobus python3 scripts/octobus_check.py

退出码 0 表示整条链路可用。
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OCTOBUS = os.environ.get("OCTOBUS_BIN", "octobus")
ADDR = os.environ.get("OCTOBUS_ADDR", "127.0.0.1:9000")
ADMIN_TOKEN = os.environ.get("OCTOBUS_ADMIN_TOKEN", "octobus-dev-admin-token")
CAPSET_TOKEN = os.environ.get("RETEST_CAPSET_TOKEN", "test-token-123")
CAPSET = "retest-agent"
INSTANCE = "retest-dev"
CASE = os.environ.get("CASE_ID", "SQLI-005")

MCP_URL = f"http://{ADDR}/capsets/{CAPSET}/mcp"
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

ENV = {**os.environ, "OCTOBUS_ADMIN_TOKEN": ADMIN_TOKEN}

ok_count = 0
fail_count = 0


def dig(obj, keys, depth=2):
    """在嵌套结构里找第一个命中的键（记录可能包在 Service/Instance 之下）。"""
    if isinstance(obj, dict):
        for k in keys:
            if k in obj:
                return obj[k]
        if depth > 0:
            for v in obj.values():
                found = dig(v, keys, depth - 1)
                if found is not None:
                    return found
    return None


def check(label, condition, detail=""):
    global ok_count, fail_count
    if condition:
        ok_count += 1
        print(f"  \033[32mPASS\033[0m  {label}")
    else:
        fail_count += 1
        print(f"  \033[31mFAIL\033[0m  {label}  {detail}")


def run(*args, quiet=True):
    result = subprocess.run([OCTOBUS, *args], capture_output=True, text=True,
                            env=ENV, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"octobus {' '.join(args)} failed:\n{result.stderr[-800:]}")
    return result.stdout if not quiet else result.stdout


def mcp(payload):
    req = urllib.request.Request(
        MCP_URL,
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {CAPSET_TOKEN}",
                 "Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"},
    )
    with _OPENER.open(req, timeout=60) as resp:
        return json.loads(resp.read())


def tool_call(name, arguments):
    resp = mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}})
    return resp["result"].get("structuredContent") or {}


def main():
    if shutil.which(OCTOBUS) is None and not os.path.isfile(OCTOBUS):
        print(f"找不到 octobus 可执行文件：{OCTOBUS}\n用 OCTOBUS_BIN 指定路径，或 npm i -g @chaitin-ai/octobus")
        return 2

    data_dir = tempfile.mkdtemp(prefix="octobus-check-")
    print(f"数据目录: {data_dir}\n")

    daemon = subprocess.Popen(
        [OCTOBUS, "serve", "--dev", "--data-dir", data_dir],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV,
    )
    try:
        for _ in range(60):
            time.sleep(0.3)
            if subprocess.run([OCTOBUS, "status"], capture_output=True, env=ENV).returncode == 0:
                break
        else:
            print("daemon 启动超时")
            return 2

        print("[1] 导入 service package")
        run("service", "import", "retest-capabilities",
            os.path.join(ROOT, "services", "retest-capabilities"))
        out = json.loads(run("service", "get", "retest-capabilities"))
        methods = dig(out, ("Methods", "methods")) or []
        check("service 识别到 5 个 unary 方法", len(methods) == 5, f"实际 {len(methods)}")

        print("\n[2] 创建 instance")
        run("instance", "create", INSTANCE, "--service", "retest-capabilities",
            "--config-json", json.dumps({"repoRoot": ROOT}))
        status = json.loads(run("instance", "get", INSTANCE))
        state = dig(status, ("Status", "status"))
        check("instance 状态 running", state == "running", str(state))

        print("\n[3] 创建 capset 并显式选择方法")
        run("capset", "create", CAPSET, "--name", "Retest Agent")
        run("capset", "add-instance", CAPSET, INSTANCE, "--no-all-methods")
        for m in ("ListTickets", "CollectEvidence", "ComputeSignals", "Judge", "ValidateReport"):
            run("capset", "select-method", CAPSET, INSTANCE,
                f"retest.v1.RetestService/{m}", "--mcp-tool", f"retest_{m}")
        run("capset", "add-token", CAPSET, "local", "--name", "local dev",
            "--token", CAPSET_TOKEN)

        print("\n[4] MCP tools/list")
        tools = mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        names = sorted(t["name"] for t in tools["result"]["tools"])
        check("暴露 5 个 MCP 工具", len(names) == 5, str(names))
        print(f"        {', '.join(names)}")

        print(f"\n[5] 调用 retest_Judge({CASE})")
        verdict = tool_call("retest_Judge", {"case_id": CASE})
        check("返回 verdict", bool(verdict.get("verdict")), str(verdict)[:120])
        check("返回证据引用", len(verdict.get("evidenceIds") or []) > 0)
        print(f"        {verdict.get('verdict')} / {verdict.get('pattern')} "
              f"via {verdict.get('ruleId')}")

        print("\n[6] 诚实报告应被接受")
        honest = tool_call("retest_ValidateReport", {
            "case_id": CASE,
            "verdict": verdict["verdict"],
            "pattern": verdict["pattern"],
            "evidence_ids": verdict["evidenceIds"],
            "explanation": verdict.get("explanation", ""),
        })
        check("accepted=true", honest.get("accepted") is True, str(honest.get("violations")))

        print("\n[7] 撒谎报告应被拒绝")
        lying = tool_call("retest_ValidateReport", {
            "case_id": CASE,
            "verdict": "FIXED",
            "pattern": "root_cause",
            "evidence_ids": ["fake:evidence:1"],
            "explanation": "看起来修好了",
        })
        violations = lying.get("violations") or []
        check("accepted=false", lying.get("accepted") is False, str(lying))
        check("抓到乐观改判", any(v.startswith("optimistic_downgrade") for v in violations))
        check("抓到编造证据", any(v.startswith("fabricated_evidence") for v in violations))
        for v in violations:
            print(f"        - {v}")
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
        shutil.rmtree(data_dir, ignore_errors=True)

    print(f"\n{'=' * 60}")
    print(f"通过 {ok_count} 项，失败 {fail_count} 项")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
