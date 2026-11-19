#!/usr/bin/env python3
"""生成 agent 工作区。

为什么需要这一步
----------------
`lab/*/cases.json` 里含 ground truth（`expected_verdict` / `ground_truth` / `intent`）。
如果把整个仓库挂进 sandbox，agent 可以直接读到答案，评测就失去意义。

所以 agent 的工作区是**独立生成的**，只包含：
  - knowledge/false-fix-patterns.yaml   （它需要引用的判据）
  - prompts/retest.md                    （任务指令）
  - cases_summary.md                     （工单清单，无真值）

真值留在仓库里，只给离线评测脚本用。

用法
----
  python3 scripts/sync_workspace.py
  # 然后 agent-compose up
"""

import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent import cases  # noqa: E402

WORKSPACE = os.path.join(ROOT, "workspace")


def main():
    shutil.rmtree(WORKSPACE, ignore_errors=True)
    os.makedirs(os.path.join(WORKSPACE, "knowledge"), exist_ok=True)

    shutil.copy2(os.path.join(ROOT, "knowledge", "false-fix-patterns.yaml"),
                 os.path.join(WORKSPACE, "knowledge", "false-fix-patterns.yaml"))
    shutil.copy2(os.path.join(ROOT, "prompts", "retest.md"),
                 os.path.join(WORKSPACE, "retest.md"))
    # 能力调用助手：给 agent 一个可执行入口，而不是让它自己拼 grpcurl
    cap_src = os.path.join(ROOT, "prompts", "cap.sh")
    cap_dst = os.path.join(WORKSPACE, "cap.sh")
    shutil.copy2(cap_src, cap_dst)
    os.chmod(cap_dst, 0o755)

    lines = ["# 待复测工单（无真值）", "",
             "| 工单 | 类型 | 资产 | 工单标题 | 修复说明 |",
             "|---|---|---|---|---|"]
    for lab, case in cases.load_all():
        t = case["ticket"]
        lines.append(f"| `{case['case_id']}` | {case['vuln_type']} | {case['asset']} "
                     f"| {t['title']} | {t['fix_note']} |")
    with open(os.path.join(WORKSPACE, "cases_summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    # 自检：工作区里绝不能出现真值字段
    merged = ""
    for name in ("retest.md", "cases_summary.md"):
        merged += open(os.path.join(WORKSPACE, name), encoding="utf-8").read()
    leaked = [f for f in cases._ANSWER_FIELDS if f in merged]
    if leaked:
        print(f"工作区泄漏真值字段: {leaked}")
        return 1

    # 统一权限：沙箱里的 agent 不是 root，必须可读
    for dirpath, _, filenames in os.walk(WORKSPACE):
        os.chmod(dirpath, 0o755)
        for name in filenames:
            path = os.path.join(dirpath, name)
            if not os.access(path, os.X_OK):
                os.chmod(path, 0o644)

    total = sum(len(files) for _, _, files in os.walk(WORKSPACE))
    print(f"工作区已生成: {WORKSPACE}  ({total} 个文件，无真值字段)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
