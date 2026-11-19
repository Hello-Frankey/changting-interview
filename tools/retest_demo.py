#!/usr/bin/env python3
"""复测 Agent 端到端演示 —— 取数 → 信号 → 知识库判定 → 证据链。

判定逻辑全部来自 knowledge/false-fix-patterns.yaml，本脚本不含任何业务判据。
想验证知识是否真的在起作用：`python3 tools/ablate.py`。

用法
----
  cd lab/sqli && ./run_local.sh up
  cd lab/xss  && ./run_local.sh up
  python3 tools/retest_demo.py               # 两个靶场全跑，紧凑输出
  python3 tools/retest_demo.py --lab xss     # 只跑 XSS
  python3 tools/retest_demo.py -v            # 展开每一条探针证据
"""

import argparse
import json
import os
import sys
import urllib.request

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from agent import collect, judge, signals  # noqa: E402

INDEX = os.path.join(ROOT, "lab", "index.json")
OUT = os.path.join(ROOT, "out", "report.json")

VERDICT_CN = {
    "FIXED": "已修复",
    "PARTIAL": "部分修复",
    "MITIGATED_NOT_FIXED": "仅缓解未修复",
    "UNFIXED": "未修复",
    "UNVERIFIABLE": "无法验证",
}


def pad(text, width):
    display = sum(2 if ord(c) > 127 else 1 for c in text)
    return text + " " * max(0, width - display)


def load_labs(name):
    with open(INDEX, encoding="utf-8") as fh:
        entries = json.load(fh)["labs"]
    labs = []
    for entry in entries:
        if name != "all" and entry["name"] != name:
            continue
        with open(os.path.join(ROOT, entry["cases"]), encoding="utf-8") as fh:
            labs.append((entry["name"], json.load(fh)["cases"]))
    return labs


def alive(cases):
    """快速判断该靶场是否已经启动，避免把"没开"算成"判定失败"。"""
    for case in cases:
        for side in ("edge", "origin"):
            base = case["targets"].get(side)
            if not base:
                continue
            try:
                with _OPENER.open(base + "/healthz", timeout=2) as resp:
                    if resp.status == 200:
                        return True
            except Exception:  # noqa: BLE001
                continue
    return False


def fmt(resp):
    if resp["status"] is None:
        return "连接失败"
    if resp.get("error"):
        return resp["error"]
    return f"{resp['status']}  {resp['length']}B  [{resp['sha256']}]"


def dump_evidence(case, ev):
    print(f"  工单: {case['ticket']['title']}")
    print(f"  修复说明: {case['ticket']['fix_note']}")
    for e in ev:
        kind = {"baseline": "基线  ", "poc": "原始PoC", "context": "上下文",
                "canary": "编码探针", "stored": "存储点", "version": "版本  ",
                "mutation": "变异  "}.get(e["kind"], e["kind"])
        extra = ""
        if e["kind"] == "version":
            extra = f"  {e.get('observed_version')}"
        if e.get("exploited"):
            extra += "  ← 可利用"
        if e.get("encoded"):
            extra += "  ← 观察到编码"
        print(f"    {pad(kind, 8)} {pad(e['endpoint'], 14)} {pad(e['label'], 12)} "
              f"{fmt(e['response'])}{extra}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", default="all", help="all | sqli | xss")
    ap.add_argument("-v", "--verbose", action="store_true", help="展开每一条探针证据")
    args = ap.parse_args()

    pack = judge.load_pack()
    min_row_delta = int(pack["thresholds"]["min_row_delta"]["value"])

    print(f"知识库: {os.path.relpath(judge.DEFAULT_PACK, ROOT)}  "
          f"({len(pack['rules'])} 条规则)\n")

    all_results = []
    verdict_hits = pattern_hits = total = 0

    for lab_name, cases in load_labs(args.lab):
        if not alive(cases):
            print(f"[skip] 靶场 {lab_name} 未启动：cd lab/{lab_name} && ./run_local.sh up\n")
            continue

        if not args.verbose:
            print(pad("工单", 11) + pad("变体", 17) + pad("裁决", 20) + pad("模式", 26)
                  + pad("规则", 24) + "对照")
            print("-" * 96)

        for case in cases:
            ev = collect.collect(case, min_row_delta)
            sig = signals.compute(ev, case)
            verdict = judge.evaluate(pack, sig, ev, case["vuln_type"])

            ok_v = verdict["verdict"] == case["expected_verdict"]
            ok_p = verdict["pattern"] == case["expected_pattern"]
            total += 1
            verdict_hits += ok_v
            pattern_hits += ok_p

            if args.verbose:
                print("=" * 96)
                print(f"{case['case_id']}  [{case['variant']}]  {case['vuln_type']}")
                dump_evidence(case, ev)
                active = [k for k, v in sig.items() if v is True]
                print(f"    信号: {', '.join(active) if active else '（全部为假）'}")
                print(f"  → {pad(verdict['verdict'], 20)} {verdict['rule_id']}  "
                      f"[{verdict['confidence']}]")
                print(f"    依据: {verdict['explanation'][:100]}")
                if verdict["human_review"] != "none":
                    print(f"    人工: {verdict['human_review']}")
                chain = " → ".join(f"{rid}{'✓' if st == 'HIT' else ''}"
                                   for rid, st in verdict["trace"])
                print(f"    求值: {chain}")
                print(f"  期望: {case['expected_verdict']}/{case['expected_pattern']}   "
                      f"裁决{'✓' if ok_v else '✗'} 模式{'✓' if ok_p else '✗'}")
                print()
            else:
                mark = "✓" if (ok_v and ok_p) else ("✗" if not ok_v else "✅/✗")
                print(pad(case["case_id"], 11) + pad(case["variant"], 17)
                      + pad(verdict["verdict"], 20) + pad(verdict["pattern"], 26)
                      + pad(verdict["rule_id"], 24) + mark)

            all_results.append({
                "case_id": case["case_id"],
                "lab": lab_name,
                "vuln_type": case["vuln_type"],
                "variant": case["variant"],
                "verdict": verdict["verdict"],
                "pattern": verdict["pattern"],
                "rule_id": verdict["rule_id"],
                "confidence": verdict["confidence"],
                "human_review": verdict["human_review"],
                "expected_verdict": case["expected_verdict"],
                "expected_pattern": case["expected_pattern"],
                "match_verdict": ok_v,
                "match_pattern": ok_p,
                "signals": {k: v for k, v in sig.items() if not k.startswith("_")},
                "evidence_ids": verdict["evidence_ids"],
                "trace": verdict["trace"],
            })
        if not args.verbose:
            print()

    if total == 0:
        print("没有任何靶场在运行。先在 lab/sqli 与 lab/xss 下执行 ./run_local.sh up")
        return 2

    print("=" * 96)
    print(f"裁决准确率: {verdict_hits}/{total}    模式准确率: {pattern_hits}/{total}")
    print("=" * 96)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"total": total,
                   "verdict_hits": verdict_hits,
                   "pattern_hits": pattern_hits,
                   "results": all_results}, fh, ensure_ascii=False, indent=2)
    print(f"明细已写入 {os.path.relpath(OUT, ROOT)}")
    return 0 if verdict_hits == total and pattern_hits == total else 1


if __name__ == "__main__":
    sys.exit(main())
