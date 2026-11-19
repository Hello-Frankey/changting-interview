#!/usr/bin/env python3
"""能力层 CLI —— 供 OctoBus service package（Node）调用。

设计原则：**这个 CLI 是唯一的确定性入口**。
LLM 通过 MCP 调到的每一个能力，最终都落到这里的某条子命令上；
Node 侧只做参数转换，不含任何判断逻辑。

输出约定：stdout 只输出一个 JSON 对象，日志走 stderr。
失败时返回非零退出码 + {"error": "..."}。

子命令
------
  tickets  [--lab all|sqli|xss|access]   列出待复测工单（不含真值）
  evidence --case ID                     取数：跑探针，返回证据
  signals  --case ID                     把证据压成信号
  judge    --case ID                     规则引擎判定
  validate --case ID --verdict V --pattern P \
           --evidence-ids id1,id2 --explanation TEXT
                                         报告守卫校验
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from agent import cases, collect, guard, judge, signals  # noqa: E402

PACK = judge.load_pack()
MIN_ROW_DELTA = int(PACK["thresholds"]["min_row_delta"]["value"])


def _pipeline(case_id):
    """取数 → 信号 → 判定。三个下游命令共用，保证看到的是同一份证据。"""
    lab, case = cases.find(case_id)
    evidence = collect.collect(case, MIN_ROW_DELTA)
    sig = signals.compute(evidence, case)
    verdict = judge.evaluate(PACK, sig, evidence, case["vuln_type"])
    return lab, case, evidence, sig, verdict


def _public_evidence(evidence):
    """给 agent 看的证据：保留可判读的字段，去掉大段响应体。"""
    out = []
    for e in evidence:
        resp = e.get("response") or {}
        out.append({
            "id": e["id"],
            "kind": e["kind"],
            "endpoint": e["endpoint"],
            "label": e["label"],
            "status": resp.get("status"),
            "count": resp.get("count"),
            "length": resp.get("length"),
            "sha256": resp.get("sha256"),
            "exploited": bool(e.get("exploited")),
            "blocked": bool(e.get("blocked")),
            "body_head": (resp.get("body") or "")[:240],
        })
    return out


def cmd_tickets(args):
    return {"tickets": [cases.public_ticket(lab, c) for lab, c in cases.load_all(args.lab)]}


def cmd_evidence(args):
    lab, case, evidence, _sig, _v = _pipeline(args.case)
    return {"case_id": args.case, "lab": lab, "count": len(evidence),
            "evidence": _public_evidence(evidence)}


def cmd_signals(args):
    _lab, _case, _ev, sig, _v = _pipeline(args.case)
    return {"case_id": args.case,
            "signals": {k: v for k, v in sig.items() if not k.startswith("_")}}


def cmd_judge(args):
    _lab, case, evidence, _sig, verdict = _pipeline(args.case)
    return {
        "case_id": args.case,
        "vuln_type": case["vuln_type"],
        "rule_id": verdict["rule_id"],
        "rule_name": verdict["rule_name"],
        "verdict": verdict["verdict"],
        "pattern": verdict["pattern"],
        "confidence": verdict["confidence"],
        "human_review": verdict["human_review"],
        "explanation": verdict["explanation"],
        "evidence_ids": verdict["evidence_ids"],
        "failure_modes": verdict.get("failure_modes", []),
        "trace": verdict.get("trace", []),
    }


def cmd_validate(args):
    _lab, _case, evidence, _sig, verdict = _pipeline(args.case)
    cited = [s for s in (args.evidence_ids or "").split(",") if s]
    report = {
        "verdict": args.verdict,
        "pattern": args.pattern,
        "evidence_ids": cited,
        "explanation": args.explanation or "",
    }
    result = guard.validate(report, verdict, evidence)
    result["case_id"] = args.case
    result["report"] = report
    return result


def main():
    ap = argparse.ArgumentParser(description="retest capability CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("tickets")
    p.add_argument("--lab", default="all")
    p.set_defaults(func=cmd_tickets)

    for name, func in (("evidence", cmd_evidence), ("signals", cmd_signals), ("judge", cmd_judge)):
        p = sub.add_parser(name)
        p.add_argument("--case", required=True)
        p.set_defaults(func=func)

    p = sub.add_parser("validate")
    p.add_argument("--case", required=True)
    p.add_argument("--verdict", required=True)
    p.add_argument("--pattern", required=True)
    p.add_argument("--evidence-ids", default="")
    p.add_argument("--explanation", default="")
    p.set_defaults(func=cmd_validate)

    args = ap.parse_args()
    try:
        result = args.func(args)
    except KeyError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001 — CLI 边界，统一转成 JSON 错误
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 1

    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
