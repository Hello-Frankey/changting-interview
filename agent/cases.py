"""工单索引：从 lab/index.json 读所有靶场的用例。

注意：对外（MCP / gRPC）暴露的工单**不能包含 ground truth**。
expected_verdict / ground_truth / intent 只供离线评测使用，必须在这里滤掉，
否则 agent 直接读到答案，整个判定就失去意义。
"""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "lab", "index.json")

# 只允许出现在离线评测里的字段
_ANSWER_FIELDS = {"ground_truth", "expected_verdict", "expected_pattern", "intent"}


def load_index():
    with open(INDEX, encoding="utf-8") as fh:
        return json.load(fh)["labs"]


def load_all(lab="all"):
    """返回 [(lab_name, case)]，case 保留全部字段（离线用）。"""
    out = []
    for entry in load_index():
        if lab != "all" and entry["name"] != lab:
            continue
        with open(os.path.join(ROOT, entry["cases"]), encoding="utf-8") as fh:
            for case in json.load(fh)["cases"]:
                out.append((entry["name"], case))
    return out


def find(case_id):
    for lab, case in load_all():
        if case["case_id"] == case_id:
            return lab, case
    raise KeyError(f"unknown case_id: {case_id}")


def public_ticket(lab, case):
    """去掉真值，只留 agent 应该看到的信息。"""
    return {
        "lab": lab,
        "case_id": case["case_id"],
        "asset": case["asset"],
        "vuln_type": case["vuln_type"],
        "reported_version": case["reported_version"],
        "title": case["ticket"]["title"],
        "endpoint": case["ticket"]["endpoint"],
        "fix_note": case["ticket"]["fix_note"],
    }


__all__ = ["load_index", "load_all", "find", "public_ticket", "_ANSWER_FIELDS"]
