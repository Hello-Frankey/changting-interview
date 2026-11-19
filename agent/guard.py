"""报告守卫：确定性校验 agent 交回来的结论。

这是整个 LLM 接线里最关键的零件。考核说明 5.1.4 要求"结论须有证据支撑，
不得由模型直接生成未经核验的数据或结论"。光靠提示词约束不住模型，所以这里
用一个纯代码的校验器做最后一道闸。

三条规则
--------
1. **单调性**：报告结论只能比工具结论更保守，不能更乐观。
   顺序即风险：FIXED < MITIGATED < PARTIAL < UNFIXED < UNVERIFIABLE。
   "未修复"是阳性证据，"已修复"是阴性证明；模型可以怀疑前者，不能替后者背书。
2. **证据必须真实存在**：引用的每个证据 ID 必须在本次取数结果里。
   防的是模型编造证据。
3. **阴性证明必须覆盖完整**：判 FIXED 时，报告必须引用工具给出的全部覆盖证据。
   防的是"只测了一个上下文就说全修好了"。

校验器不判断结论对不对（那是规则引擎的事），只判断**这个结论有没有资格被写进报告**。
"""

# 从乐观到保守排列；索引越小越乐观
SEVERITY = ["FIXED", "MITIGATED_NOT_FIXED", "PARTIAL", "UNFIXED", "UNVERIFIABLE"]

PATTERNS = {
    "root_cause", "single_point", "edge_virtual_patch", "bypassable_filter",
    "version_only", "no_fix", "baseline_broken", "unreachable",
    "context_mismatch", "csp_mitigation",
    "vertical_unfixed", "list_filtered_not_object", "unguessable_id", "silent_write",
    "no_rule_matched",
}


def _rank(verdict):
    return SEVERITY.index(verdict) if verdict in SEVERITY else None


def validate(report, tool_result, evidence):
    """返回 {"accepted": bool, "violations": [...], "tool_verdict": str}。"""
    violations = []

    verdict = report.get("verdict")
    pattern = report.get("pattern")
    cited = list(report.get("evidence_ids") or [])

    tool_verdict = tool_result["verdict"]
    tool_ids = list(tool_result.get("evidence_ids") or [])

    # 1. 结论必须是已知取值
    if _rank(verdict) is None:
        return {"accepted": False,
                "violations": [f"unknown_verdict:{verdict}"],
                "tool_verdict": tool_verdict}

    # 2. 模式必须是已知取值
    if pattern not in PATTERNS:
        violations.append(f"unknown_pattern:{pattern}")

    # 3. 单调性：不得比工具结论更乐观
    if _rank(verdict) < _rank(tool_verdict):
        violations.append(
            f"optimistic_downgrade:tool={tool_verdict} report={verdict}"
        )

    # 4. 引用的证据必须真实存在（防编造）
    known = {e["id"] for e in evidence}
    fabricated = [eid for eid in cited if eid not in known]
    if fabricated:
        violations.append(f"fabricated_evidence:{','.join(fabricated[:3])}")

    # 5. 非"无法验证"的结论必须引用证据
    if verdict != "UNVERIFIABLE" and not cited:
        violations.append("missing_evidence")

    # 6. 阴性证明必须覆盖完整
    if verdict == "FIXED" and not set(tool_ids).issubset(set(cited)):
        missing = sorted(set(tool_ids) - set(cited))
        violations.append(f"incomplete_coverage:missing={len(missing)}")

    return {"accepted": not violations, "violations": violations, "tool_verdict": tool_verdict}


def summarise(results):
    ok = sum(1 for r in results if r["accepted"])
    return {"total": len(results), "accepted": ok, "rejected": len(results) - ok}
