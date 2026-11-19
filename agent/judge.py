"""判定层：加载知识库，按优先级求值，每个结论都带出命中的规则与证据。

关键设计：
  - 规则是数据，不是代码。删掉 YAML 里的某条，判定结果就会变——
    这正是 tools/ablate.py 用来证明"知识确实被消费"的方式。
  - 没有规则命中时，退化到一个"只重放 PoC"的朴素基线（FALLBACK），
    而不是猜一个结论。这个降级路径就是消融实验的对照组。
"""

import os

import yaml

DEFAULT_PACK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "knowledge", "false-fix-patterns.yaml")


def load_pack(path=DEFAULT_PACK):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _match(cond, signals):
    if "all" in cond:
        return all(_match(c, signals) for c in cond["all"])
    if "any" in cond:
        return any(_match(c, signals) for c in cond["any"])
    if "not" in cond:
        return not _match(cond["not"], signals)
    value = signals.get(cond["signal"])
    if "is" in cond:
        return value == cond["is"]
    if "gte" in cond:
        return value is not None and value >= cond["gte"]
    return False


def _material_evidence(evidence, verdict):
    """挑出应当链进报告的证据。

    对判 FIXED 而言，必须展示"测过哪些"才构成阴性证明；
    对其余结论而言，被利用的那几条最关键，但完整记录同样是结论的基础。
    这里统一返回除 canary 之外的全部证据——canary 是阈值标定用的探针，
    不是判定依据，引它反而会让报告显得在凑数。
    """
    return [e["id"] for e in evidence if e["kind"] != "canary"]


def _primary_signal(signals):
    """朴素 Agent 唯一会看的那一个信号，按漏洞类型取。"""
    for key in ("poc_effective", "horizontal_effective"):
        if key in signals:
            return bool(signals[key])
    return False


def _fallback(signals, evidence, reason=None):
    """无知识库时的朴素基线：只重放 PoC / 只试一次越权访问。"""
    if not signals.get("reachable"):
        verdict, pattern = "UNVERIFIABLE", "unreachable"
    elif _primary_signal(signals):
        verdict, pattern = "UNFIXED", "no_fix"
    else:
        verdict, pattern = "FIXED", "root_cause"
    return {
        "rule_id": "FALLBACK_POC_REPLAY",
        "rule_name": "朴素基线（仅重放原始 PoC）",
        "verdict": verdict,
        "pattern": pattern,
        "confidence": "low",
        "human_review": "required",
        "explanation": reason or "未加载任何判定规则，只能以原始 PoC 是否打通作为依据。",
        "evidence_required": [],
        "failure_modes": [],
        "evidence_ids": _material_evidence(evidence, verdict),
        "trace": [],
    }


def evaluate(pack, signals, evidence, vuln_type):
    rules = sorted(pack.get("rules") or [], key=lambda r: r.get("priority", 999))
    trace = []

    for rule in rules:
        if vuln_type not in (rule.get("applies_to") or []):
            trace.append((rule["id"], "skipped"))
            continue
        hit = _match(rule["when"], signals)
        trace.append((rule["id"], "HIT" if hit else "miss"))
        if not hit:
            continue
        return {
            "rule_id": rule["id"],
            "rule_name": rule.get("name", ""),
            "verdict": rule["verdict"],
            "pattern": rule["pattern"],
            "confidence": rule.get("confidence", "medium"),
            "human_review": rule.get("human_review", "none"),
            "explanation": (rule.get("explanation") or "").strip(),
            "evidence_required": rule.get("evidence_required") or [],
            "failure_modes": rule.get("failure_modes") or [],
            "evidence_ids": _material_evidence(evidence, rule["verdict"]),
            "trace": trace,
        }

    if pack.get("fallback") == "strict":
        # 诊断模式：没有规则覆盖就明确说"不知道"，不猜测。
        # 消融实验用它来隔离单条规则的贡献，避免被朴素 fallback 的巧合一致所掩盖。
        return {
            "rule_id": "NO_RULE_MATCHED",
            "rule_name": "无规则覆盖",
            "verdict": "UNVERIFIABLE",
            "pattern": "no_rule_matched",
            "confidence": "low",
            "human_review": "required",
            "explanation": "知识库中没有规则匹配当前信号组合，不做推测。",
            "evidence_required": [],
            "failure_modes": [],
            "evidence_ids": _material_evidence(evidence, "UNVERIFIABLE"),
            "trace": trace,
        }

    return _fallback(signals, evidence, "知识库中没有规则匹配当前信号组合。")
