"""信号层：把证据压成规则可以求值的布尔量。

这里只做"事实的归纳"，不做"结论的选择"。
每个信号的定义必须与 knowledge/false-fix-patterns.yaml 里的 signal_vocabulary 一致。
"""


def compute(evidence, case):
    if case["vuln_type"] == "access_control":
        from . import access
        return access.compute(evidence, case)
    if case["vuln_type"].startswith("xss"):
        from . import xss
        return xss.compute(evidence, case)

    primary = case["ticket"]["endpoint"]

    connection_ok = any(e["response"]["status"] is not None for e in evidence)

    base_primary = [e for e in evidence
                    if e["kind"] == "baseline" and e["side"] == "edge" and e["endpoint"] == primary]
    baseline_ok = any(e.get("baseline_ok") for e in base_primary)
    reachable = baseline_ok

    poc_edge = next((e for e in evidence if e["kind"] == "poc" and e["side"] == "edge"), None)
    poc_effective = bool(poc_edge and poc_edge["exploited"])
    poc_neutralized = reachable and not poc_effective

    edge_mut_primary = [e for e in evidence
                        if e["kind"] == "mutation" and e["side"] == "edge" and e["endpoint"] == primary]
    primary_effective = any(e["exploited"] for e in edge_mut_primary)
    mutation_effective = primary_effective

    has_origin = any(e["side"] == "origin" for e in evidence)
    origin_mut_primary = [e for e in evidence
                          if e["kind"] == "mutation" and e["side"] == "origin" and e["endpoint"] == primary]
    origin_primary_effective = any(e["exploited"] for e in origin_mut_primary)
    origin_only_effective = bool(has_origin and not primary_effective and origin_primary_effective)

    sibling_effective = any(e["exploited"] for e in evidence
                            if e["kind"] == "mutation" and e["endpoint"] != primary)

    observed_version = next((e.get("observed_version") for e in evidence
                             if e["kind"] == "version" and e["side"] == "edge"), None)
    version_changed = bool(observed_version) and observed_version != case["reported_version"]

    edge_block_observed = any(e["blocked"] for e in evidence if e["side"] == "edge")

    return {
        "connection_ok": connection_ok,
        "baseline_ok": baseline_ok,
        "reachable": reachable,
        "poc_effective": poc_effective,
        "poc_neutralized": poc_neutralized,
        "primary_effective": primary_effective,
        "mutation_effective": mutation_effective,
        "sibling_effective": sibling_effective,
        "origin_only_effective": origin_only_effective,
        "version_changed": version_changed,
        "edge_block_observed": edge_block_observed,
        # 观测值也带上，纯为报告可读性；规则不依赖它们
        "_observed_version": observed_version,
        "_reported_version": case["reported_version"],
    }
