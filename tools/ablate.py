#!/usr/bin/env python3
"""消融实验：证明知识库确实在影响输出。

考核说明 5.2 的自检方式是"若移除该部分知识后输出质量无明显变化，则该知识不构成
实质经验"。这里把它拆成三组可执行对照：

  对照 1  完整知识库 vs 空知识库
          空库走"只重放 PoC"的朴素 fallback，代表一个没有领域知识的 Agent。
  对照 2  逐条移除规则（严格模式）
          没有规则覆盖时直接判 UNVERIFIABLE，不猜测。若用朴素 fallback 做这一步，
          某些规则会被"巧合一致"掩盖，得出"该规则未被消费"的错误结论。
  对照 3  规则命中统计
          "这次判定到底触发了哪条规则"，直接证明知识被消费。

用法
----
  cd lab/sqli && ./run_local.sh up
  cd lab/xss  && ./run_local.sh up
  python3 tools/ablate.py
  python3 tools/ablate.py --lab xss
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


def build_dataset(labs, min_row_delta):
    dataset = []
    for lab_name, cases in labs:
        for case in cases:
            ev = collect.collect(case, min_row_delta)   # 只跑一次，后续复用
            sig = signals.compute(ev, case)
            dataset.append((lab_name, case, ev, sig))
    return dataset


def score(pack, dataset):
    verdict_hits = pattern_hits = exact = 0
    broken = []
    for lab_name, case, ev, sig in dataset:
        result = judge.evaluate(pack, sig, ev, case["vuln_type"])
        ok_v = result["verdict"] == case["expected_verdict"]
        ok_p = result["pattern"] == case["expected_pattern"]
        verdict_hits += ok_v
        pattern_hits += ok_p
        exact += ok_v and ok_p
        if not (ok_v and ok_p):
            broken.append(case["case_id"])
    return verdict_hits, pattern_hits, exact, broken


def strip_rule(pack, rule_id):
    return {**pack, "rules": [r for r in pack["rules"] if r["id"] != rule_id]}


def pad(text, width):
    display = sum(2 if ord(c) > 127 else 1 for c in text)
    return text + " " * max(0, width - display)


def row(label, stats, total, broken, flag=""):
    v, p, e, _ = stats
    print(f"{pad(label, 28)}{v:>5}/{total}{p:>7}/{total}{e:>8}/{total}   "
          f"{','.join(broken) if broken else '-'}{flag}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", default="all", help="all | sqli | xss")
    args = ap.parse_args()

    pack = judge.load_pack()
    min_row_delta = int(pack["thresholds"]["min_row_delta"]["value"])

    labs = [(n, c) for n, c in load_labs(args.lab) if alive(c)]
    if not labs:
        print("没有任何靶场在运行。先在 lab/sqli 与 lab/xss 下执行 ./run_local.sh up")
        return 2

    dataset = build_dataset(labs, min_row_delta)
    total = len(dataset)

    print(f"靶场: {', '.join(n for n, _ in labs)}    样本 {total}    规则 {len(pack['rules'])}\n")
    print(f"{pad('配置', 28)}{'裁决':>7}{'模式':>9}{'一致':>7}    失效样本")
    print("-" * 92)

    base = score(pack, dataset)
    row("完整知识库（基准）", base, total, base[3])

    naive = score({**pack, "rules": []}, dataset)
    row("无知识库（朴素 fallback）", naive, total, naive[3])

    print("-" * 92)
    print("对照 2：逐条移除（严格模式，无规则覆盖即 UNVERIFIABLE）")
    print("-" * 92)

    rows = [("完整知识库", base), ("无知识库（朴素）", naive)]
    strict_pack = {**pack, "fallback": "strict"}
    dead = []

    for rule in pack["rules"]:
        stats = score(strip_rule(strict_pack, rule["id"]), dataset)
        rows.append((f"移除 {rule['id']}", stats))
        if stats[:3] == base[:3]:
            dead.append(rule["id"])
        row(f"移除 {rule['id']}", stats, total, stats[3],
            flag="  ← 无影响" if stats[:3] == base[:3] else "")

    print("-" * 92)
    print("对照 3：规则命中统计")
    print("-" * 92)

    fires = {r["id"]: [] for r in pack["rules"]}
    for lab_name, case, ev, sig in dataset:
        result = judge.evaluate(pack, sig, ev, case["vuln_type"])
        rid = result["rule_id"]
        if rid in fires:
            fires[rid].append(case["case_id"])

    for rule in pack["rules"]:
        hit = fires[rule["id"]]
        print(f"  {pad(rule['id'], 26)} 命中 {len(hit)} 次   "
              f"{','.join(hit) if hit else '从未命中 ← 冗余规则'}")

    print("-" * 92)
    print("按漏洞类型分解")
    print("-" * 92)
    for lab_name, cases in labs:
        sub = [d for d in dataset if d[0] == lab_name]
        s_base = score(pack, sub)
        s_naive = score({**pack, "rules": []}, sub)
        print(f"  {pad(lab_name, 8)} 完整 {s_base[0]}/{len(sub)}（模式 {s_base[1]}）"
              f"    无知识库 {s_naive[0]}/{len(sub)}（模式 {s_naive[1]}）")

    print("-" * 92)
    print(f"\n知识库带来的裁决提升: {base[0]}/{total} vs {naive[0]}/{total}  (+{base[0] - naive[0]})")
    print(f"知识库带来的模式提升: {base[1]}/{total} vs {naive[1]}/{total}  (+{base[1] - naive[1]})")
    print(f"完全一致提升:         {base[2]}/{total} vs {naive[2]}/{total}  (+{base[2] - naive[2]})")

    never = [rid for rid, hit in fires.items() if not hit]
    if never:
        print(f"\n从未命中的规则: {', '.join(never)} —— 应删除或重写")
    else:
        print("\n每条规则都至少命中一次；去掉任意一条，严格模式下输出都会变化。")

    out = os.path.join(ROOT, "out", "ablation.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"total": total,
                   "baseline": {"verdict": base[0], "pattern": base[1], "exact": base[2]},
                   "naive": {"verdict": naive[0], "pattern": naive[1], "exact": naive[2]},
                   "rows": [{"config": c, "verdict": s[0], "pattern": s[1],
                             "exact": s[2], "broken": s[3]} for c, s in rows],
                   "rule_hits": fires},
                  fh, ensure_ascii=False, indent=2)
    print(f"\n明细已写入 {os.path.relpath(out, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
