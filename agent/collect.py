"""取数层：发探针、存证据。这里不做任何判断。

每条证据都带响应体哈希，目的是让报告里的"我打过这个请求"可自证——
这是后面把证据链接进 OctoBus 审计日志的基础。
"""

import hashlib
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request

from .net import open_url, rebase

MARKER = "poc-marker@lab"

BASELINE = {
    "/api/user": {"id": "1"},
    "/api/search": {"name": "alice"},
    "/api/export": {"id": "1"},
}

MUTATIONS = {
    "/api/user": [
        ("or_true", {"id": "1 OR 1=1"}),
        ("bool_true", {"id": "1 AND 1=1"}),
        ("bool_false", {"id": "1 AND 1=2"}),
    ],
    "/api/search": [
        ("or_string", {"name": "alice' OR '1'='1"}),
    ],
    "/api/export": [
        ("or_true", {"id": "1 OR 1=1"}),
    ],
}


def _response(status, ctype, raw):
    body = raw.decode("utf-8", "replace")
    count = None
    try:
        obj = json.loads(body)
        if isinstance(obj, dict) and "count" in obj:
            count = obj["count"]
    except (ValueError, TypeError):
        pass
    return {
        "status": status,
        "ctype": ctype or "",
        "count": count,
        "length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest()[:16],
        "marker_hit": MARKER in body,
        "body": body,
    }


def fetch(base, path, params, timeout=4):
    url = f"{base}{path}?{urlencode(params)}"
    request = {"method": "GET", "url": url, "params": params}
    try:
        req = Request(url, headers={"User-Agent": "retest-agent/0.1"})
        with open_url(req, timeout=timeout) as resp:
            return {"request": request,
                    "response": _response(resp.status, resp.headers.get("Content-Type", ""), resp.read())}
    except HTTPError as exc:
        return {"request": request,
                "response": _response(exc.code, exc.headers.get("Content-Type", ""), exc.read())}
    except (URLError, OSError) as exc:
        return {"request": request,
                "response": {"status": None, "ctype": "", "count": None, "length": 0,
                             "sha256": None, "marker_hit": False, "body": "",
                             "error": f"{type(exc).__name__}: {exc}"}}


def is_blocked(resp):
    """边缘拦截的启发式识别：应用说 JSON，这里回 HTML 403。

    这是启发式而非确证，所以判定层还有"直连源站"这一步做交叉验证。
    真实 WAF 也可能返回 200 的拦截页或直接 RESET 连接，届时该信号会失效。
    """
    return resp["status"] in (403, 406) and "text/html" in resp["ctype"]


def exploited(resp, baseline_count, min_row_delta):
    """可利用判定：命中标记，或行数增量达到阈值。

    刻意不用"有没有报错"做判据 —— 生产环境普遍吞掉了 SQL 报错。
    """
    if resp["status"] is None or is_blocked(resp):
        return False
    if resp["marker_hit"]:
        return True
    if resp["count"] is not None and baseline_count is not None:
        return resp["count"] - baseline_count >= min_row_delta
    return False


def collect(case, min_row_delta=1):
    """跑完一张工单的全部探针，返回证据列表。"""
    if case["vuln_type"] == "access_control":
        from . import access
        return access.collect(case)
    if case["vuln_type"].startswith("xss"):
        from . import xss
        return xss.collect(case)

    case_id = case["case_id"]
    primary = case["ticket"]["endpoint"]
    edge = rebase(case["targets"]["edge"])
    origin = rebase(case["targets"]["origin"])
    sides = [("edge", edge)] if origin == edge else [("edge", edge), ("origin", origin)]

    evidence = []

    for side, base in sides:
        # 版本观测
        v = fetch(base, "/version", {})
        try:
            observed = json.loads(v["response"]["body"]).get("version")
        except (ValueError, TypeError):
            observed = None
        evidence.append({
            "id": f"{case_id}:{side}:version:/version",
            "case_id": case_id, "side": side, "kind": "version",
            "endpoint": "/version", "label": "version",
            "request": v["request"], "response": v["response"],
            "observed_version": observed, "exploited": False, "blocked": False,
        })

        for path, params in BASELINE.items():
            b = fetch(base, path, params)
            baseline_ok = b["response"]["status"] == 200 and (b["response"]["count"] or 0) >= 1
            evidence.append({
                "id": f"{case_id}:{side}:baseline:{path}",
                "case_id": case_id, "side": side, "kind": "baseline",
                "endpoint": path, "label": "baseline",
                "request": b["request"], "response": b["response"],
                "baseline_ok": baseline_ok, "exploited": False,
                "blocked": is_blocked(b["response"]),
            })
            if not baseline_ok:
                continue
            base_count = b["response"]["count"]
            for label, mparams in MUTATIONS.get(path, []):
                m = fetch(base, path, mparams)
                evidence.append({
                    "id": f"{case_id}:{side}:mutation:{path}:{label}",
                    "case_id": case_id, "side": side, "kind": "mutation",
                    "endpoint": path, "label": label,
                    "request": m["request"], "response": m["response"],
                    "exploited": exploited(m["response"], base_count, min_row_delta),
                    "blocked": is_blocked(m["response"]),
                })

        # 工单原始 PoC
        p = fetch(base, primary, case["ticket"]["poc"])
        evidence.append({
            "id": f"{case_id}:{side}:poc:{primary}",
            "case_id": case_id, "side": side, "kind": "poc",
            "endpoint": primary, "label": "ticket_poc",
            "request": p["request"], "response": p["response"],
            "exploited": exploited(p["response"], 1, min_row_delta),
            "blocked": is_blocked(p["response"]),
        })

    return evidence
