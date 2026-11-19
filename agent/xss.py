"""XSS 取数与信号 —— 与 SQLi 的关键差别是"按上下文分别判定"。

判定原则：**反射不等于可执行。**
一个字符串原样出现在响应里，并不构成 XSS；必须证明它逃逸出了所在的上下文。
所以这里对正文 / 属性 / JS 字符串三个上下文各发一条针对性 payload，
检查"逃逸序列"是否原样幸存。

为什么 payload 要带统一前缀 `xsprobe_7f3a`
--------------------------------------------
判"原样幸存"用的是子串匹配。若 payload 直接以 `"` 开头，正确转义后的 `\\"`
里仍然含有 `"`，会造成假阳性。加一个前缀后，只有当整段（含前缀）原样出现，
才说明没有发生任何转义。
"""

import hashlib
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request

from .net import open_url, rebase

TOKEN = "xsprobe_7f3a"

CONTEXT_PAYLOADS = {
    "body": TOKEN + "<svg/onload=alert(1)>",
    "attr": TOKEN + '" onmouseover="alert(1)',
    "script": TOKEN + '";alert(1);//',
}

CONTEXT_ENDPOINT = {
    "body": "/echo/body",
    "attr": "/echo/attr",
    "script": "/echo/script",
}

STORED_PAYLOAD = TOKEN + "<img src=x onerror=alert(1)>"
CANARY = TOKEN + '<z"w>'


def _response(status, ctype, raw, headers):
    body = raw.decode("utf-8", "replace")
    return {
        "status": status,
        "ctype": ctype or "",
        "length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest()[:16],
        "csp": (headers or {}).get("Content-Security-Policy"),
        "body": body,
    }


def fetch(base, path, params=None, form=None, timeout=4):
    url = base + path + (("?" + urlencode(params)) if params else "")
    data = urlencode(form).encode() if form is not None else None
    req = Request(url, data=data, headers={"User-Agent": "retest-agent/0.1"})
    try:
        with open_url(req, timeout=timeout) as resp:
            return {"request": {"method": "POST" if data else "GET", "url": url, "params": params, "form": form},
                    "response": _response(resp.status, resp.headers.get("Content-Type", ""),
                                          resp.read(), dict(resp.headers))}
    except HTTPError as exc:
        return {"request": {"method": "POST" if data else "GET", "url": url, "params": params, "form": form},
                "response": _response(exc.code, exc.headers.get("Content-Type", ""),
                                      exc.read(), dict(exc.headers))}
    except (URLError, OSError) as exc:
        return {"request": {"method": "POST" if data else "GET", "url": url, "params": params, "form": form},
                "response": {"status": None, "ctype": "", "length": 0, "sha256": None,
                             "csp": None, "body": "", "error": f"{type(exc).__name__}: {exc}"}}


def survived(resp, payload):
    """逃逸序列是否原样幸存。"""
    return resp["status"] == 200 and payload in resp["body"]


def collect(case):
    base = rebase(case["targets"]["edge"])
    case_id = case["case_id"]
    evidence = []

    v = fetch(base, "/version")
    try:
        observed = json.loads(v["response"]["body"]).get("version")
    except (ValueError, TypeError):
        observed = None
    evidence.append({"id": f"{case_id}:version", "case_id": case_id, "side": "edge",
                     "kind": "version", "endpoint": "/version", "label": "version",
                     "request": v["request"], "response": v["response"],
                     "observed_version": observed, "exploited": False, "blocked": False})

    b = fetch(base, "/echo/body", params={"q": "hello"})
    baseline_ok = b["response"]["status"] == 200 and "hello" in b["response"]["body"]
    evidence.append({"id": f"{case_id}:baseline", "case_id": case_id, "side": "edge",
                     "kind": "baseline", "endpoint": "/echo/body", "label": "baseline",
                     "request": b["request"], "response": b["response"],
                     "baseline_ok": baseline_ok, "exploited": False, "blocked": False})

    poc_q = case["ticket"]["poc"]["q"]
    p = fetch(base, "/echo/body", params={"q": poc_q})
    evidence.append({"id": f"{case_id}:poc", "case_id": case_id, "side": "edge",
                     "kind": "poc", "endpoint": "/echo/body", "label": "ticket_poc",
                     "request": p["request"], "response": p["response"],
                     "exploited": survived(p["response"], poc_q),
                     "blocked": p["response"]["status"] in (400, 403)})

    for ctx, payload in CONTEXT_PAYLOADS.items():
        r = fetch(base, CONTEXT_ENDPOINT[ctx], params={"q": payload})
        evidence.append({"id": f"{case_id}:context:{ctx}", "case_id": case_id, "side": "edge",
                         "kind": "context", "endpoint": CONTEXT_ENDPOINT[ctx], "label": ctx,
                         "request": r["request"], "response": r["response"],
                         "exploited": survived(r["response"], payload),
                         "blocked": r["response"]["status"] in (400, 403)})

    c = fetch(base, "/echo/body", params={"q": CANARY})
    encoded = (TOKEN + "&") in c["response"]["body"] or (TOKEN + "\\u003c") in c["response"]["body"]
    evidence.append({"id": f"{case_id}:canary", "case_id": case_id, "side": "edge",
                     "kind": "canary", "endpoint": "/echo/body", "label": "canary",
                     "request": c["request"], "response": c["response"],
                     "encoded": encoded, "exploited": False, "blocked": False})

    fetch(base, "/comment/reset")
    fetch(base, "/comment", form={"text": STORED_PAYLOAD})
    lst = fetch(base, "/comments")
    evidence.append({"id": f"{case_id}:stored", "case_id": case_id, "side": "edge",
                     "kind": "stored", "endpoint": "/comments", "label": "stored",
                     "request": lst["request"], "response": lst["response"],
                     "exploited": survived(lst["response"], STORED_PAYLOAD),
                     "blocked": lst["response"]["status"] in (400, 403)})

    return evidence


def compute(evidence, case):
    connection_ok = any(e["response"]["status"] is not None for e in evidence)
    baseline_ok = any(e.get("baseline_ok") for e in evidence if e["kind"] == "baseline")
    reachable = baseline_ok

    poc = next((e for e in evidence if e["kind"] == "poc"), None)
    poc_effective = bool(poc and poc["exploited"])
    poc_neutralized = reachable and not poc_effective

    contexts = {e["label"]: bool(e["exploited"]) for e in evidence if e["kind"] == "context"}
    body_breakable = contexts.get("body", False)
    attr_breakable = contexts.get("attr", False)
    script_breakable = contexts.get("script", False)
    any_context_breakable = any(contexts.values())
    all_contexts_breakable = bool(contexts) and all(contexts.values())
    reported_surface_safe = reachable and not any_context_breakable

    stored = next((e for e in evidence if e["kind"] == "stored"), None)
    stored_effective = bool(stored and stored["exploited"])

    canary = next((e for e in evidence if e["kind"] == "canary"), None)
    encoding_observed = bool(canary and canary["encoded"])
    csp_present = any(e["response"].get("csp") for e in evidence)

    return {
        "connection_ok": connection_ok,
        "baseline_ok": baseline_ok,
        "reachable": reachable,
        "poc_effective": poc_effective,
        "poc_neutralized": poc_neutralized,
        "body_breakable": body_breakable,
        "attr_breakable": attr_breakable,
        "script_breakable": script_breakable,
        "any_context_breakable": any_context_breakable,
        "all_contexts_breakable": all_contexts_breakable,
        "reported_surface_safe": reported_surface_safe,
        "stored_effective": stored_effective,
        "encoding_observed": encoding_observed,
        "csp_present": csp_present,
    }
