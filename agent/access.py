"""越权取数与信号 —— 跨主体对照探针。

与 SQLi / XSS 最大的不同：越权的响应是"正常"的。
200、结构合法、数据真实，单看一个请求永远发现不了。

所以探针分两阶段：
  阶段一（受害者视角）：bob 登录，列出自己的订单，拿到资源标识
  阶段二（攻击者视角）：alice 登录，用同一标识去访问

判定还要多看一步：**写操作不能只看响应码**。
a6 的删除是"先删后判"，返回 403，但数据已经没了。
所以删除之后必须再用 bob 的身份回读一次，确认状态是否真的没变。
"""

import hashlib
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request

from .net import open_url, rebase

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _parse(status, ctype, raw):
    body = raw.decode("utf-8", "replace")
    data = None
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        pass
    return {"status": status, "ctype": ctype or "", "length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()[:16], "body": body, "json": data}


def call(base, method, path, token=None, form=None, timeout=4):
    headers = {"User-Agent": "retest-agent/0.1"}
    data = None
    if form is not None:
        data = urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(base + path, data=data, headers=headers, method=method)
    try:
        with open_url(req, timeout=timeout) as resp:
            return _parse(resp.status, resp.headers.get("Content-Type", ""), resp.read())
    except HTTPError as exc:
        return _parse(exc.code, exc.headers.get("Content-Type", ""), exc.read())
    except (URLError, OSError) as exc:
        return {"status": None, "ctype": "", "length": 0, "sha256": None,
                "body": "", "json": None, "error": f"{type(exc).__name__}: {exc}"}


def login(base, username):
    resp = call(base, "POST", "/login", form={"username": username})
    token = (resp.get("json") or {}).get("token")
    return token, resp


def order_ids(resp):
    data = resp.get("json") or {}
    return [o.get("oid") for o in (data.get("orders") or []) if o.get("oid")]


def collect(case):
    base = rebase(case["targets"]["edge"])
    cid = case["case_id"]
    ev = []

    def add(kind, endpoint, resp, label=None, **extra):
        rec = {"id": f"{cid}:{kind}", "case_id": cid, "side": "edge",
               "kind": kind, "endpoint": endpoint, "label": label or kind,
               "request": {"method": kind, "path": endpoint},
               "response": resp, "exploited": False, "blocked": False}
        rec.update(extra)
        ev.append(rec)
        return rec

    # 复原状态：a6 的删除是破坏性的
    add("reset", "/reset", call(base, "POST", "/reset"))

    token_a, login_a = login(base, "alice")
    token_b, login_b = login(base, "bob")
    add("login", "/login", login_a, label="alice")
    add("login", "/login", login_b, label="bob")

    alice_list = call(base, "GET", "/api/orders", token=token_a)
    bob_list = call(base, "GET", "/api/orders", token=token_b)
    add("alice_list", "/api/orders", alice_list)
    bob_rec = add("bob_list", "/api/orders", bob_list)

    alice_oids = order_ids(alice_list)
    bob_oids = order_ids(bob_list)
    alice_oid = alice_oids[0] if alice_oids else None
    bob_oid = bob_oids[0] if bob_oids else None

    if not alice_oid or not bob_oid:
        return ev

    # 基线：alice 读自己的订单，必须成功，否则整个判定无意义
    add("baseline", f"/api/orders/{alice_oid}",
        call(base, "GET", f"/api/orders/{alice_oid}", token=token_a))

    # 水平越权：alice 读 bob 的订单
    add("horizontal", f"/api/orders/{bob_oid}",
        call(base, "GET", f"/api/orders/{bob_oid}", token=token_a))

    # 兄弟入口：同一订单的子资源
    add("sibling", f"/api/orders/{bob_oid}/items",
        call(base, "GET", f"/api/orders/{bob_oid}/items", token=token_a))

    # 垂直越权：普通用户调管理接口
    add("vertical", "/api/admin/users",
        call(base, "GET", "/api/admin/users", token=token_a))

    # 写操作：alice 删除 bob 的订单，再用 bob 的身份回读
    delete_resp = call(base, "DELETE", f"/api/orders/{bob_oid}", token=token_a)
    add("delete", f"/api/orders/{bob_oid}", delete_resp)
    add("after_delete", f"/api/orders/{bob_oid}",
        call(base, "GET", f"/api/orders/{bob_oid}", token=token_b))

    return ev


def compute(evidence, case):
    def get(kind):
        return next((e for e in evidence if e["kind"] == kind), None)

    connection_ok = any(e["response"]["status"] is not None for e in evidence)

    logins = [e for e in evidence if e["kind"] == "login"]
    auth_ok = len(logins) == 2 and all(e["response"]["status"] == 200 for e in logins)

    baseline = get("baseline")
    baseline_ok = bool(baseline and baseline["response"]["status"] == 200)

    bob_list = get("bob_list")
    bob_oids = order_ids(bob_list["response"]) if bob_list else []
    victim_found = bool(bob_oids)
    bob_oid = bob_oids[0] if bob_oids else None

    reachable = bool(auth_ok and baseline_ok and victim_found)

    def leaked(kind):
        e = get(kind)
        return bool(e and e["response"]["status"] == 200)

    horizontal_effective = leaked("horizontal")
    sibling_effective = leaked("sibling")
    vertical_effective = leaked("vertical")

    alice_list = get("alice_list")
    alice_oids = order_ids(alice_list["response"]) if alice_list else []
    list_filtered = bool(victim_found and bob_oid not in alice_oids)

    id_format = "uuid" if bob_oid and UUID_RE.match(str(bob_oid)) else "numeric"

    dele = get("delete")
    after = get("after_delete")
    delete_status = dele["response"]["status"] if dele else None
    after_status = after["response"]["status"] if after else None
    # 403 但对象已经不存在 —— 越权写入已经生效
    silent_write_effective = bool(delete_status in (401, 403) and after_status == 404)

    return {
        "connection_ok": connection_ok,
        "auth_ok": auth_ok,
        "baseline_ok": baseline_ok,
        "victim_resource_found": victim_found,
        "reachable": reachable,
        "horizontal_effective": horizontal_effective,
        "sibling_effective": sibling_effective,
        "vertical_effective": vertical_effective,
        "list_filtered": list_filtered,
        "id_format": id_format,
        "silent_write_effective": silent_write_effective,
        "_delete_status": delete_status,
        "_after_status": after_status,
    }
