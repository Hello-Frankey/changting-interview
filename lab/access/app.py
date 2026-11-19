#!/usr/bin/env python3
"""越权（访问控制缺陷）复测靶场 —— 七种"修复"形态。

与 SQLi / XSS 的根本差别
-----------------------
前两类的探针形态是"单请求自带 payload，看响应有没有异常"。
越权不是。越权的响应**完全正常**：200、结构合法、数据真实。
只有做「跨主体对照」——用 A 的凭证去取 B 的资源——才能发现。

所以探针必须分两阶段：
  1) 以受害者身份（bob）发现他自己的资源标识
  2) 以攻击者身份（alice）去访问同一标识

判定也因此多了一个维度：**响应码不可信**。
写操作尤其危险——「返回 403」不等于「没生效」。a6 变体就是先删除再鉴权，
响应是 403，数据已经没了。

VARIANT
-------
  a0_vulnerable    只校验登录、不校验归属（对照组）
  a1_truefix       全部入口绑定「主体-对象」关系，管理接口校验角色
  a2_list_only     列表过滤了别人的订单，但单对象接口不校验归属
  a3_uuid          ID 改成不可猜测的 UUID，但仍然不校验归属
  a4_partial       详情接口修了，子资源接口（/items）没修
  a5_vertical      水平越权修了，管理接口仍然任何登录用户可调
  a6_write_silent  读已修好，但删除操作用「先删后判」，403 其实已经生效
"""

import json
import os
import re
import secrets
import sys
import uuid as uuidlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VARIANT = os.environ.get("VARIANT", "a0_vulnerable")
BIND = os.environ.get("BIND", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8200"))
APP_VERSION = "5.1.0"

UUID_NS = uuidlib.UUID("6f1c2a9e-0d3b-4f5a-9c7e-1b2d3e4f5a6b")

USERS = [
    {"id": 1, "username": "alice", "role": "user"},
    {"id": 2, "username": "bob", "role": "user"},
    {"id": 3, "username": "admin", "role": "admin"},
]

SEED_ORDERS = [
    {"id": 1, "owner_id": 1, "item": "机械键盘", "amount": 499},
    {"id": 2, "owner_id": 2, "item": "显示器", "amount": 1299},
    {"id": 3, "owner_id": 1, "item": "鼠标", "amount": 199},
]

ORDERS = []
SESSIONS = {}


def public_id(order_id):
    """a3 之前用自增数字；a3 改用不可猜测的 UUID。"""
    if VARIANT == "a3_uuid":
        return str(uuidlib.uuid5(UUID_NS, f"order-{order_id}"))
    return str(order_id)


def reset_state():
    ORDERS.clear()
    for o in SEED_ORDERS:
        ORDERS.append({**o, "oid": public_id(o["id"])})


def find_order(oid):
    return next((o for o in ORDERS if o["oid"] == oid), None)


def user_of(headers):
    auth = headers.get("Authorization") or ""
    if not auth.startswith("Bearer "):
        return None
    uid = SESSIONS.get(auth[7:])
    return next((u for u in USERS if u["id"] == uid), None)


# ---------------------------------------------------------------- 授权逻辑

def can_read_order(user, order):
    """读单个订单是否允许。"""
    if VARIANT in ("a0_vulnerable", "a2_list_only", "a3_uuid"):
        return True                      # 只校验了登录
    return order["owner_id"] == user["id"]


def can_read_items(user, order):
    """子资源接口。a4 只修了详情，没修这里。"""
    if VARIANT in ("a0_vulnerable", "a2_list_only", "a3_uuid", "a4_partial"):
        return True
    return order["owner_id"] == user["id"]


def can_admin(user):
    """管理接口。a5 水平修了、垂直没修；a2 只漏了单对象接口，管理接口是好的。"""
    if VARIANT in ("a0_vulnerable", "a3_uuid", "a5_vertical"):
        return True
    return user["role"] == "admin"


def list_orders(user):
    """列表是否过滤。a0 连列表都不过滤。"""
    if VARIANT == "a0_vulnerable":
        return list(ORDERS)
    return [o for o in ORDERS if o["owner_id"] == user["id"]]


def delete_order(user, order):
    """返回 (status, deleted)。

    a6 的 bug：先执行删除，再判断归属。于是越权删除返回 403，
    但数据已经没了——只看响应码的复测会判"已拦截"。
    """
    if VARIANT == "a6_write_silent":
        if order in ORDERS:
            ORDERS.remove(order)
        if order["owner_id"] != user["id"]:
            return 403, True
        return 200, True

    if not can_read_order(user, order):
        return 403, False
    if order in ORDERS:
        ORDERS.remove(order)
    return 200, True


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "LabApp"

    def version_string(self):
        return f"LabApp/{APP_VERSION}"

    def log_message(self, fmt, *args):
        if os.environ.get("LAB_DEBUG") == "1":
            sys.stderr.write("[%s] %s\n" % (VARIANT, fmt % args))

    def _send(self, code, payload, ctype="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_form(self):
        length = int(self.headers.get("Content-Length") or 0)
        return parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)

    def _require_user(self):
        user = user_of(self.headers)
        if not user:
            self._send(401, {"error": "unauthorized"})
        return user

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/reset":
            reset_state()
            return self._send(200, {"ok": True, "count": len(ORDERS)})

        if path == "/login":
            form = self._read_form()
            username = form.get("username", [""])[0]
            user = next((u for u in USERS if u["username"] == username), None)
            if not user:
                return self._send(401, {"error": "bad_user"})
            token = secrets.token_hex(8)
            SESSIONS[token] = user["id"]
            return self._send(200, {"token": token, "user": user})

        return self._send(404, {"error": "not_found"})

    def do_GET(self):
        parts = [p for p in urlparse(self.path).path.split("/") if p]

        if parts == ["healthz"]:
            return self._send(200, {"ok": True, "variant": VARIANT})
        if parts == ["version"]:
            return self._send(200, {"app": "order-service", "version": APP_VERSION})

        user = self._require_user()
        if not user:
            return

        if parts == ["api", "orders"]:
            orders = list_orders(user)
            return self._send(200, {"count": len(orders), "orders": orders})

        if len(parts) == 3 and parts[:2] == ["api", "orders"]:
            order = find_order(parts[2])
            if not order:
                return self._send(404, {"error": "not_found"})
            if not can_read_order(user, order):
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"order": order})

        if len(parts) == 4 and parts[:2] == ["api", "orders"] and parts[3] == "items":
            order = find_order(parts[2])
            if not order:
                return self._send(404, {"error": "not_found"})
            if not can_read_items(user, order):
                return self._send(403, {"error": "forbidden"})
            items = [{"sku": f"SKU-{order['id']}-1", "qty": 1, "order_owner": order["owner_id"]}]
            return self._send(200, {"count": len(items), "items": items})

        if parts == ["api", "admin", "users"]:
            if not can_admin(user):
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"count": len(USERS), "users": USERS})

        return self._send(404, {"error": "not_found"})

    def do_DELETE(self):
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        user = self._require_user()
        if not user:
            return

        if len(parts) == 3 and parts[:2] == ["api", "orders"]:
            order = find_order(parts[2])
            if not order:
                return self._send(404, {"error": "not_found"})
            status, _deleted = delete_order(user, order)
            if status == 403:
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"ok": True, "deleted": order["oid"]})

        return self._send(404, {"error": "not_found"})


def main():
    reset_state()
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"[{VARIANT}] listening on {BIND}:{PORT}  version={APP_VERSION}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
