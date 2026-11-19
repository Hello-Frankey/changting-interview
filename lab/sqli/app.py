#!/usr/bin/env python3
"""SQLi 复测靶场 —— 一个应用，六种修复形态。

设计意图
--------
同一份业务逻辑（用户查询 / 搜索 / 导出），用 VARIANT 环境变量切换"修复程度"。
复测要回答的不是"这段代码改没改"，而是"不可信输入通向 SQL 的通道，是否真的被关上了"。

VARIANT
-------
  v0_vulnerable   未修复。对照组，原始 PoC 直接可利用。
  v1_truefix      根因修复。三个入口全部参数化，通道被切断。
  v2_version_only 表层变更：代码一字未改，只把版本号报成 2.0.0。
  v3_waf_only     表层变更：代码一字未改，只在边缘网关拦截（配合 edge.py）。
                  应用本身仍可直连，模拟"内网可达但公网被 WAF 挡着"。
  v4_blacklist    假净化：加了关键词黑名单，拦得住原始 PoC，拦不住同类变体。
  v5_partial      部分修复：只修了被举报的 /api/user，兄弟入口仍是拼接。
  v6_broken       服务活着，但所有接口都返回空结果（依赖挂了 / 表被清空）。
                  用来区分"网络不可达"与"活着但验证不了"——两者都必须判无法验证。

约定
----
所有接口返回 {"ok": bool, "count": n, "rows": [...]}，便于用"返回行数"做可观测信号。
生产环境默认不返回 SQL 报错（LAB_DEBUG=1 才返回），因为"报错消失"是典型的伪信号。
"""

import json
import os
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VARIANT = os.environ.get("VARIANT", "v0_vulnerable")
HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(HERE, "lab.db"))
PORT = int(os.environ.get("PORT", "8000"))
BIND = os.environ.get("BIND", "127.0.0.1")   # 容器内需 0.0.0.0
DEBUG = os.environ.get("LAB_DEBUG", "0") == "1"

# 只有 v2 声称自己升级了版本；其余都还是工单里记录的 1.4.2
APP_VERSION = "2.0.0" if VARIANT == "v2_version_only" else "1.4.2"

SEED = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT);
INSERT OR IGNORE INTO users VALUES
  (1,'alice','alice@example.com','user'),
  (2,'bob',  'bob@example.com',  'user'),
  (3,'carol','carol@example.com','admin');

CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY, k TEXT, v TEXT, note TEXT);
INSERT OR IGNORE INTO secrets VALUES
  (1,'db_password','S3cr3t-Lab-Only','db'),
  (2,'api_key',    'ak_lab_9f2c',    'svc');
"""

# v4 的黑名单：一个"看起来挺认真"的实现——引号、注释、union、select 都拦了。
# 但它对数字型注入毫无作用，因为数字型注入根本不需要引号。
DENY = ("'", '"', "--", "/*", "union", "select")


def init_db():
    """幂等初始化，允许六个变体进程共享同一个 db 文件。"""
    last = None
    for _ in range(5):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5)
            try:
                conn.executescript(SEED)
                conn.commit()
            finally:
                conn.close()
            return
        except sqlite3.OperationalError as exc:  # 并发启动时的短暂锁
            last = exc
            time.sleep(0.2)
    raise SystemExit(f"init_db failed: {last}")


def fetch(sql, params=()):
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def is_denied(value):
    low = value.lower()
    return any(tok in low for tok in DENY)


# ---------------------------------------------------------------- 三个入口
# v1 全部参数化；v5 只参数化了 /api/user；其余变体一律字符串拼接。

def rows_user(uid):
    if VARIANT in ("v1_truefix", "v5_partial"):
        return fetch("SELECT id,name,email,role FROM users WHERE id = ?", (uid,))
    return fetch(f"SELECT id,name,email,role FROM users WHERE id = {uid}")


def rows_search(name):
    if VARIANT == "v1_truefix":
        return fetch("SELECT id,name,email FROM users WHERE name = ?", (name,))
    return fetch(f"SELECT id,name,email FROM users WHERE name = '{name}'")


def rows_export(uid):
    if VARIANT == "v1_truefix":
        return fetch("SELECT id,name,email,role FROM users WHERE id = ?", (uid,))
    return fetch(f"SELECT id,name,email,role FROM users WHERE id = {uid}")


# ---------------------------------------------------------------- HTTP 层

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"   # 每个请求一条连接，简单且不会挂住
    server_version = "LabApp"

    def version_string(self):
        return f"LabApp/{APP_VERSION}"

    def log_message(self, fmt, *args):
        if DEBUG:
            sys.stderr.write("[%s] %s\n" % (VARIANT, fmt % args))

    def respond(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-App-Version", APP_VERSION)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path
        try:
            if path == "/healthz":
                return self.respond(200, {"ok": True, "variant": VARIANT, "version": APP_VERSION})

            if path == "/version":
                return self.respond(200, {"app": "user-service", "version": APP_VERSION})

            # 服务进程活着，但业务数据取不到。这不是"已修复"，是"验证不了"。
            if VARIANT == "v6_broken" and path.startswith("/api/"):
                return self.respond(200, {"ok": True, "count": 0, "rows": []})

            if path == "/api/user":
                uid = q.get("id", [""])[0]
                if VARIANT == "v4_blacklist" and is_denied(uid):
                    return self.respond(400, {"error": "illegal_input"})
                rows = rows_user(uid)
                return self.respond(200, {"ok": True, "count": len(rows), "rows": rows})

            if path == "/api/search":
                name = q.get("name", [""])[0]
                if VARIANT == "v4_blacklist" and is_denied(name):
                    return self.respond(400, {"error": "illegal_input"})
                rows = rows_search(name)
                return self.respond(200, {"ok": True, "count": len(rows), "rows": rows})

            if path == "/api/export":
                uid = q.get("id", [""])[0]
                if VARIANT == "v4_blacklist" and is_denied(uid):
                    return self.respond(400, {"error": "illegal_input"})
                rows = rows_export(uid)
                return self.respond(200, {"ok": True, "count": len(rows), "rows": rows})

            return self.respond(404, {"error": "not_found", "path": path})

        except Exception as exc:  # noqa: BLE001
            # 生产环境不把 SQL 报错抛给调用方：报错信息本身就是一个不可靠的判据
            payload = {"error": "internal_error"}
            if DEBUG:
                payload["detail"] = str(exc)
            return self.respond(500, payload)


def main():
    init_db()
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"[{VARIANT}] listening on {BIND}:{PORT}  version={APP_VERSION}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
