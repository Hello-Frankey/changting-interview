#!/usr/bin/env python3
"""XSS 复测靶场 —— 同一段业务逻辑，六种"修复"形态。

与 SQLi 靶场的核心差别
----------------------
SQLi 的判据是"数据有没有改变语义"，一处修好就是修好了。
XSS 的判据是"**数据在哪个上下文里、能不能逃逸出这个上下文**"。
同一个转义函数在 HTML 正文里是安全的，放进 <script> 里可能完全无效。
所以 XSS 复测必须**按上下文分别判定**，不能只测一个反射点。

三个反射上下文（各一个端点，便于隔离判定）
------------------------------------------
  /echo/body    正文：      <div class="result">结果：{q}</div>
  /echo/attr    属性：      <input type="text" name="q" value="{q}">
  /echo/script  脚本字符串： <script>var kw = "{q}";</script>

外加一个存储上下文
------------------
  POST /comment  提交评论，存储后由 /comments 渲染到正文。

VARIANT
-------
  x0_vulnerable    完全不编码（对照组）
  x1_truefix       按上下文分别编码（正文转义 / 属性转义 / JS 字符串转义 + 转义尖括号）
  x2_angle_only    只把 < > 转义成实体，所有上下文共用（最常见的天真修复）
  x3_blacklist     只拦字面量 "<script"（最常见的黑名单）
  x4_csp_only      不编码，只下发 CSP 响应头（属于缓解，不是修复）
  x5_partial       反射点全部正确编码，但存储点没编码
"""

import html
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VARIANT = os.environ.get("VARIANT", "x0_vulnerable")
BIND = os.environ.get("BIND", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8100"))

APP_VERSION = "3.2.0"
CSP = "default-src 'self'; script-src 'self'"

COMMENTS = []          # 进程内存储，够用；重启即清空
BLACKLIST = re.compile(r"<script", re.IGNORECASE)


# ------------------------------------------------------------------ 上下文编码

def esc_angle_only(value):
    """把 & < > 转成实体。注意：它**不处理引号**。

    这正是它作为"修复"会失败的原因 —— 属性上下文和 JS 字符串上下文
    靠的都是引号逃逸，而这两个字符它一个都没管。
    """
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def esc_body(value):
    """HTML 正文：转义 & < > 即可，引号在正文里没有特殊含义。"""
    return html.escape(value, quote=False)


def esc_attr(value):
    """双引号属性值：必须连引号一起转义，否则可以用 " 闭合属性。"""
    return html.escape(value, quote=True)


def esc_script(value):
    """JS 字符串字面量里的一层。

    只做 JSON 编码是不够的：`</script>` 依然会提前闭合脚本块，
    因为 HTML 解析器不认 JS 字符串边界。所以还要把 < > & 转成 \\u 形式。
    这是实践里最常被漏掉的一步，也是本靶场 x1 与"看起来也对"的修复的分界。
    """
    out = json.dumps(value, ensure_ascii=False)[1:-1]
    return out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


ENCODERS = {"body": esc_body, "attr": esc_attr, "script": esc_script}


def encode(context, value):
    """按变体决定用哪种编码。"""
    if VARIANT == "x0_vulnerable":
        return value
    if VARIANT == "x1_truefix":
        return ENCODERS[context](value)
    if VARIANT == "x2_angle_only":
        return esc_angle_only(value)
    if VARIANT == "x3_blacklist":
        return value                      # 交给黑名单在入口处拦
    if VARIANT == "x4_csp_only":
        return value                      # 只靠 CSP
    if VARIANT == "x5_partial":
        return ENCODERS[context](value)   # 反射点正确修复
    return value


def encode_comment(value):
    """存储点的编码策略（与反射点分开，因为 x5 只修了反射点）。"""
    if VARIANT in ("x1_truefix", "x2_angle_only"):
        return ENCODERS["body"](value) if VARIANT == "x1_truefix" else esc_angle_only(value)
    return value


def is_denied(*values):
    """x3 的黑名单：只认字面量 <script。

    <img src=x onerror=...>、属性逃逸、JS 字符串逃逸全都不含这个子串，
    所以这个"修复"能拦住原始 PoC，却拦不住任何一条等价变体。
    """
    return VARIANT == "x3_blacklist" and any(BLACKLIST.search(v or "") for v in values)


# ------------------------------------------------------------------ 页面模板

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>搜索</title></head>
<body>
<div class="result">结果：{v}</div>
</body></html>"""

ATTR_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>搜索</title></head>
<body>
<input type="text" name="q" value="{v}">
</body></html>"""

SCRIPT_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>搜索</title></head>
<body>
<script>var kw = "{v}";</script>
</body></html>"""

LIST_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>评论</title></head>
<body>
<ul>{items}</ul>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "LabApp"

    def version_string(self):
        return f"LabApp/{APP_VERSION}"

    def log_message(self, fmt, *args):
        if os.environ.get("LAB_DEBUG") == "1":
            sys.stderr.write("[%s] %s\n" % (VARIANT, fmt % args))

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        if VARIANT == "x4_csp_only":
            self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query, keep_blank_values=True)
        path = parsed.path
        kw = q.get("q", [""])[0]

        if path == "/healthz":
            return self._send(200, json.dumps({"ok": True, "variant": VARIANT}),
                              "application/json")

        if path == "/version":
            return self._send(200, json.dumps({"app": "search-ui", "version": APP_VERSION}),
                              "application/json")

        if path == "/comment/reset":
            COMMENTS.clear()
            return self._send(200, "ok", "text/plain")

        if path == "/echo/body":
            if is_denied(kw):
                return self._send(400, "非法输入")
            return self._send(200, PAGE.format(v=encode("body", kw)))

        if path == "/echo/attr":
            if is_denied(kw):
                return self._send(400, "非法输入")
            return self._send(200, ATTR_PAGE.format(v=encode("attr", kw)))

        if path == "/echo/script":
            if is_denied(kw):
                return self._send(400, "非法输入")
            return self._send(200, SCRIPT_PAGE.format(v=encode("script", kw)))

        if path == "/comments":
            items = "".join(f"<li>{encode_comment(c)}</li>" for c in COMMENTS)
            return self._send(200, LIST_PAGE.format(items=items))

        return self._send(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/comment":
            return self._send(404, "not found")

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(raw, keep_blank_values=True)
        text = form.get("text", [""])[0]

        if is_denied(text):
            return self._send(400, "非法输入")

        COMMENTS.append(text)
        return self._send(200, "ok", "text/plain")


def main():
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"[{VARIANT}] listening on {BIND}:{PORT}  version={APP_VERSION}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
