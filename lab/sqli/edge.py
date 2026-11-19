#!/usr/bin/env python3
"""边缘网关（模拟 WAF / 反代）—— 用于 v3_waf_only 变体。

它只做一件事：按规则匹配原始 query string，命中就返回 403。
它**不修改后端代码**，后端仍然可直连。这正是"虚拟补丁"的本质：
风险在边界被挡住，但漏洞本体还在，一旦绕过边界或换条路进来，依然可利用。

注意
----
返回页刻意做成 nginx 风格的通用 403，不带任何"这是 WAF"的标记。
真实复测里你也不会看到 X-Blocked-By 这种头，必须靠"响应形态与应用不一致"来推断。
"""

import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import unquote_plus, urlsplit
import urllib.request
from urllib.request import Request

# 转发必须直连源站，不能走系统代理
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

ORIGIN = os.environ.get("ORIGIN", "http://127.0.0.1:8003").rstrip("/")
PORT = int(os.environ.get("EDGE_PORT", "8004"))
BIND = os.environ.get("BIND", "127.0.0.1")
DEBUG = os.environ.get("LAB_DEBUG", "0") == "1"

RULES = [
    ("union_select", re.compile(r"(?i)union\s+select")),
    ("boolean_or", re.compile(r"(?i)\bor\b\s+\d+\s*=")),
    ("quote", re.compile(r"'")),
    ("time_based", re.compile(r"(?i)sleep\s*\(")),
]

BLOCK_PAGE = (
    "<html>\r\n<head><title>403 Forbidden</title></head>\r\n"
    "<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n"
    "</body>\r\n</html>\r\n"
).encode()


class Edge(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "nginx"

    def version_string(self):
        return "nginx"

    def log_message(self, fmt, *args):
        if DEBUG:
            sys.stderr.write("[edge] %s\n" % (fmt % args))

    def _block(self, rule):
        print(f"[edge] BLOCK rule={rule} path={self.path}", file=sys.stderr, flush=True)
        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BLOCK_PAGE)))
        self.end_headers()
        self.wfile.write(BLOCK_PAGE)

    def do_GET(self):
        # 必须先解码再匹配。直接拿编码后的 query 去跑规则是真实世界最常见的 WAF 绕过：
        # 一个空格写成 '+'、等号写成 '%3D'，正则就全废了。
        query = unquote_plus(urlsplit(self.path).query)
        for name, rx in RULES:
            if rx.search(query):
                return self._block(name)

        try:
            req = Request(ORIGIN + self.path, headers={"User-Agent": "edge-gateway"})
            with _OPENER.open(req, timeout=5) as resp:
                body = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Via", "1.1 edge")
                self.end_headers()
                self.wfile.write(body)
        except HTTPError as exc:
            body = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except URLError as exc:
            print(f"[edge] upstream error: {exc}", file=sys.stderr, flush=True)
            body = b'{"error":"bad_gateway"}'
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def main():
    srv = ThreadingHTTPServer((BIND, PORT), Edge)
    print(f"[edge] listening on {BIND}:{PORT} -> {ORIGIN}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
