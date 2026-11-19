"""统一的 HTTP 客户端：**显式禁用系统代理**。

为什么必须这么做
----------------
Python 的 urllib 在 macOS 上会读取系统代理设置（getproxies()）。
如果机器上开了代理软件，探针发往靶场的请求会被代理接管：

  - 目标不可达时，代理返回 502/504 而不是连接错误
  - 探针于是把"连不上"判成"服务活着但返回异常"
  - 最终结论从 `unreachable` 变成 `baseline_broken` —— 前置条件判错，后面全错

安全探针必须直连目标：经过代理的"不可达"不是不可达，是代理的不可达。

注意：这里只影响探针。拉 git / npm 依赖时仍然需要系统代理，那是另一条链路。
"""

import os
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse

# 空 ProxyHandler = 不使用任何代理
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# 部署在容器里时，127.0.0.1 指向容器自己而不是宿主机上的靶场/资产。
# 用 RETEST_TARGET_HOST 做主机重写，端口保持不变。
_TARGET_HOST = os.environ.get("RETEST_TARGET_HOST", "").strip()


def rebase(url):
    """把工单里的目标主机替换成 RETEST_TARGET_HOST（若已设置）。"""
    if not _TARGET_HOST or not url:
        return url
    parts = urlparse(url)
    if not parts.hostname:
        return url
    netloc = _TARGET_HOST if parts.port is None else f"{_TARGET_HOST}:{parts.port}"
    return urlunparse(parts._replace(netloc=netloc))


def open_url(req, timeout=4):
    """发请求；HTTP 错误码以 HTTPError 抛出，由调用方按状态码处理。"""
    return _OPENER.open(req, timeout=timeout)


__all__ = ["open_url", "rebase", "HTTPError", "URLError"]
