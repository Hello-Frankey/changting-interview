#!/usr/bin/env python3
"""从 registry 直接下载镜像并打包成 docker load 可用的 tar。

为什么要这个脚本
----------------
本地 Docker Desktop 挂了且无法通过命令行恢复，但需要把新版 agent-compose 镜像
搬到只能访问 ghcr.io 的服务器上。这里绕开本地 Docker，直接走 registry API。

产物：/tmp/ac-oci.tar（OCI 布局，docker 25+ 的 `docker load` 支持）
若 `docker load` 不认 OCI，用 --legacy 重新打包成传统格式（层需解压，体积大）。

用法：
  python3 tools/pull_image_tar.py --repo chaitin/agent-compose --tag latest \
      --arch amd64 --proxy http://127.0.0.1:7897 --out /tmp/ac-oci.tar
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

BLOB_CACHE = "/tmp/ac-blobs"


def _ssl_context():
    # Python 自带的根证书包常常缺失，导致 CERTIFICATE_VERIFY_FAILED。
    # 优先用 certifi，其次退回系统 CA。
    import ssl
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """blob 会被 307 到 Cloudflare 的签名 URL，带 Authorization 会被拒 401。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        old_host = urllib.parse.urlsplit(req.full_url).hostname
        new_host = urllib.parse.urlsplit(newurl).hostname
        if new_host != old_host:
            for bag in (new.headers, new.unredirected_hdrs):
                for k in [k for k in bag if k.lower() == "authorization"]:
                    bag.pop(k, None)
        return new


def opener_for(proxy):
    ctx = _ssl_context()
    handlers = [_StripAuthOnRedirect(), urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def build(repo, tag, arch, proxy, out, legacy=False):
    op = opener_for(proxy)
    os.makedirs(BLOB_CACHE, exist_ok=True)

    def get(url, headers=None, timeout=120):
        req = urllib.request.Request(url, headers=headers or {})
        return op.open(req, timeout=timeout)

    tok = json.load(get(
        f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    ))["token"]

    accept = ",".join([
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ])
    H = {"Authorization": f"Bearer {tok}", "Accept": accept}
    base = f"https://registry-1.docker.io/v2/{repo}"

    manifest = json.load(get(f"{base}/manifests/{tag}", H))
    if "manifests" in manifest:
        picked = next((x for x in manifest["manifests"]
                       if x.get("platform", {}).get("architecture") == arch), None)
        if not picked:
            sys.exit(f"{arch} 不在 manifest 列表里")
        manifest = json.load(get(f"{base}/manifests/{picked['digest']}", H))

    media_type = manifest.get("mediaType") or "application/vnd.oci.image.manifest.v1+json"
    config_digest = manifest["config"]["digest"]
    layer_digests = [l["digest"] for l in manifest["layers"]]
    print(f"manifest: {media_type}", flush=True)
    print(f"config {config_digest[:19]}  layers {len(layer_digests)}", flush=True)

    def fetch_blob(digest):
        # 用 curl 而不是 urllib：blob 会被 307 到 CDN，而 CDN 拒绝带 Authorization
        # 的请求。curl 跨主机重定向时默认会剥掉该头，urllib 不会。
        path = os.path.join(BLOB_CACHE, digest.split(":")[1])
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return path, os.path.getsize(path)
        tmp = path + ".part"
        cmd = ["curl", "-sL", "--fail", "--retry", "3", "-o", tmp,
               "-H", f"Authorization: Bearer {tok}", f"{base}/blobs/{digest}"]
        if proxy:
            cmd[1:1] = ["--proxy", proxy]
        subprocess.run(cmd, check=True)
        os.replace(tmp, path)
        return path, os.path.getsize(path)

    print("下载 config ...", flush=True)
    cfg_path, _ = fetch_blob(config_digest)

    if legacy:
        # 传统格式：层必须是未压缩的 layer.tar
        workdir = tempfile.mkdtemp(prefix="ac-legacy-")
        layer_entries = []
        for i, dg in enumerate(layer_digests):
            p, size = fetch_blob(dg)
            print(f"  [{i+1}/{len(layer_digests)}] {dg[:19]} {size/1e6:.0f}MB 解压中...", flush=True)
            d = os.path.join(workdir, f"layer{i}")
            os.makedirs(d, exist_ok=True)
            tar_path = os.path.join(d, "layer.tar")
            import gzip
            with gzip.open(p, "rb") as src, open(tar_path, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            with open(os.path.join(d, "VERSION"), "w") as fh:
                fh.write("1.0")
            with open(os.path.join(d, "json"), "w") as fh:
                fh.write("{}")
            layer_entries.append(f"layer{i}/layer.tar")
        cfg_name = config_digest.split(":")[1] + ".json"
        mf = [{"Config": cfg_name, "RepoTags": [f"{repo}:{tag}"], "Layers": layer_entries}]
        with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tf:
            tf.add(cfg_path, arcname=cfg_name)
            for i in range(len(layer_entries)):
                tf.add(os.path.join(workdir, f"layer{i}"), arcname=f"layer{i}")
            data = json.dumps(mf).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size = len(data)
            import io
            tf.addfile(ti, io.BytesIO(data))
        shutil.rmtree(workdir, ignore_errors=True)
        return out

    # OCI 布局：只搬运 blob，不重压
    idx = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": media_type,
            "digest": hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest(),
            "size": 0,
            "annotations": {"org.opencontainers.image.ref.name": tag},
        }],
    }
    # 修正 index 里的 digest/size 指向真实 manifest blob
    man_bytes = json.dumps(manifest, separators=(",", ":")).encode()
    man_digest = "sha256:" + hashlib.sha256(man_bytes).hexdigest()
    os.makedirs(BLOB_CACHE, exist_ok=True)
    man_path = os.path.join(BLOB_CACHE, man_digest.split(":")[1])
    with open(man_path, "wb") as fh:
        fh.write(man_bytes)
    idx["manifests"][0]["digest"] = man_digest
    idx["manifests"][0]["size"] = len(man_bytes)

    print("打包 OCI tar ...", flush=True)
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tf:
        def add_bytes(name, data):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            import io
            tf.addfile(ti, io.BytesIO(data))

        add_bytes("oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
        add_bytes("index.json", json.dumps(idx).encode())
        tf.add(man_path, arcname=f"blobs/sha256/{man_digest.split(':')[1]}")
        tf.add(cfg_path, arcname=f"blobs/sha256/{config_digest.split(':')[1]}")
        for i, dg in enumerate(layer_digests):
            p, size = fetch_blob(dg)
            print(f"  [{i+1}/{len(layer_digests)}] {dg[:19]} {size/1e6:.0f}MB", flush=True)
            tf.add(p, arcname=f"blobs/sha256/{dg.split(':')[1]}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--tag", default="latest")
    ap.add_argument("--arch", default="amd64")
    ap.add_argument("--proxy", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--legacy", action="store_true")
    a = ap.parse_args()
    path = build(a.repo, a.tag, a.arch, a.proxy, a.out, a.legacy)
    print(f"完成: {path}  {os.path.getsize(path)/1e6:.0f} MB", flush=True)


if __name__ == "__main__":
    main()
