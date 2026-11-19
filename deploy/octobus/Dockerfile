# OctoBus 派生镜像 —— 在官方镜像基础上补 python3
#
# 为什么需要这一层
# ----------------
# 官方镜像 ghcr.io/chaitin/octobus 基于 ubuntu:26.04，自带 git / nodejs / npm /
# protobuf-compiler。实测它**恰好带了 python3**（作为某个包的传递依赖），
# 但**没有 PyYAML**——`import yaml` 直接 ModuleNotFoundError。
#
# 这里显式声明 python3 + python3-yaml，而不是依赖那个传递依赖的巧合：
# 上游哪天换依赖，容器就会在运行时炸，而且报错点离原因很远。
#
# 而 OctoBus 的 service runtime 是跑在容器内的 Node 子进程；本项目的
# services/retest-capabilities/bin/retest.js 会 execFile 一个 Python CLI。
# 所以必须把 python3 补进镜像，否则 instance 会启动失败或调用时报 ENOENT。
#
# 这是选型带来的真实约束，不是配置疏漏：
#   - OctoBus 的 service package 契约是 Node.js
#   - 我的判定逻辑在 Python
#   - 薄壳方案要求两者共存于同一 runtime
#
# 备选方案（未采用）：
#   - 用 Node 重写探针与规则引擎：要维护两份知识实现，消融实验会失效
#   - 把 Python 做成 HTTP sidecar：多一个进程和多一跳故障点，收益不明显

FROM ghcr.io/chaitin/octobus:latest

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-yaml \
    && rm -rf /var/lib/apt/lists/*

# 恢复官方镜像的默认运行用户
USER octobus

WORKDIR /var/lib/octobus
