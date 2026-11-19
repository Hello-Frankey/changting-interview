# 部署手册

> 目标：从一台空服务器到「考官能 SSH 登录并核验两套系统在跑」，全部命令可复制执行。
>
> 本文档面向**部署执行者**。项目整体设计见 [README](../README.md)。
>
> 标记说明：**[实测]** = 在开发机上按同样步骤跑通过（含容器路径）；**[待验证]** = 依赖目标服务器环境，第一次执行时确认。
>
> **已验证到哪一步（本机实测）**
>
> | 环节 | 状态 |
> |---|---|
> | OctoBus 三层链路（Docker + 派生镜像） | ✅ 9/9 |
> | 容器内探针 → 宿主机靶场 → 正确判定 | ✅ |
> | `agent-compose config` 校验项目配置 | ✅ 通过（抓出两个插值 bug） |
> | daemon 启动 + 控制面鉴权 | ✅ 401 拦截生效 |
> | `agent-compose up` 应用项目 | ❌ 未完成 |
> | 沙箱能力注入（CAP_GRPC_* / catalog） | ❌ 未验证 |
>
> **未完成的原因**：本机拉 `chaitin/agent-compose-guest` 反复失败
> （Docker content store 的 size 校验错误，换平台参数、重试均无效），
> 而沙箱创建依赖它。这是环境问题，不是配置问题——在服务器上按 §9.1 先拉镜像即可。
> §8.4 的第 3 条验收请务必在服务器上执行，那是唯一还没跑过的环节。

---

## 0. 目标与验收

跑完这份手册，应当满足考核说明的全部硬性要求：

| 要求 | 验收方式 | 对应章节 |
|---|---|---|
| agent-compose daemon 常驻、可自恢复 | 重启服务器后 `restart: always` 生效 | §2 §10 |
| 至少 1 个自建项目、可定时触发 | `agent-compose ps` 看到项目与 trigger | §9 |
| 已配模型凭据、Agent 实际调用模型 | 跑一次 `run` 看到模型输出 | §9 |
| 控制面不无鉴权对公网开放 | 只绑回环 / 有 `AGENT_COMPOSE_AUTH_TOKEN` | §8 |
| OctoBus service→instance→capset 三层 | `octobus catalog` 看到方法 | §5 §6 |
| Agent 经 OctoBus 调用能力 | MCP/gRPC 调用成功 + access log | §6 §10 |
| OctoBus 不对公网发布端口 | `docker ps` 无 9000 映射 | §3 §10 |
| 考官公钥可登录 | `ssh -i 考官私钥` 成功 | §1 |
| 重启后自动恢复 | `reboot` 后再验一遍 | §10 |

**时间预估**：首次约 3~4 小时，其中 §3（派生镜像）和 §8（capproxy）最容易卡。

---

## 1. 服务器基线

### 1.1 规格与系统

- 4 核 8G、系统盘 40G+、Ubuntu 22.04 / 24.04
- 公网出站可用（拉镜像、装依赖）

```bash
# 安装 Docker 与 compose 插件（官方源）
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"   # 重新登录后生效
```

### 1.2 安全组

**只开 22**，并把来源限制为考官出口 IP + 你自己的 IP。

```
入方向：TCP 22   ← 仅这两个来源
出方向：全放通
```

> 7000 段（agent-compose 控制面）、9000（OctoBus）、7411（capproxy）**一律不开放**。
> 考官要核验就 SSH 进来，这是最省事也最安全的做法。

### 1.3 考官公钥 [待验证]

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA... 考官公钥' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
# 自检：权限与语法
ssh-keygen -l -f ~/.ssh/authorized_keys
```

> 别改 SSH 端口之后忘了同步告诉考官——README 里要写清 `地址 / 用户名 / 端口`。

### 1.4 拉取仓库

```bash
sudo mkdir -p /opt/retest && sudo chown "$USER" /opt/retest
git clone <你的仓库地址> /opt/retest
cd /opt/retest

# 部署时 agent 的工作区需要先生成
python3 scripts/sync_workspace.py
```

服务器需要 `python3` 与 `pyyaml`（宿主机侧只用于生成 workspace 和跑 CLI）：

```bash
sudo apt-get install -y python3 python3-yaml
```

---

## 2. 部署 agent-compose

> **为什么不用官方 install.sh**
>
> 安装器要从 **GitHub Releases** 下载二进制，镜像默认从 **Docker Hub** 拉 `chaitin/*`。
> 实测某些地域的服务器两个都访问不了，只有 **ghcr.io** 通。
>
> 而 ghcr.io 上同样发布了 `chaitin/agent-compose` 与 `chaitin/agent-compose-guest`
> （带 `latest` 标签），所以本仓库 vendored 了一份 compose，直接拉 ghcr.io，
> 不依赖安装器、也不依赖 Docker Hub。

### 2.1 镜像版本要求（重要）

**[实测] ghcr.io 上的 `latest` 停在 v2607.10.0（7 月），缺三个关键特性：**

| 特性 | v2607.10.0 | 需要 |
|---|---|---|
| `octobus_servers` | ❌ | v2611+ |
| `models.json` / `CreateProvider` | ❌ | v2611+ |
| Anthropic→Chat 协议桥 | ❌ | v2611+ |

旧版会导致：
- `claude` provider 报 `unsupported llm protocol bridge from "anthropic_messages" to "openai_chat"`
- 项目级 OctoBus 连接报 `unknown field: octobus_servers`
- `workspace.provider: file` 报不支持（只认 `local`）

**做法**：从 Docker Hub 取 `chaitin/agent-compose:latest`（v2611.3.0），
在其可访问的机器上 `docker save` 后传到服务器 `docker load`，然后：

```bash
docker tag chaitin/agent-compose:latest agent-compose:v2611.3.0
# .env 里设 AGENT_COMPOSE_IMAGE=agent-compose:v2611.3.0
```

> 若服务器能直接访问 Docker Hub，也可以直接 `docker pull` 后 tag。
> 本项目的服务器只能访问 ghcr.io，所以走了离线搬运。

### 2.2 启动

```bash
cd /opt/retest/deploy/agent-compose

cp .env.example .env
vi .env      # 必填：AGENT_COMPOSE_AUTH_TOKEN（openssl rand -hex 24）

docker compose up -d
```

compose 里已经配好：

| 配置 | 值 | 作用 |
|---|---|---|
| `CAP_GRPC_LISTEN` | `0.0.0.0:7411` | capproxy 在 daemon 容器内监听 |
| `CAP_GRPC_TARGET` | `agent-compose:7411` | 沙箱容器访问 capproxy 的地址 |
| `AGENT_COMPOSE_AUTH_TOKEN` | `${...}` | 控制面鉴权 |
| `ports` | `127.0.0.1:7410` | **只绑回环**，不对公网暴露 |

> `container_name: agent-compose` 同时决定了 `CAP_GRPC_TARGET` 里的主机名，
> 以及 OctoBus compose 引用的网络名 `agent-compose_default`。改名字要同步改这两处。

### 2.3 验收

```bash
docker compose ps                    # agent-compose 应为 running
docker network ls | grep agent-compose   # 期望 agent-compose_default
ss -lntp | grep 7410                 # 期望 127.0.0.1:7410，不是 0.0.0.0

# daemon 起来了
docker exec agent-compose agent-compose --host http://127.0.0.1:7410 status
```

**如果 `status` 返回 401，那是正常的**——说明鉴权生效了。CLI 侧要先登录，见 §8.3。

---

## 3. 部署 OctoBus（派生镜像）

### 3.1 为什么必须用派生镜像

官方镜像 `ghcr.io/chaitin/octobus:latest` 基于 `ubuntu:26.04`，**[实测]**：

- 有 `git` / `nodejs` / `npm` / `protobuf-compiler`
- **恰好也带了 `python3`**（某个包的传递依赖），但 **`import yaml` 直接失败**——没有 PyYAML

OctoBus 的 service runtime 是容器内的 Node 子进程，而我的能力层是 Python。所以必须补依赖。

> 顺带：[实测] 官方 `latest` 镜像的 octobus 二进制是 `commit 25badd7 / 2026-07-24`，
> **比 npm 上的 0.10.0 旧**，`serve` 只有 `--data-dir`，没有 `--dev`。
> 下面的步骤全部按**镜像的实际能力**写，不用 `--dev`。

镜像定义在 `deploy/octobus/Dockerfile`，已经写好。

### 3.2 起容器

```bash
cd /opt/retest
export RETEST_REPO=/opt/retest
export AGENT_COMPOSE_NETWORK=agent-compose_default   # 按 §2 实际网络名改

sudo -E docker compose -f deploy/docker-compose.octobus.yml up -d --build
sudo docker ps --format '{{.Names}}\t{{.Ports}}'
```

**验收**：`octobus` 这一行的 Ports 列必须是空的——不能出现 `0.0.0.0:9000->9000`。

```bash
sudo docker exec octobus octobus status
# {"services":0,"status":"ok"}
```

---

## 4. 引导 admin token（有安全窗口，务必立刻做）

**[实测]** 库里没有任何 admin token 时，`admin-token add` **不需要鉴权就能成功**。
这是一个引导窗口（bootstrap window）。因为 §3 没发布端口，只有能 `docker exec` 的人够得着，但仍应立刻关掉。

```bash
TOKEN=$(openssl rand -hex 24)

# 立刻签发，并记下来
sudo docker exec octobus octobus admin-token add bootstrap --name bootstrap --token "$TOKEN"

# 验证：不带 token 应当被拒
sudo docker exec octobus octobus service list
# 期望：admin token is required

# 带 token 应当成功
sudo docker exec -e OCTOBUS_ADMIN_TOKEN="$TOKEN" octobus octobus service list
```

把 `$TOKEN` 写进 `/opt/retest/.env`（**不要提交到仓库**）：

```bash
printf 'OCTOBUS_ADMIN_TOKEN=%s\n' "$TOKEN" | sudo tee /opt/retest/.env >/dev/null
sudo chmod 600 /opt/retest/.env
```

---

## 5. 导入 service package

**[实测]** 仓库是只读挂载的，而 `service import` 过程会执行 `npm pack`（要往目录里写）。
所以先拷到容器内的可写目录再导入。

```bash
source /opt/retest/.env
E="sudo docker exec -e OCTOBUS_ADMIN_TOKEN=$OCTOBUS_ADMIN_TOKEN octobus"

sudo docker exec octobus sh -c 'rm -rf /tmp/svc && cp -r /opt/retest/services/retest-capabilities /tmp/svc'
$E octobus service import retest-capabilities /tmp/svc
```

**验收**：输出里应看到 5 个 unary 方法。

```bash
$E octobus service get retest-capabilities | grep -c '"unary": true'
# 期望 5
```

> 这一步会 `npm install @chaitin-ai/octobus-sdk`，需要容器有出网能力。
> 如果服务器走代理，给容器加 `HTTP_PROXY/HTTPS_PROXY` 环境变量。

---

## 6. 建 instance / capset / 访问令牌

```bash
source /opt/retest/.env
E="sudo docker exec -e OCTOBUS_ADMIN_TOKEN=$OCTOBUS_ADMIN_TOKEN octobus"

# 1) instance：repoRoot 指向容器内挂载的仓库路径
$E octobus instance create retest-dev \
  --service retest-capabilities \
  --config-json '{"repoRoot":"/opt/retest"}'

# 2) capset：显式选择方法（对应考核 3.3.2「显式选择所暴露的方法」）
$E octobus capset create retest-agent --name "Retest Agent"
$E octobus capset add-instance retest-agent retest-dev --no-all-methods
for m in ListTickets CollectEvidence ComputeSignals Judge ValidateReport; do
  $E octobus capset select-method retest-agent retest-dev "retest.v1.RetestService/$m"
done

# 3) 访问令牌
CAP_TOKEN=$(openssl rand -hex 24)
$E octobus capset add-token retest-agent local --name "retest agent" --token "$CAP_TOKEN"
printf 'RETEST_CAPSET_TOKEN=%s\n' "$CAP_TOKEN" | sudo tee -a /opt/retest/.env >/dev/null
```

**验收**：

```bash
$E octobus instance get retest-dev | grep '"Status"'
# 期望 "running"

$E octobus catalog retest-agent --all --json | grep -c method_full_name
# 期望 5
```

> **[实测]** 旧版镜像的 MCP tool 名是自动生成的
> `retest-capabilities__retest-dev__judge`；新版可用 `--mcp-tool` 自定义成 `retest_Judge`。
> 两者都能用，别在脚本里硬编码——先 `tools/list` 看一眼。

---

## 7. 目标主机重写（容器里最容易踩的坑）

**[实测]** OctoBus 跑在容器里，而工单里的目标是 `http://127.0.0.1:8000`。
**容器里的 `127.0.0.1` 是容器自己**，不是宿主机。不处理的话所有探针都会失败，
判定会全部落到 `UNVERIFIABLE / unreachable`——看起来很"安全"，实际上是全错。

本项目支持主机重写：

```bash
# Linux：用 docker 默认网桥地址
-e RETEST_TARGET_HOST=172.17.0.1
# 或者用宿主机内网 IP
-e RETEST_TARGET_HOST=10.0.0.12
# Docker Desktop（macOS 本地调试）
-e RETEST_TARGET_HOST=host.docker.internal
```

改 `deploy/docker-compose.octobus.yml` 的环境变量，然后重建容器：

```bash
sudo -E docker compose -f deploy/docker-compose.octobus.yml up -d
```

**验收**（必须做，否则后面全是假象）：

```bash
# 容器内能否探到宿主机的靶场
sudo docker exec octobus sh -c 'curl -s -o /dev/null -w "%{http_code}\n" http://172.17.0.1:8000/healthz'
# 期望 200
```

如果这一步不通，先解决网络，再看判定结果——否则你看到的所有 `UNVERIFIABLE` 都是假的。

---

## 8. 打通 agent-compose 与 OctoBus

这一步有**两条独立链路**，缺一不可。下面的写法和上一版不同——我用真实 daemon 试过之后，
**不再需要 Web UI 和 Settings API**。

### 8.1 控制面：Capability Gateway

**[实测] 关键坑：网关的 token 必须填 capset token，不能填 OctoBus 的 admin token。**

填 admin token 时，沙箱调用会返回：

```
rpc error: code = Unauthenticated
desc = ... capset token is required
```

因为 capproxy 转发给 OctoBus 的 capset 调用需要的是该 capset 的访问令牌。

配置方式（v2611+ 支持 Settings API，不必开 Web UI）：

```bash
# 在 octobus 容器里执行（它有 curl，agent-compose 容器没有）
docker exec octobus curl -sS -X POST \
  http://agent-compose:7410/agentcompose.v2.SettingsService/UpdateCapabilityGatewayConfig \
  -H "Authorization: Bearer $AGENT_COMPOSE_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"addr\":\"http://octobus:9000\",\"token\":\"$RETEST_CAPSET_TOKEN\"}"
```

期望返回 `{"config":{"addr":"http://octobus:9000","tokenSet":true}}`。

> **capset_ids 用不带限定的写法**（`- retest-agent`）。带 server 限定
> （`local/retest-agent`）时，capproxy 记录的授权集是限定名，
> 而客户端发的是裸 capset id，会报 `capset "..." is not allowed for this sandbox`。

### 8.2 数据面：capproxy（daemon 启动时绑定）### 8.2 数据面：capproxy（daemon 启动时绑定）

能力调用从沙箱出来必须先到 capproxy。给 daemon 加两个启动变量：

```yaml
services:
  agent-compose:
    environment:
      CAP_GRPC_LISTEN: 0.0.0.0:7411
      CAP_GRPC_TARGET: agent-compose:7411
```

```bash
cd /opt/agent-compose
sudo docker compose up -d
```

> **必须重启 daemon 才生效**，且旧 sandbox 拿不到新变量——重启后要新建 sandbox。

### 8.3 控制面鉴权（daemon 侧 + CLI 侧是两回事）

**[实测] 这里有个容易搞混的点：**

| 侧 | 配置方式 |
|---|---|
| **daemon** | 环境变量 `AGENT_COMPOSE_AUTH_TOKEN=<token>` |
| **CLI** | 先执行 `agent-compose auth login --token <token>`，**不是**读环境变量 |

注意：给 CLI 传这个环境变量是无效的，仍然返回 401。

```bash
cd /opt/agent-compose
grep -q AGENT_COMPOSE_AUTH_TOKEN .env || \
  printf 'AGENT_COMPOSE_AUTH_TOKEN=%s\n' "$(openssl rand -hex 24)" >> .env
sudo docker compose up -d

# CLI 侧登录（token 从 .env 读）
sudo docker exec <agent-compose容器名> agent-compose \
  --host http://127.0.0.1:7410 auth login --token "$(grep ^AGENT_COMPOSE_AUTH_TOKEN .env | cut -d= -f2)"

sudo docker exec <agent-compose容器名> agent-compose --host http://127.0.0.1:7410 status
# STATUS OK  vXXXX
```

### 8.4 验收

```bash
# 1) 配置能过静态校验（§8.1）
# 2) daemon 健康 + 鉴权生效（§8.3）
# 3) 沙箱拿到能力环境（需要 guest 镜像，见 §9.1）
sudo docker exec <某个sandbox容器> sh -c 'test -n "$CAP_GRPC_TARGET" && test -n "$CAP_TOKEN" && echo ready'
```

---

## 9. 启动项目并跑一轮

### 9.1 先把镜像拉齐（否则 `up` 会卡住）

**[实测]** `agent-compose up` **没有 `--no-pull`**。缺 guest 镜像时它会去拉，
而拉取失败的表现是**命令一直挂着、没有任何输出**——很容易误判成"卡死"。

```bash
# 先在宿主机把两个镜像拉好
sudo docker pull chaitin/agent-compose-guest:latest

# 如果报 "failed size validation" / "unexpected EOF"（多架构清单问题），
# 显式指定平台即可：
sudo docker pull --platform linux/amd64 chaitin/agent-compose-guest:latest

# 确认 daemon 也认得这个镜像
sudo docker exec <agent-compose容器名> agent-compose images
```

> 这个 `--platform` 的坑我本机反复遇到三次，报错各不相同（`28570 != 27899` 之类），
> 本质是 Docker content store 对多架构 manifest 的校验问题。服务器上一般不会遇到，
> 遇到就加平台参数。

### 9.2 应用项目

```bash
cd /opt/retest
python3 scripts/sync_workspace.py          # 生成 agent 工作区（不含真值）

AC="sudo docker exec -e RETEST_OCTOBUS_TOKEN=$(grep ^RETEST_OCTOBUS_TOKEN /opt/retest/.env | cut -d= -f2) <agent-compose容器名> agent-compose"

$AC -f /opt/retest/agent-compose.yml up
$AC -f /opt/retest/agent-compose.yml ps --all
$AC project ls                              # 应看到 retest-project
```

### 9.3 先手工跑一次，别等定时

```bash
$AC -f /opt/retest/agent-compose.yml \
  run verifier --prompt "只处理 SQLI-005 这一张工单：取数、判定、写结论、调用 ValidateReport 自检，把结论和证据贴出来。"
```

这一步同时验证三件事：**模型凭据可用、capability 注入生效、守卫在工作**。

### 9.4 再确认定时触发

```bash
$AC -f /opt/retest/agent-compose.yml scheduler list
```

### 9.5 靶场跑在哪

见 §7。核心是 `RETEST_TARGET_HOST` 必须指向**从 OctoBus 容器可达**的靶场地址，
并且 §7 的 `curl` 验收必须返回 200，否则判定结果全是假的 `UNVERIFIABLE`。

---

## 10. 交付前自检（对应考核 3.4）

逐条打勾，**全部在服务器上执行**：

```bash
# ① 重启后自动恢复 —— 真的 reboot 一次
sudo reboot
# 回来之后：
sudo docker ps --format '{{.Names}}\t{{.Status}}'   # 都应 Up，且 restart 策略生效
sudo docker exec octobus octobus status             # status ok
sudo docker exec <ac容器> agent-compose -f /opt/retest/agent-compose.yml ps --all

# ② 考官公钥可登录 —— 让同事/考官实际试一次
#    不要只自己用 key 试（可能是 agent 转发）

# ③ 能力集与所暴露方法可查
source /opt/retest/.env
sudo docker exec -e OCTOBUS_ADMIN_TOKEN=$OCTOBUS_ADMIN_TOKEN octobus octobus catalog retest-agent --all --json

# ④ Agent 已完整执行至少一轮，且有可查记录
sudo docker exec <ac容器> agent-compose -f /opt/retest/agent-compose.yml logs
sudo docker exec -e OCTOBUS_ADMIN_TOKEN=$OCTOBUS_ADMIN_TOKEN octobus octobus logs | tail -50
#    把报告落到 /opt/retest/out/ 并保留

# ⑤ 仓库无明文密钥
cd /opt/retest && git secrets --scan 2>/dev/null || grep -rInE '(sk-|ghp_|BEGIN .*PRIVATE KEY|password\s*=\s*["'\''][^"'\'']+)' --exclude-dir=.git . | head
```

### 端口暴露复核

```bash
sudo ss -lntp | grep -E ':(7410|7411|9000)\b'
# 期望：只有 7410/7411 绑在回环或 docker 网桥；9000 不应出现在宿主机
sudo docker ps --format '{{.Names}}\t{{.Ports}}'
# 期望：octobus 的 Ports 为空
```

---

## 11. 实测踩坑清单

这些都是在开发机上按同样步骤执行时真实撞到的，不是理论风险。

| # | 现象 | 原因 | 处理 |
|---|---|---|---|
| 1 | 容器内 `import yaml` 失败 | 官方镜像有 python3 无 PyYAML | 派生镜像补 `python3-yaml`（§3） |
| 2 | `octobus serve --dev` 报 unknown flag | 官方 `latest` 镜像比 npm 版本旧 | 不用 `--dev`，走 bootstrap token（§4） |
| 3 | `service import` 报 npm 写盘失败 | 仓库只读挂载，`npm pack` 要写 | 先 `cp` 到容器 `/tmp` 再导入（§5） |
| 4 | 所有判定都是 `UNVERIFIABLE/unreachable` | 容器里的 `127.0.0.1` 不是宿主机 | `RETEST_TARGET_HOST` 重写（§7） |
| 5 | 不可达目标被判成"服务异常" | 系统代理劫持了探针请求 | 探针已内置 no-proxy opener，别再改回去 |
| 6 | MCP 工具名和预期不一致 | 新旧版本命名规则不同 | 先 `tools/list` 再写脚本 |
| 7 | bootstrap 窗口 | 无 token 时可直接签发 token | 端口不发布 + 立刻签发（§4） |

---

## 12. 安全收尾

- [ ] `/opt/retest/.env` 权限 600，且已在 `.gitignore` 里
- [ ] 仓库里没有 `AGENT_COMPOSE_AUTH_TOKEN` / `OCTOBUS_ADMIN_TOKEN` / `RETEST_CAPSET_TOKEN` 明文
- [ ] OctoBus 容器无端口映射，7411 不对公网
- [ ] 控制面要么只绑回环，要么已设 `AGENT_COMPOSE_AUTH_TOKEN`
- [ ] 安全组只有 22 开放，来源收敛
- [ ] README 写明登录地址 / 用户名 / 端口，且与 `authorized_keys` 一致

---

## 附录：本环境的实测记录（2026-11-19）

部署完成后在真实服务器上逐项验证的结果，可作为复现基准。

### 服务状态

| 项 | 结果 |
|---|---|
| agent-compose daemon | v2611.3.0，`STATUS OK`，7410 仅监听 `127.0.0.1` |
| OctoBus | `{"services":1,"status":"ok"}`，容器无端口映射 |
| service 方法数 | 5 个 unary |
| instance | `retest-dev` running |
| capset | `retest-agent`，5 个方法显式选择 |
| 靶场 | systemd `retest-labs` enabled + active，21 个端口 |

### 能力调用链路

```
guest agent → ./cap.sh → grpcurl → capproxy → OctoBus → Node 薄壳 → Python → 靶场
```

实测结果：

| 验证 | 结果 |
|---|---|
| `ListTickets` | 返回 21 张工单 |
| `Judge(SQLI-005)` | `UNFIXED / bypassable_filter / R05_BYPASSABLE_FILTER`，10 条证据 |
| `ValidateReport` 诚实报告 | `accepted=true` |
| `ValidateReport` 无证据 | `accepted=false`，`missing_evidence` |
| `ValidateReport` 撒谎（改判 FIXED + 编造证据） | `accepted=false`，三条违规 |

### 重启恢复

`reboot` 后：

| 检查 | 结果 |
|---|---|
| 两个容器 | 自动 `Up`（`restart: always` / `unless-stopped`） |
| 靶场 | systemd 自动拉起，21 个端口 |
| 项目与触发器 | 保留 |
| 调度触发 | `scheduler trigger` → `succeeded`（9.2s） |

### 沙箱能力注入

| 检查 | 结果 |
|---|---|
| `CAP_GRPC_TARGET` | `agent-compose:7411` |
| `CAP_TOKEN` | 36 位 UUID，**不等于** OctoBus admin token |
| capability guide | `/data/runtime/mpi/catalog.md`，5 个方法 + metadata 说明 |
| guide 是否泄露上游凭据 | 不含 `octobus:9000`，不含 admin token |

### 对照实验：`octobus_servers` 为什么没用

最初的项目定义用的是项目级 `octobus_servers` + 带限定的 `capset_ids`，
期望项目自包含、不依赖 daemon 全局设置。实际部署时失败：

```
rpc error: code = PermissionDenied
desc = capset "retest-agent" is not allowed for this sandbox
```

**第一次归因是错的。** 当时为了让它跑通，同时改了两个变量：

1. `octobus_servers` → 改用 daemon 全局网关
2. 网关 token：admin token → capset token

通是通了，但两个变量一起动，无法判断是哪个起的作用。

**后来做了单变量对照**：token 保持正确，只把项目配置换回
`octobus_servers` + `local/retest-agent`。结果仍然报同一个权限错误。

| 变量 | 写法 | 结果 |
|---|---|---|
| capset token（固定） | `capset_ids: [retest-agent]` + 全局网关 | ✅ 21 张工单 |
| capset token（固定） | `capset_ids: [local/retest-agent]` + `octobus_servers` | ❌ `not allowed` |

**结论**：授权失败由「带限定的 capset id」直接导致，与 token 无关。

**根因（未完全确认）**：推断 daemon 把 `capset_ids` 的原始字符串
（`local/retest-agent`）存进了沙箱授权集，而 capproxy 比对时用的是客户端发来的裸 id
（`retest-agent`），两者不匹配。理论上「用裸 id 授权、用限定名选上游连接」应当是正交的，
所以这更像 v2611.3.0 的缺陷而非设计意图。没有读源码确认，故记为未完全确认。

**处置**：保留能工作的全局网关写法，并在 README 中显式声明这个前置条件，
避免考官按仓库复现时卡在「为什么调不通」。

> 教训：这是本次唯一一次**归因错误**。教训是「一次只改一个变量」——
> 同时改两个再观察结果，即使最后成功，也无法把成功归因到正确的改动上。

### 复盘：提示词形态决定 agent 是否真的执行

**现象**：把定时任务的提示词写成「按 retest.md 的流程完成今晚的漏洞复测」，
运行 4.4 秒就结束，只调了一次 `ListTickets`，21 张工单处理了 0 张。

**定位**：查沙箱日志，模型输出的是「让我先看看工作目录、读一下 retest.md」——
一段纯文本，没有任何工具调用。而 **agent 的一轮在模型输出纯文本且不带工具调用时结束**，
harness 认为任务已完成，整个 run 随之终止。

**根因**：提示词里出现「按 retest.md 的流程」这类**对文档的引用**，
模型会先想去读文档，于是产生纯文本回合，run 提前结束。

**验证**：同一套环境下做对照——

| 提示词形态 | 结果 |
|---|---|
| `按 retest.md 的流程…` | 4 秒结束，0 张工单 |
| `执行 ./cap.sh ListTickets '{…}'，只报总数` | ✅ 正常返回 21 |
| 全程祈使、不引用文档、逐条列命令 | ✅ **21 张全部处理，且判定 21/21 正确** |

**处置**：把定时触发词改成**第一条就是具体命令**的祈使式，并在
`prompts/retest.md` 里写明「只说『我先读一下』然后不做工具调用会被判定为结束」。

**反思**：这类问题不能靠"把提示词写得更详细"解决。文档写得再全，
只要模型的第一反应是"先去读文档"，运行就会当场结束。
**提示词的第一句必须是可执行动作，而不是一个需要它先理解的任务描述。**

> 这也解释了为什么早期测试都成功、一换生产形态就失败：
> 我的测试提示词本身就是命令，而生产提示词是任务描述。**测试形态和交付形态不一致，
> 等于没测。**
