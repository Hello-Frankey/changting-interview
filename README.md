# 漏洞复测 Agent

> **验证「已修复」是否真的修好了。**
> 不是找漏洞，是验修复——因为漏洞管理里最贵的失败不是漏报，而是**假修复放行**。

<p>
<a href="#快速验证">快速验证</a> ·
<a href="#设计">设计</a> ·
<a href="#知识层">知识层</a> ·
<a href="#实施中的问题">问题复盘</a> ·
<a href="docs/DEPLOYMENT.md">部署手册</a>
</p>

---

## 这是什么

漏洞管理有一条断点：开发者说修好了，安全团队没有人力逐条验证，最后退化成"重放一次原始 PoC，没打穿就算过"。

于是三类假修复被大量放行：

| 类型 | 表现 | 为什么会被放过 |
|---|---|---|
| **版本号漂移** | 只改了版本号，代码一字未动 | 版本号看起来像"已升级" |
| **边界虚拟补丁** | WAF / 反代拦住了，代码没修 | "打不通"和"修好了"在响应上一样 |
| **假净化 / 单点修复** | 只拦了原 PoC 的字面量，或只修了被举报的那个入口 | 重放原 PoC 恰好通过 |

这个 Agent 判定的不是"这段代码改没改"，而是：

> **那条从不可信输入通向危险操作的通道，是不是真的被关上了。**

并且把"验证不了"当成合法结论，而不是硬塞进"已修复"。

---

## 访问方式

服务器已部署完成，`agent-compose` 与 `OctoBus` 两套系统均在运行。
运行状态核验命令见文末 [核验命令](#核验命令)。

| 项 | 值 |
|---|---|
| **登录地址** | `121.41.195.11` |
| **用户名** | `root` |
| **端口** | `22` |

```bash
ssh -p 22 -i <考官私钥路径> root@121.41.195.11
```

**考官公钥已写入 `/root/.ssh/authorized_keys`。**

> 阿里云 Ubuntu 镜像默认以 `root` 登录，因此公钥目录是 `/root/.ssh/`，
> 不是 `/home/<user>/.ssh/`。
>
> 安全组的 SSH 入方向仅对白名单来源开放。若连接被拒绝，通常是来源 IP
> 不在白名单内，而不是密钥问题——请联系候选人补充来源 IP。

---

## 快速验证

```bash
git clone <repo> && cd <repo>
sudo apt install -y python3-yaml   # Debian/Ubuntu；其他发行版用 pip install pyyaml
# Ubuntu 24.04 起系统 Python 受 PEP 668 保护，直接 pip install 会报
# externally-managed-environment，用 apt 装或建 venv 都行

# 1) 起靶场：3 类漏洞、21 个带真值的用例
(cd lab/sqli && ./run_local.sh up)
(cd lab/xss && ./run_local.sh up)
(cd lab/access && ./run_local.sh up)

# 2) 端到端判定
python3 tools/retest_demo.py
#   裁决准确率: 21/21    模式准确率: 21/21

# 3) 消融实验：证明知识库真的在起作用
python3 tools/ablate.py
#   完整知识库 21/21  vs  无知识库 11/21
```

想看单条证据长什么样：

```bash
python3 tools/retest_demo.py -v --lab access   # 展开每一条探针与信号
```

---

## 设计

### 分层

```
        运行面                     能力面                    数据面
  ┌──────────────┐          ┌──────────────┐         ┌──────────────┐
  │ agent-compose│  cron    │   OctoBus    │         │   靶场 / 资产 │
  │  guest agent │ ───────▶ │ service      │ ──────▶ │              │
  │  （LLM）      │  gRPC    │  ↓ instance  │  探针    │              │
  └──────────────┘          │  ↓ capset    │         └──────────────┘
         │                  │  ↓ method    │
         │ MCP/gRPC         └──────────────┘
         ▼                         ▲
  ┌────────────────────────────────────────┐
  │  能力层（本项目）                        │
  │  取数 → 信号 → 判定 → 知识               │
  └────────────────────────────────────────┘
```

四层的切分依据是**什么会变**：

| 层 | 文件 | 职责 | 会不会变 |
|---|---|---|---|
| 取数层 | `agent/collect.py` `agent/xss.py` `agent/access.py` | 按漏洞类型发探针、存证据（带哈希） | 换漏洞类型就要加 |
| 信号层 | `agent/signals.py` `agent/xss.py` `agent/access.py` | 证据 → 布尔量 | 较稳定 |
| 判定层 | `agent/judge.py` | 读知识库按优先级求值 | 稳定 |
| 知识层 | `knowledge/false-fix-patterns.yaml` | 21 条可执行判据 | **经常变** |

**为什么把知识抽成 YAML 而不是写在代码里？** 因为要能消融。判据是 `if-else` 的话，就无法回答"这条知识有没有用"。抽成数据之后，删掉一条跑一遍，输出变了就说明它被消费——这就是 `tools/ablate.py`。

### LLM 与脚本的分工

| 谁 | 做什么 | 为什么 |
|---|---|---|
| **脚本** | 发请求、算长度与行数增量、比对阈值、强制五态裁决、生成证据哈希 | 确定性的事模型不能碰 |
| **LLM** | 规划探针、解释信号冲突、撰写报告 | 模糊判断 |
| **守卫生成器** | 校验报告结论是否可被接受 | 见下 |

关键约束：**模型没有裁决权，只有升级权。**

```python
# agent/guard.py
SEVERITY = ["FIXED", "MITIGATED_NOT_FIXED", "PARTIAL", "UNFIXED", "UNVERIFIABLE"]
if SEVERITY.index(report_verdict) < SEVERITY.index(tool_verdict):
    reject("optimistic_downgrade")
```

理由：**「未修复」是阳性证据，「已修复」是阴性证明。**
阴性证明本来就弱，如果允许模型乐观，整个系统的可信度就没了。
所以模型可以把"未修复"升级为"需人工"，但不能把"无法验证"降级为"已修复"。

### 五态裁决

| 结论 | 含义 | 置信度 |
|---|---|---|
| `FIXED` | 根因切断，所有变体与入口均无效 | medium（阴性证明） |
| `PARTIAL` | 部分入口/视图已修，其余仍可利用 | high |
| `MITIGATED_NOT_FIXED` | 边界拦截或 CSP 缓解，代码未修 | high |
| `UNFIXED` | 仍可利用 | high（阳性证据） |
| `UNVERIFIABLE` | 不可达、基线异常、证据不足 | — |

**`UNVERIFIABLE` 是刻意保留的。** 大量复测事故来自"打不通就当成修好了"——
服务下线、依赖不可用、鉴权拦截都会让攻击失败，但那不是修复。

---

## 知识层

`knowledge/false-fix-patterns.yaml` 定义 **21 条规则 / 27 个信号**，覆盖三类漏洞。

### 三层知识，越往下越难从公开资料查到

| 层 | 内容 | 公开资料 |
|---|---|---|
| 判据 | 什么条件判什么结论 | 部分可得 |
| **伪信号** | 哪些字段看起来像证据、其实不是 | **很少系统讲** |
| **取舍** | 什么时候必须交给人 | **几乎不讲** |

### 三个具体判据

**① 过滤了单引号，为什么还是没修好**

```sql
SELECT * FROM users WHERE id = {uid}     -- 数字型注入
```

`1 OR 1=1` 不需要引号。原始 PoC 之所以带引号，只是因为写 PoC 的人不知道字段类型。
修复方恰好过滤了那个字符，双方都以为完事了。

> 判据：原始 PoC 失效 **且** 同类变体仍有效 → `UNFIXED / bypassable_filter`

**② JS 上下文里，JSON 编码也不够**

`JSON.stringify` 处理了引号，但没处理尖括号——`</script>` 依然会提前闭合脚本块，
因为 HTML 解析器不认 JS 字符串边界。必须再把 `< > &` 转成 `\u003c`。

> 判据：有编码动作但上下文错配 → `UNFIXED / context_mismatch`

**③ 403 不代表没生效**

```python
def delete_order(user, order):
    ORDERS.remove(order)            # 先删
    if order.owner_id != user.id:
        return 403                  # 再判
```

返回 403，数据已经没了。只看响应码的复测会写"已拦截，修复有效"。

> 判据：越权写返回 401/403 **且** 所有者回读 404 → `UNFIXED / silent_write`

### 「不可作为判断依据」清单

这是本知识层里最不像"标准答案"、但最能减少误判的部分：

| 字段 | 为什么不能用 |
|---|---|
| 版本号 / `Server` 头 | 可被 CDN / 反代重写，与实际 artifact 无强绑定 |
| HTTP 状态码 | WAF 和业务都可能返回 403，语义不可区分 |
| 报错信息消失 | 多数框架已全局捕获异常，与注入失效无关 |
| 原始 PoC 被拦 | 只证明这一条字面量被匹配 |
| 列表里看不到别人的数据 | 列表过滤是查询条件，不是访问控制 |

### 消融实验

判断一份知识是不是真的有价值，标准很朴素：**把它拿掉，输出应该明显变差**。这一条被做成了工具：

| 配置 | 裁决 | 模式 | 完全一致 |
|---|---|---|---|
| 完整知识库 | **21/21** | **21/21** | **21/21** |
| 无知识库（仅重放 PoC） | 11/21 | 7/21 | 7/21 |

逐条移除 21 条规则，**每一条被删掉后输出都会变化**；规则命中统计显示每条各命中 1 次，无冗余。

> 注：这里用了"严格模式"做逐条移除——无规则命中时直接判 `UNVERIFIABLE` 而不猜。
> 用朴素 fallback 做这一步会掩盖规则贡献，详见 [问题复盘](#实施中的问题) 第 1 条。

---

## 用例

21 个用例，全部带 ground truth，分布在三类漏洞上。

| 靶场 | 用例数 | 覆盖的假修复形态 |
|---|---|---|
| `lab/sqli` | 8 | 版本号漂移、WAF 虚拟补丁、关键词黑名单、单点修复、不可达、基线异常 |
| `lab/xss` | 6 | 上下文错配、黑名单、CSP 缓解、存储点未修 |
| `lab/access` | 7 | 列表过滤、UUID 冒充授权、子资源未修、垂直越权、静默写入 |

每个靶场都是「一个应用 + 多个修复变体」，用 `VARIANT` 环境变量切换。
真值由构造者掌握——这是这类实验相对生产数据的最大优势。

```bash
cd lab/sqli && ./run_local.sh up      # 端口 8000-8007，8008 故意留空
cd lab/xss && ./run_local.sh up       # 端口 8100-8105
cd lab/access && ./run_local.sh up    # 端口 8200-8206
```

每个靶场的 README 里写了该组的验证目标与真值表。

---

## 目录

```
agent-compose.yml             项目定义（cron 触发 + capset_ids）
prompts/retest.md             guest agent 的任务指令与硬约束

agent/
├── collect.py  xss.py  access.py   取数：按漏洞类型分派探针
├── signals.py                      信号：证据 → 布尔量
├── judge.py                        判定：读知识库求值
├── guard.py                        守卫：单调性 + 证据真实性 + 覆盖完整性
├── net.py                          探针 HTTP 客户端（显式禁用系统代理）
└── cases.py                        工单索引（对 agent 隐去真值）

knowledge/false-fix-patterns.yaml   21 条规则 / 27 个信号 / 阈值出处
services/retest-capabilities/       OctoBus service package（proto + Node 薄壳）
lab/{sqli,xss,access}/              三个靶场
scripts/                            OctoBus 端到端验证、工作区生成
tools/                              判定演示、消融实验、能力层 CLI
docs/DEPLOYMENT.md                  完整部署手册
```

---

## 部署

完整步骤见 **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**。这里只给要点。

### 环境

- 4C8G 以上，Ubuntu 22.04 / 24.04，Docker + compose v2
- OctoBus 不对公网发布端口；agent-compose 控制面只绑回环
- 安全组只开放 22

### 三步

> **所有镜像都取自 ghcr.io。** 目标服务器可能访问不了 Docker Hub，
> 但 ghcr.io 上同样发布了 daemon 与 guest 镜像，因此部署既不依赖 Docker Hub，
> 也不依赖官方安装器（安装器要从 GitHub Releases 下载）。

```bash
# 1. agent-compose（仓库内置 compose，不用 install.sh）
cd deploy/agent-compose
cp .env.example .env && vi .env        # 填 AGENT_COMPOSE_AUTH_TOKEN
docker compose up -d

# 2. OctoBus（基于官方镜像的派生镜像，补 PyYAML）
cd /opt/retest
export RETEST_REPO=/opt/retest AGENT_COMPOSE_NETWORK=agent-compose_default
sudo -E docker compose -f deploy/docker-compose.octobus.yml up -d --build

# 3. 导入 service package 并建三层链路
#    仓库是只读挂载的，import 会 npm pack（要写盘），所以先拷到容器内可写目录
sudo docker exec octobus sh -c 'cp -r /opt/retest/services/retest-capabilities /tmp/svc'
O="sudo docker exec -e OCTOBUS_ADMIN_TOKEN=$OCTOBUS_ADMIN_TOKEN octobus octobus"
$O service import retest-capabilities /tmp/svc
$O instance create retest-dev --service retest-capabilities --config-json '{"repoRoot":"/opt/retest"}'
$O capset create retest-agent
$O capset add-instance retest-agent retest-dev --no-all-methods
for m in ListTickets CollectEvidence ComputeSignals Judge ValidateReport; do
  $O capset select-method retest-agent retest-dev "retest.v1.RetestService/$m"
done
```

# 4. 配置 daemon 侧的能力网关（关键，见下）
#    注意 token 必须是 capset token，不是 OctoBus 的 admin token
docker exec octobus curl -sS -X POST \
  http://agent-compose:7410/agentcompose.v2.SettingsService/UpdateCapabilityGatewayConfig \
  -H "Authorization: Bearer $AGENT_COMPOSE_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"addr\":\"http://octobus:9000\",\"token\":\"$RETEST_CAPSET_TOKEN\"}"
```

### ⚠️ 一个不在仓库里的前置条件

**本项目的 `agent-compose.yml` 依赖 daemon 侧的 Capability Gateway 配置。**

也就是说，光把仓库 clone 下来、`docker compose up` 是不够的——还必须执行上面第 4 步，
把 OctoBus 的地址和 **capset token** 配进 daemon。否则沙箱调用能力时会报：

```
rpc error: code = Unauthenticated
desc = ... capset token is required
```

两个容易配错的地方：

| 配错 | 报错 |
|---|---|
| token 填成 admin token | `capset token is required` |
| `capset_ids` 写成带限定的 `local/retest-agent` | `capset "retest-agent" is not allowed for this sandbox` |

### 为什么没用项目级 `octobus_servers`

agent-compose v2611 支持把 OctoBus 连接声明在项目文件里（`octobus_servers` + 带限定的
`capset_ids`），那样项目就是自包含的，不需要 daemon 侧配置。这是更干净的形态。

**本部署没有采用它，因为它在这个版本上有缺陷。** 实测对照（同一个 capset token、
同一个 capset，只改写法）：

| 写法 | 结果 |
|---|---|
| `capset_ids: [retest-agent]` + 全局网关 | ✅ 调通 |
| `capset_ids: [local/retest-agent]` + `octobus_servers` | ❌ `capset "retest-agent" is not allowed` |

现象确证，根因怀疑是 daemon 把限定名原样存进了沙箱的授权集，而客户端发的是裸 capset id。
没有读到源码层，所以这里只记为「已确认的现象 + 未完全确认的根因」。

**取舍**：宁可多一步 daemon 配置，也不用一个有缺陷的特性去改架构。
代价是项目不自包含，所以这一节必须写清楚。

> 其余部署细节（admin token 引导、capproxy 的两个启动变量）见
> [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) §4 与 §8。

### 核验命令

考官登录后，先加载环境变量，再逐项核验：

```bash
set -a; source /opt/retest/.env; set +a
AC="docker exec agent-compose agent-compose"
```

```bash
# ① 两套系统常驻运行
docker ps --format '{{.Names}}	{{.Status}}'
#   期望：agent-compose 与 octobus 都是 Up

# ② OctoBus 三层链路与显式暴露的方法（5 个）
docker exec -e OCTOBUS_ADMIN_TOKEN=$OCTOBUS_ADMIN_TOKEN octobus octobus catalog retest-agent --all --json \
  | grep -c method_full_name
#   期望：15（5 个方法 × grpc/connect/mcp 三种协议）

# ③ 项目、触发器与沙箱历史
$AC -f /opt/retest/agent-compose.yml ps --all
$AC -f /opt/retest/agent-compose.yml scheduler ls
$AC -f /opt/retest/agent-compose.yml scheduler runs

# ④ agent 的完整输出（模型思考过程 + 工具调用记录）
$AC -f /opt/retest/agent-compose.yml logs

# ⑤ 能力调用的网关侧审计 —— "Agent 确实经过了 OctoBus" 的佐证
docker exec -e OCTOBUS_ADMIN_TOKEN=$OCTOBUS_ADMIN_TOKEN octobus octobus logs --limit 0 \
  | grep '"grpc_code":"OK"' | tail -10
```

**⑤ 的两个注意点：**

- **`--limit 0` 不能省。** `octobus logs` 默认只返回最后 200 条，
  调试期间的失败记录会超过这个数，把成功调用挤出窗口——我第一次就因此以为审计里没有记录。
- **成功的 agent 调用特征是 `"protocol":"grpc"` 且 `"user_agent":"grpc-go/..."`**，
  来源 IP 是沙箱容器。`"protocol":"mcp"` 的是直接调 MCP 端点产生的，不是 agent 调用。

一次完整复测在审计里长这样（四步按序、来源同一个沙箱 IP）：

```
03:14:37  retest.v1.RetestService/CollectEvidence   131ms
03:14:38  retest.v1.RetestService/ComputeSignals    132ms
03:14:39  retest.v1.RetestService/Judge             131ms
03:14:40  retest.v1.RetestService/ValidateReport    132ms
```

### 安全说明

- 仓库内**不含任何明文密钥**；凭据一律 `${ENV}` 插值或 daemon 侧环境变量
- OctoBus 容器无 `ports` 映射，仅挂在内部网络
- OctoBus 的 admin token 留在 daemon 侧，沙箱只能拿到每沙箱签发的 `CAP_TOKEN`
- 探针 HTTP 客户端**显式禁用系统代理**——经过代理的"不可达"不是不可达（见问题 2）

---

## 实施中的问题

五个真实问题。都按「现象 → 定位 → 处理 → 反思」写，因为反思比修复更有信息量。

### 1. 消融实验骗了我

**现象**：第一版消融跑出来，三条规则显示"移除后输出完全不变"。按 5.2 的口径，它们该被删掉。

**定位**：不是规则冗余，是**度量有问题**。没有规则命中时会退化到"只重放 PoC"的朴素 fallback，
而它恰好对这三个用例给出了相同答案，把规则的贡献掩盖了。

**处理**：加严格模式（无规则覆盖即判 `UNVERIFIABLE`），逐条移除时用它隔离边际贡献；
再加"规则命中统计"作为第二重证据，确认每条规则都实际触发过。

**反思**：这是最有价值的一个坑。**消融实验本身会骗人**——如果对照组和实验组碰巧给出相同答案，
"无变化"会被误读成"该知识无用"。评估方法本身需要被评估。

### 2. 系统代理把"不可达"变成了"服务异常"

**现象**：回归时，网络不可达的用例从 `unreachable` 变成了 `baseline_broken`。

**定位**：macOS 的系统代理设置被 Python `urllib` 自动读取（`getproxies()`）。
探针发往不可达目标的请求被代理接管，返回 502。于是 `connection_ok` 被判为真，
"连不上"变成了"服务活着但异常"——**前置条件判错，后面全错**。

**处理**：在 `agent/net.py` 里建一个空的 `ProxyHandler({})` opener，所有探针显式绕过代理。

**反思**：**经过代理的"不可达"是代理的不可达，不是目标的。**
安全探针必须直连目标。这类环境假设错误在本地看不出来，一换机器就复现。

### 3. 我自己写出一个有缺陷的 WAF

**现象**：边界拦截用例的判定一直错，网关没拦住任何 payload。

**定位**：探针用 `urlencode`，空格变成 `+`、等号变成 `%3D`；而网关规则匹配的是**编码后**的
原始 query string，正则全部落空。

**处理**：网关在匹配前先 `unquote_plus`。

**反思**：这个 bug 恰好就是真实世界最常见的 WAF 绕过之一——**忘了先规范化就做字符串匹配**。
我无意中写出了一个有真实缺陷的 WAF，而它暴露的正是复测要识别的绕过手法。
这条写进了 `edge.py` 的注释，因为它是"失效经验"，不是实现细节。

### 4. 官方镜像是旧版本，而且没有 PyYAML

**现象**：OctoBus 容器里 `import yaml` 直接失败；`serve --dev` 报 unknown flag。

**定位**：`ghcr.io/chaitin/octobus:latest` 基于 `ubuntu:26.04`，实测**恰好带了 python3**
（某个包的传递依赖）但没有 PyYAML；二进制是 `commit 25badd7 / 2026-07-24`，
**比 npm 上的 0.10.0 旧**，`serve` 只有 `--data-dir`。

**处理**：做派生镜像显式声明 `python3` + `python3-yaml`；部署流程改走 bootstrap token，
不用 `--dev`。

**反思**：**不要依赖传递依赖的巧合。** 上游哪天换依赖，容器会在运行时炸，且报错点离原因很远。

### 5. 容器里的 `127.0.0.1` 不是宿主机

**现象**：OctoBus 跑进容器后，所有判定都返回 `UNVERIFIABLE / unreachable`，
看起来完全正常，实际上是全错。

**定位**：工单里的目标是 `http://127.0.0.1:8000`，而容器内的 `127.0.0.1` 是容器自己。

**处理**：加 `RETEST_TARGET_HOST` 做目标主机重写，部署时指向从容器可达的宿主机地址。

**反思**：这类问题最危险的地方是**它有正常的输出**。
所以部署手册里加了一条强制验收：先 `curl` 通，再看判定结果。

---

## 已知局限

诚实列出来，因为这些是实际使用中最容易被质疑的地方。

1. **变体矩阵是手写的**，不是按漏洞类型生成的。真正的知识层要能说清"这类洞有哪些等价变形"。
2. **阈值是零噪声下标的的**。靶场响应是确定性 JSON，`min_row_delta=1` 只能证明流程可用；
   生产环境必须重测（方法写在 `thresholds.provenance`）。
3. **不覆盖 DOM 型 XSS**。`location.hash → innerHTML` 不经过服务端响应，服务端探针看不到。
4. **边缘识别是启发式的**（403 + HTML）。真实 WAF 可能返回 200 的拦截页或直接 RESET。
5. **直连源站依赖实验环境可控**。生产复测必须先授权，否则是越权测试。
6. **越权覆盖有限**：单租户、三个账号，不测令牌伪造与批量接口。
7. **样本量**：21 个用例能证明判据必要性，谈不上统计意义上的覆盖率。

---

## 参考

- [agent-compose](https://github.com/chaitin/agent-compose) —— daemon + CLI，在隔离 sandbox 中运行 agent
- [OctoBus](https://github.com/chaitin/OctoBus) —— 把 service 能力按 capset 暴露给 agent
