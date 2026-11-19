# XSS 复测靶场

和 SQLi 靶场同一套 agent 架构，但判定逻辑完全不同。

> **SQLi 问的是「数据有没有改变语义」，一处修好就是修好了。**
> **XSS 问的是「数据在哪个上下文里、能不能逃逸出去」，必须逐上下文判。**

这就是为什么同一个 Agent 需要按漏洞类型切换探针策略——`agent/collect.py` 与
`agent/signals.py` 按 `vuln_type` 分派，判定层则共用同一份知识库。

---

## 快速开始

```bash
cd lab/xss
./run_local.sh up                       # 六个变体，端口 8100-8105
python3 ../../tools/retest_demo.py --lab xss
python3 ../../tools/ablate.py --lab xss
./run_local.sh down
```

也可以和 SQLi 一起跑：

```bash
cd lab/sqli && ./run_local.sh up
cd ../xss  && ./run_local.sh up
python3 ../../tools/retest_demo.py      # 14 个用例一起判
```

---

## 六个变体

| 用例 | 变体 | "修复"方式 | 期望判定 | 验证目标 |
|---|---|---|---|---|
| XSS-001 | `x0_vulnerable` | 无 | `UNFIXED` / `no_fix` | 对照组 |
| XSS-002 | `x1_truefix` | 按上下文分别编码 | `FIXED` / `root_cause` | 根因修复 |
| XSS-003 | `x2_angle_only` | 只转义 `<` `>` | `UNFIXED` / `context_mismatch` | **编码存在但上下文错配** |
| XSS-004 | `x3_blacklist` | 只拦字面量 `<script` | `UNFIXED` / `bypassable_filter` | **黑名单只认字面量** |
| XSS-005 | `x4_csp_only` | 只下发 CSP 头 | `MITIGATED_NOT_FIXED` / `csp_mitigation` | **CSP 是缓解不是修复** |
| XSS-006 | `x5_partial` | 反射点修了，存储点没修 | `PARTIAL` / `single_point` | **同一缺陷的另一个实例** |

三个反射上下文各一个端点，便于隔离判定：

| 端点 | 上下文 | 逃逸靠什么 |
|---|---|---|
| `/echo/body` | `<div>结果：{q}</div>` | `<` |
| `/echo/attr` | `<input value="{q}">` | `"` |
| `/echo/script` | `<script>var kw = "{q}";</script>` | `"` 与 `</script>` |

外加存储上下文：`POST /comment` 提交，`GET /comments` 渲染到正文。

---

## 三个关键知识点

### 1. 转义函数必须匹配上下文（XSS-003）

`x2` 的修复是「把所有输入统一做 HTML 实体转义」，只转义 `& < >`。

- 正文上下文：`<` 被转义 → **安全**
- 属性上下文：`"` 没被转义 → `q=" onmouseover="alert(1)` 闭合属性 → **可执行**
- JS 字符串：`"` 没被转义 → `q=";alert(1);//` 闭合字符串 → **可执行**

原始 PoC（`<script>alert(1)</script>`）在正文里失效了，所以只测原 PoC 会判"已修复"。

**这不是"漏了某个路由"，而是"编码函数选错了上下文"。** 所以知识库里给它单独一条规则
`X03_CONTEXT_MISMATCH`，与"兄弟入口没修"的 `X02_STORED_UNFIXED` 区分开。

> 附带的坑：JS 字符串上下文只做 `json.dumps` 也不够。`</script>` 依然会提前闭合脚本块，
> 因为 HTML 解析器不认 JS 字符串边界。必须再把 `< > &` 转成 `\u003c` 这类形式。
> 这是 `x1` 与"看起来也对"的修复之间的分界线。

### 2. 黑名单只拦字面量（XSS-004）

`x3` 只拦 `<script`。于是：

| payload | 结果 |
|---|---|
| `<script>alert(1)</script>` | 400，被拦 |
| `<svg/onload=alert(1)>` | 通过 |
| `" onmouseover="alert(1)` | 通过（根本不需要尖括号） |
| `";alert(1);//` | 通过（根本不需要尖括号） |

**属性逃逸和 JS 字符串逃逸都不需要尖括号**，所以以尖括号为锚点的黑名单对它们完全无效。

### 3. CSP 是缓解，不是修复（XSS-005）

`x4` 反射原样不动，只加 `Content-Security-Policy: script-src 'self'`。

复测结论必须是 `MITIGATED_NOT_FIXED`，理由与 SQLi 的 WAF 虚拟补丁同构：
风险降低了，代码没变。而且 CSP 本身可绕——JSONP 端点、白名单 CDN、script gadget、
report-only 模式、老客户端与内嵌 WebView 都不受约束。

---

## 和 SQLi 的对照

| | SQLi | XSS |
|---|---|---|
| 判定单位 | 入口（endpoint） | **上下文（context）** |
| 核心问句 | 数据有没有改变语义？ | 数据能不能逃逸出上下文？ |
| 单点修复 | 兄弟路由没修 | 兄弟上下文没修 |
| 假净化 | 黑名单拦关键字 | 黑名单拦标签名 |
| 缓解手段 | WAF 虚拟补丁 | CSP |
| 特有模式 | 版本号漂移 | **上下文错配** |

同一个 `R01/R02`（不可达 / 基线异常）被两个类型共用，说明规则库的分层是对的：
**可达性判定与漏洞类型无关，判定逻辑才与类型有关。**

---

## 已知局限

1. **不覆盖 DOM 型 XSS**。`location.hash` 直接进 `innerHTML` 这类漏洞不经过服务端响应，
   服务端反射检测完全看不到。要覆盖需要浏览器侧探针（headless）。
2. **不做真实执行验证**。判据是「逃逸序列原样幸存」，不是「浏览器真的弹窗了」。
   CSP 是否真的挡住、浏览器是否真的解析，都没有实测。这是刻意的取舍：
   引入浏览器会大幅增加复杂度，而"逃逸"已经足以判定修复不成立。
3. **上下文只有三种**。URL（`javascript:`）、注释、`<textarea>`、CSS 内联等未覆盖。
4. **编码判定依赖前缀匹配**。若应用对输入做截断或重组，可能造成漏判。

---

## 实施中踩到的坑

**探针的假阳性**：第一版用 `"` 开头的 payload 直接做子串匹配，结果在"正确转义"的响应里
也匹配到了——因为转义后的 `\"` 本身含有 `"`。

**修复**：所有 payload 加统一前缀 `xsprobe_7f3a`，只有「前缀 + 逃逸序列」整段原样出现
才算幸存。

**反思**：这是「判据的边界条件」问题。判定"字符串是否原样出现"看起来是个平凡操作，
但在转义场景下，被转义的内容里仍然含有原始字符。同类问题还有：用 `in` 判断子串时
忽略大小写、忽略 Unicode 归一化。
