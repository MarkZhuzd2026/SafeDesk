# 企业级沙箱市场调研报告 & SafeDesk 对比分析

> 调研时间：2026-10-24  
> 目的：盘点市面主流的企业级（Agent 代码执行）沙箱产品功能，对比 SafeDesk 当前实现，找出差距与优势，指导后续建设。

---

## 1. 市场格局总览

2025–2026 年，"给 AI Agent 一个安全的执行环境"已从边缘需求变成独立基础设施赛道，大致分四类玩家：

| 类别            | 代表产品                                                                      | 定位一句话                     |
| ------------- | ------------------------------------------------------------------------- | ------------------------- |
| 云端 Agent 沙箱平台 | E2B、Daytona、Modal、Cloudflare Sandbox、Vercel Sandbox、Northflank            | API/SDK 即用的托管沙箱，按秒计费      |
| 本地/自托管沙箱运行时   | microsandbox、Anthropic sandbox-runtime（srt）                               | 跑在自己硬件上，重点是本地开发与合规        |
| 模型厂自带沙箱       | Claude Code 沙箱化、Claude Code on the web、OpenAI Codex 云环境                   | 沙箱是 coding agent 产品的内置安全层 |
| 底层隔离技术        | Firecracker、gVisor、Kata/Cloud Hypervisor、bubblewrap/seatbelt、WASM（Wasmer） | 上面所有产品的隔离基座               |

**SafeDesk 的独特身位**：属于"本地/自托管 + 企业控制面 + coding agent 终端生命周期管理"的交集，与 E2B（云 API 型）不是一个物种，和 **microsandbox 的定位" + OpenAI 的《Running Codex safely》描述的内部治理栈**最接近。

## 2. 重点产品功能盘点

### 2.1 E2B —— 品类领导者

- 隔离：每会话一个 Firecracker microVM、独立内核；运行时 Apache-2.0 开源
- 生命周期：pause/resume（内存级暂停）、snapshot、fork；Pro 会话上限 24h，暂停无限保留
- 网络：按沙箱配 egress allow/deny（IP/CIDR/域名），可接入自托管 SOCKS5 代理，失败即关闭（fails closed）
- 密钥：**Secrets 在 egress 层解析注入**，密钥值不进入沙箱（"密钥可达不可读"）——与 SafeDesk 设计相同
- 可观测：OTLP 指标/日志、带签名的生命周期 webhook
- 部署：托管云（美/欧/亚太）、BYOC（AWS/GCP/Azure，企业版）、Private cloud（气隙网络）、E2B Embed（单机全栈）
- 合规：SOC 2 Type II、HIPAA BAA、DPA、独立渗透测试报告
- 生态：Python/JS SDK、Code Interpreter、Desktop（computer-use）、200+ MCP 服务、主流框架集成
- 规模背书：94 家 Fortune 100、2B+ 累计沙箱、SOC 2 + 渗透测试是典型企业采购敲门砖

### 2.2 Daytona —— 有状态开发环境型

- 冷启动 ~90ms（预热池）；Docker/Sysbox 容器默认，Kata microVM 可选
- 环境广度最强：Linux 容器/VM、Windows、macOS、GPU（H100、RTX PRO 6000）、Computer Use 桌面
- 生命周期：快照保存/恢复/分叉、无限时可配置、Volumes 跨沙箱共享数据
- 可编程面：File/Git/LSP/Execute API，SDK 覆盖 Python/TS/Ruby/Go/Java
- 缺口：2026 年 6 月核心代码转闭源、只管得了云（自托管路径收窄）

### 2.3 Modal —— GPU/算力型

- gVisor 容器隔离（CPU-only VM 沙箱在 beta）
- 强项：全系列 GPU（T4→B200）按沙箱配置、5 万–10 万并发、与 Modal 镜像/Volumes/Secrets 共享
- 网络：tunnels 直连 + 细粒度 egress 策略；文件系统快照
- 纯托管，无 BYOC；价格约比 E2B/Daytona 高 40%

### 2.4 microsandbox —— 与 SafeDesk 最像的竞品（重点参考）

- 本地 microVM（Linux KVM / macOS Hypervisor.framework），一个沙箱一个内核，冷启动 <200ms
- Apache-2.0 全开源、OCI 镜像兼容、无守护进程无 root、SDK（Rust/TS/Python/Go）+ MCP
- 安全模型文档化做得极好：明确"保护 host 防 guest，不防已沦陷的 host"
- 网络：默认放行公网但**deny 私网/回环/link-local/云元数据**（防 SSRF），可降为白名单
- 密钥：**占位符（placeholder）在沙箱内，真实值在 host 侧按"目的地白名单"拦截注入**——与 SafeDesk "MCP 不填密钥、主机代签"理念完全一致，且是少数真做出来的实现
- 云上版本（私有 beta）：org、SSO、审计日志、配额——企业控制面与 SafeDesk 控制面同构

### 2.5 Anthropic sandbox-runtime（srt）与 Claude Code 沙箱化

- 不是 VM：macOS sandbox-exec/seatbelt + Linux bubblewrap，进程级、零容器开销，Apache-2.0 开源
- 双隔离模型：文件系统（默认到处可读、仅 CWD 可写）+ 网络（全部走 host 侧 HTTP/SOCKS5 代理，按域名白名单，fail close）
- 产品化数据：srt 让 Claude Code 权限弹窗减少 84%；支持被注入提示攻击完全隔离在沙箱内
- Claude Code on the web：云端隔离沙箱运行会话，git 凭据/签名密钥绝不进沙箱，由代理透明处理 git 交互
- 企业可以自定义代理做 HTTPS 解密检查、细粒度过滤、全量审计、接 SIEM

### 2.6 OpenAI Codex 环境（云 + 本地治理栈）

- 默认"关机网络"模式：文件写仅限工作区、网络默认关；云上可限定可信域
- OpenAI 内部治理实践（《Running Codex safely》）是典型企业参考模板：
  - 托管式网络策略：预期目的地放行、黑名单拦截、陌生域需审批；Auto-review 子代理自动批低风险越界请求
  - 凭据管在 OS keyring、登录绑定 ChatGPT 企业工作区
  - admin 强制的 requirements 配置（用户不可覆盖），跨桌面 app/CLI/IDE 统一
  - OpenTelemetry 导出代理原生日志（提示、审批决策、工具结果、MCP 使用、网络 allow/deny 事件），进 SIEM，供 AI 安全分诊代理消费

### 2.7 Cloudflare Sandbox / Vercel Sandbox / Northflank

- Cloudflare：边缘容器 + Durable Objects，冷启动 <50ms 级，R2/S3 挂载持久化，按 Active CPU 计费
- Vercel Sandbox：Firecracker microVM，GA 于 2026.1，45min–5h(24h 企业)会话上限，Active CPU 计费
- Northflank：多隔离可选（Firecracker/Kata/Cloud Hypervisor/gVisor）+ 自助 BYOC（8 种云/裸金属），200 沙箱稳态月成本对比：Northflank $7.2k vs E2B $16.8k vs Modal $24.5k vs Vercel $31k

## 3. 关键能力对比矩阵

| 能力         | E2B                        | Daytona      | Modal           | microsandbox         | srt(Anthropic)   | Codex 治理栈                     | SafeDesk 现状                       |
| ---------- | -------------------------- | ------------ | --------------- | -------------------- | ---------------- | ----------------------------- | --------------------------------- |
| 隔离强度       | VM（每会话内核）                  | 容器默认/Kata 可选 | gVisor          | microVM 每沙箱内核        | 进程级（OS 原语）       | 容器（云）/本地受限                    | WASM 能力沙箱（wasmer/WASIX）*仅设计*      |
| 冷启动        | ~150ms                     | ~90ms        | 亚秒              | <200ms               | 毫秒（无容器）          | —                             | —（未实现拉起）                          |
| 密钥不落沙箱     | ✅ egress 注入                | 部分           | 部分（Secrets）     | ✅ 占位符+目的地绑定          | ✅（凭据文件 denyRead） | ✅（代理透明处理 git）                 | ✅ 设计（CredentialBroker，未实现）        |
| 网络白名单代理    | ✅                          | 部分           | ✅ egress policy | ✅                    | ✅ host 代理        | ✅                             | ✅ 设计（MCP Gateway/网络代理，未实现）        |
| 审批/人工介入    | ✗（API 型）                   | ✗            | ✗               | ✗                    | 运行时越界弹确认         | ✅ Auto-review + requirements  | ✅ 已实现（启动前审批、管理端拒绝带原因）             |
| 生命周期       | pause/resume/snapshot/fork | 快照/分叉/volume | 快照/24h          | 基础                   | —                | 任务级隔离                         | 状态机：待审批/运行/暂停/恢复/终止（已实现）          |
| 企业 RBAC/组织 | org/SSO（企业版）               | 有限           | 有限              | cloud beta 有         | ✗                | 企业工作区+requirements            | ✅ 已实现（admin/user、用户只见自己沙箱、组织设置）   |
| 审计/合规      | SOC2 II、HIPAA、OTLP webhook | —            | —               | 审计日志（beta）           | 违规日志             | OTel + Compliance Logs + SIEM | ✅ 内存事件流（40 条环形，未持久化/未外送）          |
| 登录认证       | API key                    | API key      | API key         | —                    | —                | ChatGPT 企业绑定                  | ✅ 已实现（手机号 OTP、微信/企业微信扫码、管理员）      |
| 自托管        | ✅ 开源+Embed                 | ✗（转闭源）       | ✗               | ✅ 本地优先               | ✅ npm 包          | ✗                             | ✅ 全本地                             |
| 桌面/多 agent | Desktop 协议                 | 桌面/GPU       | —               | Claude Code/Codex 接入 | Claude Code 原生   | Codex 原生                      | 设计支持 Claude Code/Codex/DSH 统一生命周期 |

## 4. SafeDesk 优势与差距分析

### 4.1 已建立的差异化优势

1. **企业控制面完整度领先**：登录认证（OTP/微信/企业微信扫码/admin）、启动前审批流（批准/拒绝带原因）、组织设置（并发上限、会话超时、审计保留、登录方式开关）、企业工作台（指标总览、任务模板、搜索筛选、风险分布）。E2B/Daytona/microsandbox 都不内置人工审批，OpenAI 的 requirements+Auto-review 是闭源自用的。**"管理端审批 + 最终用户友好"正是赛题要求的核心差异点。**
2. **三策略收口模型**：balanced/review/build 三档预设 → 编译出 `SandboxLaunchPlan`（资源限额、SECRET_PATHS 遮蔽清单、credentialBroker、mcpGateway、append-only 审计），安全默认值对最终用户"开箱即用"。
3. **密钥不进沙箱的产品哲学**与 E2B/microsandbox 同源，且更早把"MCP 白名单 + 主机代签"做成必选（而非可选）。
4. **全本地/自托管自带**：无云依赖，自带 TLS HTTPS，天然满足数据不出域。

### 4.2 主要差距（按优先级排序）

| 优先级 | 差距                                                  | 市场上的参照做法                                                          |
| --- | --------------------------------------------------- | ----------------------------------------------------------------- |
| P0  | **沙箱内核未真正接入**：控制面只管理状态机，wasmer/WASIX 实际拉起、资源限额执行未落地 | microsandbox 证明"本地 <200ms 拉起真实微内核"可落地；应定义 LaunchPlan→sidecar 执行契约 |
| P0  | **Host Credential Broker 无实现**：只有 manifest 声明与事件文案  | microsandbox 的"占位符 + 目的地白名单拦截注入"、E2B 的 egress 解析密钥，是可直接抄的架构       |
| P0  | **网络代理/外联拦截无实现**：意识上没有真实代理进程                        | srt 的 host 侧 HTTP+SOCKS5 双代理（Unix socket 入沙箱、网络命名空间摘除）是最小可用方案     |
| P1  | **MCP Gateway 无实现**：目前只是白名单配置                       | srt 包装 MCP server 的 `.mcp.json` 前置做法 + 白名单路由（streamable-http）     |
| P1  | **审计未持久化无外送**：内存 40 条环形缓冲                           | Codex 的 OTel 导出、E2B 的签名 webhook；至少先落盘 append-only + 事件查询 API 分页   |
| P2  | **无持久化/快照能力**：沙箱不可序列化                               | Daytona/E2B 的 snapshot→fork 是代理级工作流标配（后续阶段）                       |
| P2  | **会话遥测弱**：无 agent 级 activity（工具调用、网络决策）             | Codex "agent-native telemetry"：把网络 allow/deny、审批决策做成结构化 span      |
| P3  | 合规背书与安全模型文档                                         | microsandbox 的 Security model 页模板：明确信任边界、在界内/界外社区                 |

### 4.3 建议的落地路线

**Phase 1（把设计变真）**

1. 实现 LaunchPlan → sidecar 执行器：拉起 wasmer `run`，强制 `--volume/--net/--env` 三策略与资源限额，沙箱真实产生进程。
2. Host Credential Broker 最小版：host 侧 HTTP 代理，沙箱内一律占位符，按目的地白名单代签注入；全程不落盘密钥。
3. 网络代理最小版：默认 deny 私网/回环/元数据（防 SSRF），公网走白名单，fail closed。

**Phase 2（企业化补强）**  
4\. MCP Gateway：白名单 MCP 服务注册 + streamable-http 路由 + 每沙箱凭据绑定。  
5\. 审计持久化 append-only + OTel/webhook 外送；`/api/events` 分页。  
6\. 安全模型文档（参照 microsandbox）：信任边界、担保范围、明确不担保项。

**Phase 3（体验对标）**  
7\. 快照/暂停内存级 resume（E2B 式 AutoResume）。  
8\. agent 级遥测 span（工具调用/网络决策/审批链），方便接 SIEM。

---

## 5. 结论

- 市场已被 E2B 验证了"安全沙箱是第一优先级"的共识：隔离强度（每会话内核/能力沙箱）+ 密钥不落沙箱 + egress 白名单是被 Fortune 100 认可的三个支柱。**SafeDesk 的架构方向与市场最佳实践高度一致**，且"审批流 + 组织管理 + 本地友好"的差异化成立。
- 当前最大的风险不是架构而是**执行侧未闭环**：六大模块中控制面/策略编译已可用，但隔离运行时、凭据代签、MCP 网关只活在文档和 manifest 中。microsandbox 已证明这条路（本地 microVM + 主机侧代签 + 目的地绑定密钥）在 200ms 体验内完全可行，应作为第一参照实现。
- 短期最划算的"抄作业"对象：**microsandbox（安全模型 + 密钥占位符注入）+ Anthropic srt（host 侧代理 + MCP 包装）+ OpenAI requirements 模式（admin 强制配置 + OTel 遥测）**，三者都是开源/公开实践，可快速补齐。

---

### 主要参考来源

- E2B Enterprise: <https://e2b.dev/enterprise> ，E2B Security & Compliance（SOC2/BYOC/OTLP/egress）
- Anthropic: Beyond permission prompts（sandbox 弹窗 -84%）/ anthropic-experimental/sandbox-runtime README / claude-code-sandboxing 工程博客
- OpenAI: Running Codex safely at OpenAI（requirements、Auto-review、OTel、keyring）/ Introducing Codex（默认关网、云端隔离容器）
- microsandbox: 官网安全模型页（信任边界、占位符密钥、SSRF 默认 deny）
- Northflank / Modal / Vercel / Cloudflare / Daytona 2026 年第三方评测（drydock、reactify-solutions、changegamer、fast.io、decryptiondigest）
