<div align="center">

<img src="apps/safedesk-control-plane/static/brand/logo-icon.png" alt="SafeDesk" width="96" />

# SafeDesk

**企业级 Agent 安全沙箱 / Enterprise Agent Security Sandbox**

安全优先，配置对最终用户友好。

Security first. Friendly for the people who actually use it.

[中文](#safedesk) · [English](#english)

</div>

## 中文

SafeDesk 是桌面级企业安全沙箱。它让主流 Agent 在隔离环境中工作，同时把密钥、密码和主机凭据留在沙箱之外。

### 产品原则

1. **安全优先**：默认拒绝文件系统、网络和环境变量；密钥永远留在主机凭据代理。
2. **最终用户友好**：配置只问“谁来跑、能碰哪、要哪些能力”，不暴露底层运行时参数。
3. **主流 Agent 可运行**：Claude Code、Codex、DSH 走同一套沙箱生命周期。
4. **MCP 不填敏感信息**：沙箱内只看到能力清单和网关地址，真实 API Key / Password 由主机代签。

### 快速开始

开发环境公网入口（HTTPS，自签证书）：

- https://218.11.5.249:10648/
- https://111.62.156.213:10645/

本地启动控制面：

```bash
cd apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 python3 server.py
```

具备 Node.js 20+ 时也可以：

```bash
cd apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 node server.mjs
```

登录方式：手机号验证码、微信扫码、管理员账户。默认管理员为 `admin` / `SafeDesk@Admin`，登录后可在组织设置中修改密码；改密后重启服务不会恢复默认值。普通用户只能管理自己的沙箱，审批由管理员完成。

### 演示路径

1. 登录控制台，查看总览指标、待审批数量和安全拦截。
2. 选择 Claude Code、Codex 或 DSH，或使用任务模板。
3. 选择策略：标准研发、只读审阅或受限构建。
4. 填写项目绝对路径，勾选凭据能力和 MCP 服务，不要填写任何密钥。
5. 创建待审批沙箱，查看编译后的启动清单。
6. 管理员审批启动后，安全事件会记录凭据代签与外联拦截。
7. 终止沙箱，确认状态变为 `terminated`。

### 关键能力对比矩阵

SafeDesk 与市面主流企业级沙箱的能力对比（2026 年 10 月调研）：

| 能力 | SafeDesk | E2B | Daytona | Modal | microsandbox | Anthropic srt | Codex 治理栈 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 隔离运行时 | WASM 能力沙箱（wasmer/WASIX，设计中） | Firecracker microVM（每会话内核） | 容器默认，Kata 可选 | gVisor 容器 | 本地 microVM（每沙箱内核） | 进程级 OS 原语（seatbelt/bubblewrap） | 云端隔离容器 |
| 冷启动 | —（待接入） | ~150ms | ~90ms | 亚秒 | <200ms | 毫秒级（无容器） | — |
| 密钥不落沙箱 | 主机代签（已设计，实现中） | ✅ egress 层注入 | 部分 | 部分（Secrets） | ✅ 占位符 + 目的地白名单注入 | ✅ 凭据文件 denyRead | ✅ 代理透明处理 |
| 网络白名单代理 | MCP Gateway（已设计，实现中） | ✅ 按沙箱 allow/deny | 部分 | ✅ 细粒度 egress | ✅ 默认 deny 私网/元数据 | ✅ host 侧 HTTP/SOCKS5 代理 | ✅ 托管网络策略 |
| 人工审批流 | ✅ 启动前审批、拒绝带原因 | ✗ | ✗ | ✗ | ✗ | 运行时越界弹确认 | ✅ Auto-review + 强制配置 |
| 企业控制面（RBAC/组织/工作台） | ✅ 已实现 | 企业版 org/SSO | 有限 | 有限 | 云端 beta | ✗ | ✅ 企业工作区 |
| 多登录方式（OTP/扫码/管理员） | ✅ 已实现 | ✗（API key） | ✗ | ✗ | — | ✗ | ChatGPT 企业绑定 |
| 审计与安全事件 | ✅ 事件流（持久化/外送规划中） | ✅ SOC 2 II、OTLP、签名 webhook | — | — | 审计日志（beta） | 违规日志 | ✅ OTel + SIEM |
| 生命周期管理 | ✅ 待审批/运行/暂停/恢复/终止状态机 | ✅ pause/resume/snapshot/fork | ✅ 快照/分叉/Volumes | 快照/24h | 基础 | — | 任务级隔离 |
| 自托管 / 本地化 | ✅ 本地优先，自带 TLS | ✅ 开源 + Embed + BYOC | ✗（已转闭源） | ✗ | ✅ 本地优先 | ✅ npm 包 | ✗ |

✅ 已实现；其他为当前规划或对方部分支持。详细分析见[市场调研报告](docs/safedesk/MARKET-SANDBOX-SURVEY-2026-10.md)。

### 文档

- 架构设计：[docs/safedesk/ARCHITECTURE.md](docs/safedesk/ARCHITECTURE.md)
- 市场调研：[docs/safedesk/MARKET-SANDBOX-SURVEY-2026-10.md](docs/safedesk/MARKET-SANDBOX-SURVEY-2026-10.md)
- 运行说明：[docs/safedesk/RUNBOOK.md](docs/safedesk/RUNBOOK.md)
- 控制面：[apps/safedesk-control-plane/README.md](apps/safedesk-control-plane/README.md)
- 底层运行时说明：[docs/safedesk/RUNTIME.md](docs/safedesk/RUNTIME.md)
- API 演示案例：[demos/README.md](demos/README.md)

---

## English

SafeDesk is a desktop-class enterprise sandbox for AI agents. Mainstream agents run inside an isolated workspace, while API keys, passwords, and host credentials stay on the host.

### Product principles

1. **Security first**: file, network, and environment access are denied by default. Secrets stay in the host credential broker.
2. **End-user friendly**: users only choose who runs, which workspace, and which capabilities. Runtime flags stay hidden.
3. **Mainstream agents**: Claude Code, Codex, and DSH share the same sandbox lifecycle.
4. **No secrets in MCP config**: the sandbox sees capability names and a gateway URL. Real API keys and passwords are injected on the host.

### Quick start

Public demo endpoints (HTTPS, self-signed certificate):

- https://218.11.5.249:10648/
- https://111.62.156.213:10645/

Start the control plane locally:

```bash
cd apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 python3 server.py
```

With Node.js 20+:

```bash
cd apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 node server.mjs
```

Sign-in methods: phone OTP, WeChat QR, and an admin account. Default admin is `admin` / `SafeDesk@Admin`; change it from Organization Settings after sign-in. A changed password survives service restarts. Regular users only manage their own sandboxes; admins approve launches.

### Demo path

1. Sign in to the console and check overview metrics, pending approvals, and blocked events.
2. Choose Claude Code, Codex, or DSH, or apply a task template.
3. Choose a policy: Standard Development, Read-only Review, or Restricted Build.
4. Enter an absolute project path and select credential/MCP capabilities. Do not paste secrets.
5. Create a pending sandbox and inspect the compiled launch plan.
6. An admin approves the sandbox. Security events record credential proxying and blocked egress.
7. Terminate the sandbox and confirm the status becomes `terminated`.

### Capability comparison matrix

SafeDesk versus mainstream enterprise sandboxes (surveyed October 2026):

| Capability | SafeDesk | E2B | Daytona | Modal | microsandbox | Anthropic srt | Codex governance stack |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Isolation runtime | WASM capability sandbox (wasmer/WASIX, in design) | Firecracker microVM (kernel per session) | Container by default, Kata optional | gVisor containers | Local microVM (kernel per sandbox) | Process-level OS primitives (seatbelt/bubblewrap) | Isolated cloud container |
| Cold start | — (to be wired) | ~150ms | ~90ms | Sub-second | <200ms | Milliseconds (no container) | — |
| Secrets stay out of the sandbox | Host-side signing (designed, being implemented) | ✅ injected at egress layer | Partial | Partial (Secrets) | ✅ placeholder + destination-allowlist injection | ✅ credential files denied by default | ✅ brokered through proxy |
| Network allowlist proxy | MCP Gateway (designed, being implemented) | ✅ per-sandbox allow/deny | Partial | ✅ granular egress policy | ✅ denies private/metadata routes by default | ✅ host-side HTTP/SOCKS5 proxies | ✅ managed network policy |
| Human approval workflow | ✅ pre-launch approval, rejection with reason | ✗ | ✗ | ✗ | ✗ | Runtime violation prompts | ✅ Auto-review + enforced requirements |
| Enterprise control plane (RBAC/org/workbench) | ✅ shipped | Org/SSO on Enterprise plan | Limited | Limited | Cloud private beta | ✗ | ✅ enterprise workspace |
| Multiple sign-in methods (OTP/QR/admin) | ✅ shipped | ✗ (API key) | ✗ | ✗ | — | ✗ | Bound to ChatGPT workspace |
| Audit & security events | ✅ event stream (persistence/export planned) | ✅ SOC 2 II, OTLP, signed webhooks | — | — | Audit logs (beta) | Violation logs | ✅ OpenTelemetry + SIEM |
| Lifecycle management | ✅ pending/running/paused/resumed/terminated state machine | ✅ pause/resume/snapshot/fork | ✅ snapshots/fork/Volumes | Snapshots/24h | Basic | — | Per-task isolation |
| Self-hosting / local-first | ✅ local-first with built-in TLS | ✅ open source + Embed + BYOC | ✗ (closed since 2026) | ✗ | ✅ local-first | ✅ npm package | ✗ |

✅ means shipped today; other entries reflect current SafeDesk plans or partial vendor support. See the full [market survey report](docs/safedesk/MARKET-SANDBOX-SURVEY-2026-10.md).

### Docs

- Architecture: [docs/safedesk/ARCHITECTURE.md](docs/safedesk/ARCHITECTURE.md)
- Market survey: [docs/safedesk/MARKET-SANDBOX-SURVEY-2026-10.md](docs/safedesk/MARKET-SANDBOX-SURVEY-2026-10.md)
- Runbook: [docs/safedesk/RUNBOOK.md](docs/safedesk/RUNBOOK.md)
- Control plane: [apps/safedesk-control-plane/README.md](apps/safedesk-control-plane/README.md)
- Underlying runtime notes: [docs/safedesk/RUNTIME.md](docs/safedesk/RUNTIME.md)
- API demos: [demos/README.md](demos/README.md)
