# SafeDesk 架构设计 / Architecture

## 产品定位 / Positioning

SafeDesk 是桌面级企业安全沙箱。它让 Claude Code、Codex、DSH 等主流 Agent 在隔离环境中工作，同时保证：

- 安全优先，默认无文件、无网络、无环境变量。
- 最终用户只做最少配置，不接触底层运行时参数。
- 所有主流 MCP 配置都不在沙箱内填写 API Key、Password 或其他敏感信息。

SafeDesk is a desktop-class enterprise sandbox. Mainstream agents such as Claude Code, Codex, and DSH run in isolation, while:

- File, network, and environment access stay denied by default.
- End users only make a few product choices; they never see low-level runtime flags.
- Mainstream MCP configs never store API keys, passwords, or other secrets inside the sandbox.

底层隔离运行时说明见 [RUNTIME.md](RUNTIME.md)。

See [RUNTIME.md](RUNTIME.md) for the isolation runtime notes.

## 模块规格 / Modules

| 模块 / Module | 职责 / Responsibility | 边界 / Boundary |
| --- | --- | --- |
| Control Plane | 策略选择、沙箱生命周期、审批、审计展示 | 不持有明文密钥 |
| Policy Compiler | 把用户意图编译成启动清单 | 只输出能力，不输出密钥 |
| Host Credential Broker | 在主机侧代签出站请求 | 沙箱只看到 `proxy-managed` |
| MCP Gateway | 把 stdio MCP 转成 Streamable HTTP | 凭据注入发生在网关，不进沙箱 |
| Isolation Runtime | 隔离执行 Agent 与工具 | 仅挂载项目目录，不挂载 `~/.ssh` / `.env` |
| Audit Log | 记录策略编译、代签、拦截、终止 | 追加写，不记录密钥值 |

## 信任边界 / Trust boundary

```
用户 → SafeDesk UI → Control Plane → Policy Compiler
                                  → Host Credential Broker → 外部 API
                                  → MCP Gateway → MCP Server
                                  → Isolation Runtime → Agent
```

沙箱内可见：项目文件、Agent 二进制、MCP 网关地址、凭据占位符。  
沙箱内不可见：真实 API Key、OS 钥匙串、主机环境变量、家目录密钥文件。

Visible inside the sandbox: project files, agent binaries, MCP gateway URL, credential placeholders.  
Never visible inside the sandbox: real API keys, OS keychain, host environment, home-directory secret files.

## 企业层能力 / Enterprise layer

SafeDesk 在隔离底座上增加企业层：

1. 把文件、网络、环境变量收口为三种策略：标准研发、只读审阅、受限构建。
2. 禁止把主机环境变量整包转发给沙箱。
3. 所有模型与 MCP 流量走主机代理，而不是把密钥注入 guest env。
4. 启动前必须审批，终止后短期会话凭据立即失效。
