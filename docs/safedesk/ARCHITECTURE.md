# SafeDesk 架构设计

## 产品定位

SafeDesk 是基于 [Wasmer](https://wasmer.io/) 二次开发的桌面级企业安全沙箱。它让 Claude Code、Codex、DSH 等主流 Agent 在隔离环境中工作，同时保证：

- 安全优先，默认无文件、无网络、无环境变量。
- 最终用户只做最少配置，不接触 `--volume` / `--net` / WASIX 细节。
- 所有主流 MCP 配置都不在沙箱内填写 API Key、Password 或其他敏感信息。

## 模块规格

| 模块 | 职责 | 边界 |
| --- | --- | --- |
| Control Plane | 策略选择、沙箱生命周期、审批、审计展示 | 不持有明文密钥 |
| Policy Compiler | 把用户意图编译成 Wasmer 启动清单 | 只输出能力，不输出密钥 |
| Host Credential Broker | 在主机侧代签出站请求 | 沙箱只看到 `proxy-managed` |
| MCP Gateway | 把 stdio MCP 转成 Streamable HTTP | 凭据注入发生在网关，不进沙箱 |
| Wasmer Runtime | WASIX 隔离执行 | 仅挂载项目目录，不挂载 `~/.ssh` / `.env` |
| Audit Log | 记录策略编译、代签、拦截、终止 | 追加写，不记录密钥值 |

## 信任边界

```
用户 → SafeDesk UI → Control Plane → Policy Compiler
                                  → Host Credential Broker → 外部 API
                                  → MCP Gateway → MCP Server
                                  → Wasmer Sandbox → Agent
```

沙箱内可见：项目文件、Agent 二进制、MCP 网关地址、凭据占位符。
沙箱内不可见：真实 API Key、OS 钥匙串、主机环境变量、家目录密钥文件。

## 二次开发点

Wasmer 默认安全模型已经足够作为隔离底座。SafeDesk 在其上增加企业层：

1. 把 `--volume` / `--net` / `--env` 收口为三种策略：标准研发、只读审阅、受限构建。
2. 禁止 `--forward-host-env`。
3. 所有模型与 MCP 流量走主机代理，而不是把密钥注入 guest env。
4. 启动前必须审批，终止后短期会话凭据立即失效。
