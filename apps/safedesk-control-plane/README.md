# SafeDesk Control Plane

企业级 Agent 安全沙箱的控制面。它不把密钥写进沙箱，也不让用户面对底层运行时参数。用户只选择 Agent、项目目录和能力，其余由策略编译器生成启动清单。

The enterprise control plane for SafeDesk. Secrets never enter the sandbox, and users never configure low-level runtime flags. They only choose the agent, workspace, and capabilities; the policy compiler produces the launch plan.

## 产品原则 / Product principles

1. **安全优先 / Security first**：默认拒绝文件系统、网络和环境变量；密钥永远留在主机凭据代理。
2. **最终用户友好 / End-user friendly**：配置只问“谁来跑、能碰哪、要哪些能力”。
3. **主流 Agent 可运行 / Mainstream agents**：Claude Code、Codex、DSH 走同一套沙箱生命周期。
4. **MCP 不填敏感信息 / No secrets in MCP config**：沙箱内只看到占位符和网关地址，真实 API Key / Password 由主机代签。

## 本地运行 / Local run

推荐在具备 Node.js 20+ 的环境运行：

```bash
cd apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 node server.mjs
```

当前开发机未安装 Node.js，使用零依赖 Python 控制面：

```bash
cd /opt/safedesk/apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 python3 server.py
```

开发机公网入口 / public endpoints：

- http://218.11.5.249:10648/
- http://111.62.156.213:10645/

两者都映射到内网 `8022`。

## 验证 / Tests

```bash
cd apps/safedesk-control-plane
node --test test/*.test.mjs
```

底层隔离运行时说明见 [docs/safedesk/RUNTIME.md](../../docs/safedesk/RUNTIME.md)。
