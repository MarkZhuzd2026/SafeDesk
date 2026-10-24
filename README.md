<div align="center">

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

登录方式：手机号验证码、微信扫码、管理员账户。默认管理员为 `admin` / `SafeDesk@Admin`。普通用户只能管理自己的沙箱，审批由管理员完成。

### 演示路径

1. 登录控制台，查看总览指标、待审批数量和安全拦截。
2. 选择 Claude Code、Codex 或 DSH，或使用任务模板。
3. 选择策略：标准研发、只读审阅或受限构建。
4. 填写项目绝对路径，勾选凭据能力和 MCP 服务，不要填写任何密钥。
5. 创建待审批沙箱，查看编译后的启动清单。
6. 管理员审批启动后，安全事件会记录凭据代签与外联拦截。
7. 终止沙箱，确认状态变为 `terminated`。

### 文档

- 架构设计：[docs/safedesk/ARCHITECTURE.md](docs/safedesk/ARCHITECTURE.md)
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

Sign-in methods: phone OTP, WeChat QR, and an admin account. Default admin is `admin` / `SafeDesk@Admin`. Regular users only manage their own sandboxes; admins approve launches.

### Demo path

1. Sign in to the console and check overview metrics, pending approvals, and blocked events.
2. Choose Claude Code, Codex, or DSH, or apply a task template.
3. Choose a policy: Standard Development, Read-only Review, or Restricted Build.
4. Enter an absolute project path and select credential/MCP capabilities. Do not paste secrets.
5. Create a pending sandbox and inspect the compiled launch plan.
6. An admin approves the sandbox. Security events record credential proxying and blocked egress.
7. Terminate the sandbox and confirm the status becomes `terminated`.

### Docs

- Architecture: [docs/safedesk/ARCHITECTURE.md](docs/safedesk/ARCHITECTURE.md)
- Runbook: [docs/safedesk/RUNBOOK.md](docs/safedesk/RUNBOOK.md)
- Control plane: [apps/safedesk-control-plane/README.md](apps/safedesk-control-plane/README.md)
- Underlying runtime notes: [docs/safedesk/RUNTIME.md](docs/safedesk/RUNTIME.md)
- API demos: [demos/README.md](demos/README.md)
