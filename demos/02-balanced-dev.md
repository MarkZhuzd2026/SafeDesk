# Demo 02 · 标准研发：Claude Code 改代码 + 凭据代签

场景：开发让 **Claude Code** 在 `pay-service` 仓库上做一个功能分支，需要读 GitHub 代码、调模型、访问一个只读 Postgres MCP 服务。要求是它能干活，但密钥绝不出现在沙箱环境变量里。这对应 `balanced`（标准研发）策略。

前置：已按 [README](./README.md) 启动控制面并设置 `BASE`。

## 1. 创建带凭据 profile 与 MCP 白名单的沙箱

```bash
curl -s -X POST $BASE/api/sandboxes \
  -H 'Content-Type: application/json' \
  -d '{"name":"feature-branch","agent":"claude-code","policyId":"balanced","workspace":"/srv/workspaces/pay-service","credentials":["github-read","llm-gateway"],"mcpServers":["github","postgres-read"]}'
```

预期输出（节选）：

```json
{
  "sandbox": {
    "id": "sbx-389e72a7",
    "agent": "claude-code",
    "policyId": "balanced",
    "credentials": ["github-read", "llm-gateway"],
    "mcpServers": ["github", "postgres-read"],
    "status": "pending_approval"
  },
  "manifest": {
    "runtime": { "network": "brokered" },
    "filesystem": { "mode": "rw" },
    "credentialBroker": {
      "enabled": true,
      "exposedValues": false,
      "profiles": ["github-read", "llm-gateway"]
    },
    "mcpGateway": {
      "enabled": true,
      "transport": "streamable-http",
      "allowedServers": ["github", "postgres-read"]
    },
    "enforcement": { "approval": "destructive", "maxCpu": 2, "maxMemoryMb": 4096 }
  }
}
```

关注点（与 demo 01 的差异即 `balanced` 的定位）：

- `network: brokered`：有网，但所有流量必须经主机凭据代理，默认拒绝未知外联。
- `credentials` 只是 profile 名——沙箱拿到的是 Broker 地址与占位符，`exposedValues: false` 保证真实 token 不落盘、不进 env。
- `mcpServers` 是**白名单**而非配置原文：符合“MCP 配置不在沙箱内填密钥”的产品红线，密钥由主机在 MCP 网关上代签。
- `approval: destructive`：只有破坏性动作（删文件、force push 等）需要审批，日常读写放行。

## 2. 记下沙箱 ID

```bash
SBX=<SBX>
```

## 3. 审批启动

```bash
curl -s -X POST $BASE/api/sandboxes/$SBX/approve
```

预期 `status` 变为 `running`。

## 4. 确认凭据代签事件

```bash
curl -s $BASE/api/events
```

预期能在事件流看到（节选）：

```json
[
  { "level": "allow", "action": "人工审批", "detail": "feature-branch 已启动；凭据仅由主机 Broker 按策略代签" },
  { "level": "info",  "action": "创建待审批沙箱", "detail": "feature-branch 使用 标准研发 策略" }
]
```

服务启动事件流中还预置了一条 `凭据代签` 示例事件：`github-read 通过 Host Credential Broker 注入 Authorization 头`——即模型/代码请求外发时由主机补签授权头，沙箱自始至终见不到密钥。

## 5. 收尾

```bash
curl -s -X POST $BASE/api/sandboxes/$SBX/terminate
```

预期 `status` 变为 `terminated`；Broker 上为该会话发放的短期凭据同时失效。

## 本 demo 讲清了什么

- **凭据三段式**：用户选 profile → 清单只记 profile 名 → 主机 Broker 运行时注入。
- **MCP 零密钥配置**：沙箱只见网关地址与 server 名，不见 API Key / Password。
- **审批分级**：破坏性操作才打断用户，避免审批疲劳。
