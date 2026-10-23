# Demo 01 · 只读审阅：让 Codex 做依赖安全审计

场景：安全团队怀疑 `webapp` 项目的依赖有风险，派 **Codex** 进沙箱做静态审计。要求是只看、不许改、不许联网，任何写操作都要人工审批。这正好对应 `review`（只读审阅）策略。

前置：已按 [README](./README.md) 启动控制面并设置 `BASE`。

## 1. 创建待审批沙箱

```bash
curl -s -X POST $BASE/api/sandboxes \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"dep-audit","agent":"codex","policyId":"review","workspace":"/srv/audit/webapp"}'
```

预期输出（节选）：

```json
{
  "sandbox": {
    "id": "sbx-c7b953e0",
    "name": "dep-audit",
    "agent": "codex",
    "policyId": "review",
    "status": "pending_approval"
  },
  "manifest": {
    "runtime": { "network": "disabled", "volume": "/srv/audit/webapp:/workspace" },
    "filesystem": { "mode": "ro" },
    "enforcement": { "approval": "all_writes", "maxCpu": 1, "maxMemoryMb": 2048 }
  }
}
```

关注点：

- `status` 是 `pending_approval`——创建≠启动，必须人工放行。
- `network: disabled`：沙箱没有任何网络出口，依赖投毒想回传数据也没路。
- `filesystem.mode: ro`：工作区只读挂载。
- `secretPaths`（完整响应中可见）默认屏蔽 `/.env`、`/.ssh/**`、`/.aws/**` 等凭据文件。
- 资源封顶 `maxCpu: 1 / maxMemoryMb: 2048`，审计 agent 跑飞也伤不到主机。

## 2. 记下沙箱 ID

把上一步返回的 `sandbox.id`（形如 `sbx-xxxxxxxx`）代入后续命令的 `<SBX>`。

```bash
SBX=<SBX>
```

## 3. 复核启动清单

审批人先看清单再决定：

```bash
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/$SBX/manifest
```

预期与创建时返回的 `manifest` 一致，可逐字段核对：`credentialBroker.exposedValues` 恒为 `false`（密钥值从不暴露给沙箱）。

## 4. 人工审批并启动

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/$SBX/approve
```

预期输出（节选）：

```json
{
  "sandbox": {
    "id": "sbx-c7b953e0",
    "status": "running",
    "startedAt": "2026-10-23T13:43:55.804234Z"
  }
}
```

## 5. 查看安全事件流

```bash
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/events
```

预期最新两条事件（节选）：

```json
[
  { "level": "allow", "action": "人工审批", "detail": "dep-audit 已启动；凭据仅由主机 Broker 按策略代签" },
  { "level": "info",  "action": "创建待审批沙箱", "detail": "dep-audit 使用 只读审阅 策略" }
]
```

事件流是 append-only 的，审计时可直接追溯“谁创建、谁放行、何时终止”。

## 6. 审计结束，终止沙箱

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/$SBX/terminate
```

预期输出（节选）：

```json
{
  "sandbox": {
    "status": "terminated",
    "terminatedAt": "2026-10-23T13:43:56.633261Z"
  }
}
```

终止后该沙箱对应的短期会话凭据立即失效，实例不可复用。

## 本 demo 讲清了什么

- **默认拒绝**：创建时需要显式策略，策略里最小权限（ro + 断网）。
- **审批闸门**：`pending_approval → running` 必须人工触发。
- **密钥不出主机**：全程没有 API key / token 字段进入沙箱配置。
