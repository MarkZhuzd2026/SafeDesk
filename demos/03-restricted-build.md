# Demo 03 · 受限构建：DSH 跑夜间构建，出网先过白名单

场景：CI 由 **DSH** 在沙箱内执行夜间构建。构建需要写临时目录、拉依赖，但绝不允许悄悄访问任意外网。这对应 `build`（受限构建）策略：临时工作区 + 出网白名单 + 更高的资源配额。

前置：已按 [README](./README.md) 启动控制面并设置 `BASE`。

## 1. 创建构建沙箱

```bash
curl -s -X POST $BASE/api/sandboxes \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"nightly-build","agent":"dsh","policyId":"build","workspace":"/srv/build/cache"}'
```

预期输出（节选）：

```json
{
  "sandbox": {
    "id": "sbx-649f12c5",
    "agent": "dsh",
    "policyId": "build",
    "status": "pending_approval"
  },
  "manifest": {
    "runtime": { "network": "allowlist", "volume": "/srv/build/cache:/workspace" },
    "filesystem": { "mode": "ephemeral" },
    "enforcement": {
      "approval": "egress_and_destructive",
      "maxCpu": 4,
      "maxMemoryMb": 8192,
      "audit": "append-only"
    }
  }
}
```

关注点：

- `filesystem.mode: ephemeral`：工作区是临时的，构建结束即焚，不污染源码树。
- `network: allowlist`：默认无网，只有白名单内的构建镜像/代理可达——供应链攻击最常用的“构建脚本里藏 curl 外传”这条路径被堵死。
- `approval: egress_and_destructive`：新增出网目标和破坏性操作都要审批，是三套策略里最严的一档。
- `maxCpu: 4 / maxMemoryMb: 8192`：构建合法地需要更多资源，但仍有硬顶。

## 2. 记下沙箱 ID

```bash
SBX=<SBX>
```

## 3. 审批并启动

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/$SBX/approve
```

预期 `status` 变为 `running`。

## 4. 核对清单与事件

```bash
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/$SBX/manifest
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/events
```

预期事件中包含：

```json
{ "level": "allow", "action": "人工审批", "detail": "nightly-build 已启动；凭据仅由主机 Broker 按策略代签" }
```

## 5. 构建完成后销毁

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/$SBX/terminate
```

预期 `status` 变为 `terminated`，临时工作区与会话凭据一并失效。

## 三套策略横向对比

| 字段 | review 只读审阅 | balanced 标准研发 | build 受限构建 |
| ---- | -------------- | ---------------- | ------------- |
| workspaceMode | `ro` | `rw` | `ephemeral` |
| networkMode | `disabled` | `brokered` | `allowlist` |
| approval | `all_writes` | `destructive` | `egress_and_destructive` |
| maxCpu / maxMemoryMb | 1 / 2048 | 2 / 4096 | 4 / 8192 |

一条规律：**读写越宽、出网越多，审批越严、资源越高**——能力与安全闸门口径同步缩放。
