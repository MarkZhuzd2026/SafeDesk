# SafeDesk Demos / 演示案例

四个可照着敲的演示场景，覆盖 SafeDesk 控制面的完整沙箱生命周期与安全边界。所有命令逐条可复制执行，无脚本封装。

Four copy-paste demo scenarios covering the full sandbox lifecycle and security guardrails of the SafeDesk control plane. Commands are listed one by one — no wrapper scripts.

| Demo | 场景 | 看点 |
| ---- | ---- | ---- |
| [01-readonly-review](./01-readonly-review.md) | 只读审阅 | `review` 策略：工作区只读、网络禁用，适合依赖审计 |
| [02-balanced-dev](./02-balanced-dev.md) | 标准研发 | `balanced` 策略：凭据 Broker 代签 + MCP 网关白名单 |
| [03-restricted-build](./03-restricted-build.md) | 受限构建 | `build` 策略：临时工作区 + 出网白名单复核 |
| [04-guardrails](./04-guardrails.md) | 防护与拒绝路径 | 400 / 404 / 409：不合法输入与非法状态跳转被拒 |

## 前置条件 / Prerequisites

1. 启动控制面（三选一）：

```bash
# 本机 Node.js 20+
cd apps/safedesk-control-plane
PORT=18022 HOST=0.0.0.0 node server.mjs
```

```bash
# 本机零依赖 Python
cd apps/safedesk-control-plane
PORT=18022 HOST=0.0.0.0 python3 server.py
```

```bash
# 或直接用已部署的开发机
# 不需要启动任何东西，下一步把 BASE 指向公网入口即可
```

2. 设置请求根地址（每条 demo 的第一步都假设它已设置）：

```bash
# 本机
BASE=http://127.0.0.1:18022

# 开发机公网入口（任选其一）
BASE=http://218.11.5.249:10648
BASE=http://111.62.156.213:10645
```

3. 确认服务存活：

```bash
curl -s $BASE/api/bootstrap | head -c 200
```

预期返回以 `{"policies":` 开头的 JSON，包含 `balanced` / `review` / `build` 三个策略。

## 说明

- 每个 demo 的第一步都是创建沙箱，返回的 `sandbox.id` 形如 `sbx-xxxxxxxx`，后续命令把该值代入 `<SBX>`。
- 所有写操作都会在内置安全事件流里留下记录，可用 `curl -s $BASE/api/events` 随时查看。
- 演示只调用 HTTP API，不会在本机真正拉起隔离沙箱；审批 = 授权执行器按清单启动。
