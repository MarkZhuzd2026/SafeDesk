# Demo 04 · 防护与拒绝路径：不合规输入一律被拦

场景：演示控制面的输入校验与状态机防护——未登录、不合法的 Agent、可疑路径、未知策略、非法状态跳转，全部被拒绝且不落任何数据。这是“安全优先”原则在 API 层的直接体现。

前置：已按 [README](./README.md) 启动控制面并设置 `BASE` 与管理员 `TOKEN`。本 demo 前几步可独立执行，后两步需要先有一个沙箱，可先跑 [Demo 01](./01-readonly-review.md) 前两步创建。

## 0. 未登录访问受保护接口

```bash
curl -s -w '\nHTTP %{http_code}\n' $BASE/api/bootstrap
```

预期输出：

```json
{"error": "请先登录"}
HTTP 401
```

普通用户（手机号 / 微信）登录后也不能审批：

```bash
curl -s -w '\nHTTP %{http_code}\n' -X POST $BASE/api/sandboxes/$SBX/approve \
  -H "Authorization: Bearer $USER_TOKEN"
```

预期 `HTTP 403`，错误为 `仅管理员可以执行此操作`。

## 1. 未知 Agent：只允许 Claude Code / Codex / DSH

```bash
curl -s -w '\nHTTP %{http_code}\n' -X POST $BASE/api/sandboxes \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent":"gpt-freestyle","policyId":"balanced","workspace":"/srv/x"}'
```

预期输出：

```json
{"error": "仅支持 Claude Code、Codex 或 DSH"}
HTTP 400
```

白名单之外的可执行体进不了沙箱——沙箱里跑什么由平台决定，不由调用方决定。

## 2. 相对路径工作区：堵目录穿越

```bash
curl -s -w '\nHTTP %{http_code}\n' -X POST $BASE/api/sandboxes \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent":"codex","policyId":"review","workspace":"../etc/passwd"}'
```

预期输出：

```json
{"error": "工作区必须为绝对路径"}
HTTP 400
```

挂载点必须是绝对路径，防止借相对路径逃逸到沙箱边界之外的目录。

## 3. 未知策略：不能自造权限

```bash
curl -s -w '\nHTTP %{http_code}\n' -X POST $BASE/api/sandboxes \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"agent":"codex","policyId":"root","workspace":"/srv/x"}'
```

预期输出：

```json
{"error": "未知策略"}
HTTP 400
```

策略只能三选一，调用方无法传入自定义权限组合绕过编译器。

## 4. 重复审批：状态机拒绝回跳

先创建一个沙箱并审批（若无现成沙箱）：

```bash
curl -s -X POST $BASE/api/sandboxes \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"guard-test","agent":"codex","policyId":"review","workspace":"/srv/guard"}'
SBX=<上一步返回的 sandbox.id>
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/$SBX/approve
```

再次审批同一个沙箱：

```bash
curl -s -w '\nHTTP %{http_code}\n' -X POST $BASE/api/sandboxes/$SBX/approve \
  -H "Authorization: Bearer $TOKEN"
```

预期输出：

```json
{"error": "沙箱不是待审批状态"}
HTTP 409
```

`running → running` 这种重复放行被拒绝，审批动作不可重放。

## 5. 不存在的沙箱

```bash
curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/sbx-deadbeef/manifest
```

预期输出：

```json
{"error": "未找到沙箱"}
HTTP 404
```

ID 采用 `sbx-` 前缀 + 随机后缀的路由校验，畸形 ID 直接 404，不会进入业务逻辑。

## 6. 重复终止：终结态不可逆

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes/$SBX/terminate   # 第一次终止：成功
curl -s -w '\nHTTP %{http_code}\n' -X POST $BASE/api/sandboxes/$SBX/terminate \
  -H "Authorization: Bearer $TOKEN"
```

预期输出：

```json
{"error": "沙箱已终止"}
HTTP 409
```

状态机是单向的：`pending_approval → running → terminated`，任何方向的回跳都返回 409。

## 本 demo 讲清了什么

- **身份即边界**：未登录 401，普通用户不能审批 403，管理员才能放行。
- **输入即边界**：Agent、路径、策略三类输入全部白名单/格式校验，400 快速失败。
- **状态即边界**：生命周期是单向状态机，409 拒绝一切非法跳转。
- **失败不落数据**：所有被拒请求不产生沙箱记录，可用 `curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/sandboxes` 复核列表未被污染。
