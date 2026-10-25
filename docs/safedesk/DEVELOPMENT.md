# SafeDesk 开发文档 / Developer Guide

面向控制面开发者：模块地图、配置、API 参考、安全模型、测试体系与扩展方法。

For contributors to the SafeDesk control plane: module map, configuration, HTTP API reference, security model, test suites, and extension recipes.

---

## 1. 仓库布局 / Repository layout

仓库以 `wasmerio/wasmer v7.5.0`（基线 tag `v0`）为隔离运行时底座，团队代码集中在：

```
apps/safedesk-control-plane/     # 控制面（团队代码全部在这里）
├── server.py                    # ● 主服务端：Python 标准库实现，零三方依赖
├── server.mjs                   # ○ 备选服务端：Node.js 20+ 同等实现
├── auth.py                      # 登录与会话：手机 OTP / 微信 / 企业微信 / 管理员
├── policy.py                    # 三档策略 + Agent 白名单 + 启动清单编译
├── broker.py                    # 主机侧凭据代理：占位符签发、掩码、白名单
├── launcher.py                  # 隔离进程拉起：wasmer 或 dry-run，信号生命周期
├── proxy.py                     # 每沙箱 egress 代理：SSRF 守卫 + 白名单 + 头注入
├── product.py                   # 工作台聚合：总览、筛选、模板、组织设置
├── audit.py                     # append-only 审计日志 + 保留期清理
├── static/                      # 单页控制台（index.html，零构建）+ 品牌资源
├── data/                        # 运行期数据（见 §4）
├── test/                        # Python 单元/集成/E2E + Node 侧 *.test.mjs
└── src/                         # Node 侧与 *.py 一一对应的模块
docs/safedesk/                   # 产品文档（本目录）
```

> Python（`server.py`）是生产与部署主线，所有新能力先落地 Python 侧；Node（`server.mjs` + `src/`）保持接口对齐。测试命令见 §8。

- The Python server is the production line; the Node server mirrors it for hosts with Node 20+. All team code lives under `apps/safedesk-control-plane/`.

---

## 2. 本地开发环境 / Local setup

```bash
git clone git@github.com:wuyeliang/SafeDesk.git
cd SafeDesk/apps/safedesk-control-plane

# Python 主线（3.9+，纯标准库，无需 pip install）
PORT=8022 HOST=127.0.0.1 python3 server.py

# 或 Node 备选
npm test        # node --test test/*.test.mjs
npm run dev     # node server.mjs
```

浏览器打开 `http://127.0.0.1:8022/`，默认管理员 `admin` / `SafeDesk@Admin`。

常用开发组合：

```bash
# 关闭登录（仅本地调试，真实环境禁止）
SAFEDESK_AUTH=0 PORT=8022 python3 server.py

# 验证码不回显（贴近生产行为，改密等流程必须用 admin 登录）
SAFEDESK_DEMO=0 PORT=8022 python3 server.py

# 数据目录隔离（互不影响的多实例调试）
SAFEDESK_DATA_DIR=/tmp/sd-a PORT=8022 python3 server.py
```

---

## 3. 配置项总表 / Environment variables

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PORT` / `HOST` | `8022` / `0.0.0.0` | 监听地址 |
| `SAFEDESK_DATA_DIR` | `<app>/data` | 全部运行数据的根目录 |
| `SAFEDESK_DATA_FILE` | `$DATA_DIR/sandboxes.json` | 沙箱存储文件（单文件覆盖场景） |
| `SAFEDESK_AUTH` | `1` | `0` 关闭登录并注入 `local-dev` 管理员（测试专用） |
| `SAFEDESK_DEMO` | `1` | 演示模式；`0` 关闭 OTP 回显 |
| `SAFEDESK_OTP_ECHO` | `0` | `1` 时独立于 demo 强制回显验证码 |
| `SAFEDESK_ADMIN_USERNAME` | `admin` | 管理员用户名 |
| `SAFEDESK_ADMIN_PASSWORD` | `SafeDesk@Admin` | **仅在首次创建管理员时生效**，不覆盖已修改的密码 |
| `SAFEDESK_ADMIN_PHONES` | 空 | 逗号分隔的手机号白名单，这些手机号登录即管理员 |
| `SAFEDESK_TLS_CERT` / `SAFEDESK_TLS_KEY` | 空 | 同时设置即切换 HTTPS |
| `SAFEDESK_EGRESS_PROXY_PORT` | `0`（随机） | egress 代理固定端口，调试/审计时可固定 |
| `SAFEDESK_START_TIMEOUT` | `30` | 沙箱启动超时（秒），同时决定 dry-run 占位进程寿命 |

---

## 4. 数据文件布局 / Data files

全部位于 `SAFEDESK_DATA_DIR`：

| 文件 | 内容 | 权限/特性 |
| --- | --- | --- |
| `sandboxes.json` | 沙箱数组（含状态、owner、egressToken、runtime） | 每次生命周期变更整体重写 |
| `settings.json` | 组织设置（merge 默认值后持久化） | 缺省字段自动补齐 |
| `users.json` | 用户与管理员（PBKDF2-SHA256 密码散列，12 万轮） | 管理员首次启动自动播种 |
| `sessions.json` | 会话 token（7 天有效，过期自动清理） | 改密会吊销其他全部会话 |
| `credentials.json` | 凭据明文（仅主机侧） | `0600`；任何 API 不回显 |
| `audit.jsonl` | 审计事件，每行一条 JSON | `0600`，append-only，启动时按保留期清理 |
| `runners/sbx-*.log` | 沙箱进程 stdout/stderr | dry-run / wasmer 统一写盘 |

> **不变式（测试固化）**：`sandboxes.json`、启动清单、API 响应中**绝不出现凭据明文**；只有 `credentials.json` 与 `audit.jsonl` 的详情内容允许存在于磁盘，且均为 `0600`。

---

## 5. 模块地图 / Module map

| 模块 | 关键职责 | 关键不变式 |
| --- | --- | --- |
| `server.py` | 路由、鉴权装饰（`require_user/admin`）、生命周期编排、事件写盘 | `/api/*` 未知路径 404；非 API 路径走静态目录且不可越权读源码 |
| `auth.py` | OTP 签发（60s 限频/5min 有效/5 次容错）、QR 票据、会话、改密 | 改密吊销其他全部会话；默认密码登录强制 `mustChangePassword` |
| `policy.py` | `balanced/review/build` 三策略、`ALLOWED_AGENTS`、`compile_manifest` | 清单只含能力声明与占位符，`exposedValues=False` |
| `broker.py` | 凭据注册/掩码/删除、占位符签发 `{{SD_CRED_<sbx>_<rand>}}` | 占位符不可猜测；`resolve()` 只在 running 状态出货 |
| `launcher.py` | `wasmer` 拉起（缺失时 dry-run `sleep`）、rlimit、SIGSTOP/SIGCONT/SIGTERM | `workspace_allowed` 用 realpath 拦截 `../` 逃逸 |
| `proxy.py` | egress 代理：CONNECT（仅 443）、绝对 URI 转发、SSRF 硬拒绝 | 私网/回环/云元数据（169.254.169.254 等）默认拒绝；暂停即冻结 |
| `product.py` | 总览指标、筛选、模板、设置 merge | riskMix 不计 terminated；pending>0 即 health=attention |
| `audit.py` | jsonl 追加、查询/分页、启动 prune | 损坏行与超期行在启动重写时被丢弃 |

---

## 6. HTTP API 参考 / API reference

鉴权：除标注 `public` 外均需 `Authorization: Bearer <token>`；标注 `admin` 还需管理员角色。
错误统一为 `{"error": "中文原因"}` + 语义化状态码（400 参数、401 未登录、403 越权、404 不存在、409 状态冲突、502 上游失败）。

### 认证（public）

| 方法/路径 | 说明 |
| --- | --- |
| `GET /api/auth/config` | 可用登录方式、管理员用户名、密码最小长度 |
| `POST /api/auth/phone/send` `{phone}` | 发码；60s 内重复 → 400；demo 模式回显 `demoCode` |
| `POST /api/auth/phone/verify` `{phone, token}` | 验码成功 → `{token, expiresAt, user}` |
| `POST /api/auth/wechat|wecom/start` | → `{ticket, expiresIn}` |
| `GET /api/auth/wechat|wecom/poll?ticket=` | `pending` / `confirmed(+token)` / `expired`；confirmed 票据一次性消费 |
| `POST /api/auth/wechat|wecom/confirm` `{ticket}` | 手机端确认扫码 |
| `POST /api/auth/admin/login` `{username, password}` | 管理员登录 |

### 会话

| 方法/路径 | 说明 |
| --- | --- |
| `GET /api/auth/me` | 当前用户（含 `mustChangePassword` / `canChangePassword`） |
| `POST /api/auth/logout` | 吊销当前 token |
| `POST /api/auth/password` `{currentPassword, newPassword}` | **仅带密码散列的管理员**；改密吊销其他全部会话 |

### 工作台数据

| 方法/路径 | 说明 |
| --- | --- |
| `GET /api/bootstrap` | 登录后首屏聚合：user/overview/catalog/templates/settings/policies/agents/sandboxes/securityEvents（非管理员 events 为空） |
| `GET /api/overview` | 指标卡：total/各状态计数/riskMix/health/activeUsers |
| `GET /api/catalog` | 策略、Agent、凭据能力、MCP 服务清单 |
| `GET /api/templates` | 任务模板（≥3 条） |
| `GET /api/settings` / `POST /api/settings` (`admin`) | 组织设置读写（POST 整体 merge 持久化） |
| `GET /api/events` (`admin`) | 实时事件（内存窗口 40 条），支持 `q/level/action` 过滤 |
| `GET /api/events?history=1` (`admin`) | 历史审计：`q/level/action/since/limit/offset`，最新在前 |

### 沙箱

| 方法/路径 | 说明 |
| --- | --- |
| `POST /api/sandboxes` | 创建 → 201 `{sandbox, manifest}`；校验策略/Agent/绝对路径/根目录白名单/并发配额（非管理员超限 409） |
| `GET /api/sandboxes` | 列表；普通用户只见自有，`q/status/agent/policyId` 过滤 |
| `GET /api/sandboxes/{id}` | 详情 `{sandbox, manifest}`；越权访问 404 |
| `GET /api/sandboxes/{id}/manifest` | 编译后启动清单 |
| `GET /api/sandboxes/{id}/activity` | 与该沙箱相关的安全事件 |
| `POST /api/sandboxes/{id}/approve` (`admin`) | 待审批 → running；注册 egress、拉起进程 |
| `POST /api/sandboxes/{id}/reject` (`admin`) | 待审批 → rejected，`{reason}` 可选（默认"不符合安全策略"） |
| `POST /api/sandboxes/{id}/pause|resume|terminate` | 所有者或管理员；terminate 注销 egress 凭据 |

### 凭据（admin）

| 方法/路径 | 说明 |
| --- | --- |
| `GET /api/credentials` | 掩码列表（`{"name","allowedHosts","masked"}`） |
| `POST /api/credentials` | 注册/更新 `{name, value, allowedHosts[]}`；响应不含明文 |
| `POST /api/credentials/delete` | `{name}` 删除 |

---

## 7. Egress 代理协议 / Egress proxy

审批（非 `review` 策略）时控制面启动一次进程内代理（`serve()`），并为沙箱注册 `sandboxId : egressToken`。

- **鉴权**：`Proxy-Authorization: Basic base64(sandboxId:token)`；错误 → 407；
- **HTTPS**：仅允许 `CONNECT host:443`，隧道不解密；
- **HTTP**：绝对 URI 转发，透代前剥离 hop-by-hop 头并按凭据白名单**替换占位符为真实值**；占位符送往未授权主机 → 403；
- **SSRF 硬拒绝**（先于白名单判定）：回环、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`100.64/10`、`localhost`、`metadata.*.internal`、`169.254.169.254`、`100.100.100.200`，以及解析到上述地址的域名；
- **冻结与失效**：沙箱暂停 → 一律 403；终止/注销 → 一律 407；
- **健康检查**：`GET /healthz` 匿名可达。

---

## 8. 测试体系 / Test suites

```bash
cd apps/safedesk-control-plane

# Python 全部（单元 + 集成 + 端到端，当前 219 个）
python3 -m unittest discover -s test -p "test_*.py" -v

# 只跑端到端（20 个真实服务器场景）
python3 -m unittest test.test_e2e -v

# Node 侧
node --test test/*.test.mjs
```

| 层 | 文件 | 方式 |
| --- | --- | --- |
| 单元 | `test_auth.py` `test_auth_store.py` `test_audit.py` `test_broker.py` `test_launcher.py` `test_policy.py`(在 control_plane 内) `test_product.py` `test_proxy.py` | 直接导入模块 |
| 集成 | `test_control_plane.py` | `SAFEDESK_AUTH=0` 起真实 server，走 HTTP |
| 端到端 | `test_e2e.py` | `SAFEDESK_AUTH=1` 起真实 server 与 egress 代理，20 个业务场景（E2E-01..20，见文件头注释） |

**写新 E2E**：继承 `E2EBase`，每个类独占一台服务器与数据目录；钩子：`extra_env()`（追加环境变量）、`prepare_data_dir()`（启动前预置数据）、`respawn()`（重启同一数据目录）。管理员密码在每个类里都是默认值 `SafeDesk@Admin`。

---

## 9. 安全模型与不变式 / Security invariants

1. 密钥永不进沙箱：环境变量只含 `{{SD_CRED_...}}` 占位符；注入发生在主机侧代理。
2. 默认拒绝：未声明白名单的主机一律 403；私网/元数据一律 403（无视白名单）。
3. 最小权限生命周期：终止即吊销 egress token（407）；暂停即冻结（403）。
4. 数据隔离：`visible_sandboxes` + `can_access` 双闸门，跨用户一律 404。
5. 审计只增不删：运行期 append-only；启动期 prune 是唯一删除通道。
6. 认证防爆破：OTP 5 次容错、60s 限频、5min 过期；改密吊销全量会话。

以上不变式均由测试固化（`grep -n "不得\|never\|绝不" test/test_e2e.py`）。

---

## 10. 扩展指南 / How to extend

**新增一档策略**（如 `locked-down`）：
1. `policy.py` → `POLICIES` 加一条（workspaceMode/networkMode/approval/资源上限）；
2. `product.py` → `risk_for()` 与 `catalog().suitableFor` 补文案；
3. 测试：仿 `CompileManifestTest` 加映射断言 + E2E 建箱断言。

**新增一种 Agent**：
1. `policy.py` → `ALLOWED_AGENTS` 加 `{label, command}`；
2. 创建接口自动放行；E2E-12 类筛选用例可顺带覆盖。

**新增一个 API**：
1. `server.py` 对应 `do_GET/do_POST` 分支，先做 `require_user/require_admin`；
2. 用 `send_json` 回包；参数错误抛 `ValueError` → 400；
3. 在 `test_e2e.py` 加一个继承 `E2EBase` 的类覆盖正/反路径。

**接入真实短信/微信**：`auth.py` 的 `send_phone_otp` / `start_wechat` 是替换点；保持返回结构不变，前端与全部测试无需改动（测试依赖 demo 回显，不受影响）。

---

## 11. 提交规范 / Contribution rules

- 先读仓库根 `AGENTS.md` 与 `docs/CONTRIBUTING.md`；提交信息用 Conventional Commits（如 `feat(safedesk): ...`）。
- 基线 `v0` 之后的团队改动走 PR；AI 代理提交必须在 message 中声明代理身份，责任归属人类用户。
- 合并前硬性门槛：`python3 -m unittest discover -s test -p "test_*.py"` 全绿；改动 Node 侧则 `node --test test/*.test.mjs` 同样全绿。

---

相关文档：[用户手册](USER-GUIDE.md) · [架构设计](ARCHITECTURE.md) · [运维手册](RUNBOOK.md) · [部署手册](DEPLOY-UBUNTU.md) · [需求基线](REQUIREMENTS-100.md)
