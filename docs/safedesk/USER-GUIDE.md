# SafeDesk 用户操作手册 / User Guide

面向控制台使用者：普通研发用户与管理员。无需任何命令行知识即可完成全部操作。

For console users (regular users and admins). Every task below is done in the browser — no command line required.

---

## 1. 产品与角色 / Product & roles

SafeDesk 让 Claude Code、Codex、DSH 等 Agent 在隔离沙箱里工作。你只需回答三个问题：**谁来跑、能碰哪里、要哪些能力**——密钥永远不会进入沙箱。

| 角色 | 能做什么 |
| --- | --- |
| 普通用户（手机号 / 微信 / 企业微信登录） | 创建沙箱、查看自己的沙箱、暂停/恢复/终止自己的沙箱 |
| 管理员 | 普通用户全部能力 + 审批/拒绝任意沙箱 + 查看全部沙箱与安全事件 + 管理凭据 + 修改组织设置 |

- Regular users manage only their own sandboxes; approvals, credential management, audit events, and org settings are admin-only.

---

## 2. 访问与登录 / Access & sign-in

打开控制台地址（开发环境示例，自签证书请选择"继续访问"）：

- https://218.11.5.249:10648/
- https://111.62.156.213:10645/

四种登录方式：

| 方式 | 步骤 |
| --- | --- |
| 手机号验证码 | 输入 11 位手机号 → 获取验证码 → 60 秒内只能发一次 → 输入 6 位验证码登录（验证码 5 分钟有效，错 5 次作废） |
| 微信扫码 | 点"微信登录"生成二维码 → 用手机微信扫码 → 页面自动确认进入 |
| 企业微信扫码 | 同微信扫码流程，身份记录为企业微信成员 |
| 管理员账户 | 输入用户名与密码，默认 `admin` / `SafeDesk@Admin` |

> **演示模式**：当前环境开启了验证码回显，获取手机验证码后页面会直接显示 6 位数字，方便没有短信网关时体验。

### 首次登录必须改密码（管理员）

使用默认密码登录管理员账户后，会**强制弹出改密窗口**，完成前无法操作控制台。规则：

- 新密码至少 8 位，不能含空格，不能等于默认密码，不能与当前密码相同；
- 改密成功后**其他所有已登录会话立即失效**（包括其他人的会话），仅当前窗口保持登录；
- 服务重启不会恢复默认密码。

- Admins signing in with the default password are forced to change it; other sessions are revoked immediately, and restarts never roll the password back.

---

## 3. 控制台总览 / Overview

登录后进入工作台首页，包含：

- **指标卡**：沙箱总数、运行中、待审批、已暂停、已拒绝、已终止；
- **健康状态**：有待审批沙箱时显示"需要关注"，清空后恢复"健康"；
- **风险分布**：按低/中/高风险统计活跃沙箱（已终止不计入）;
- **安全事件流**（仅管理员可见）：凭据代签、外联拦截、审批、终止等；
- 普通用户的总览只统计**自己名下**的沙箱。

- The overview shows counters per sandbox state, a risk mix (terminated sandboxes excluded), and a security event stream that is visible to admins only.

---

## 4. 创建沙箱 / Create a sandbox

点"新建沙箱"，逐项填写：

| 字段 | 说明 | 约束 |
| --- | --- | --- |
| 名称 | 便于识别的任务名 | 特殊字符自动替换为 `-`，最长 48 字符，留空自动命名 `agent-<类型>` |
| Agent | Claude Code / Codex / DSH 三选一 | 必填 |
| 策略 | 见下方三档策略 | 必填 |
| 工作区 | 项目在本机的**绝对路径** | 相对路径会被拒绝；管理员配置了根目录白名单时必须在白名单内 |
| 用途 | 一句话说明，会进入审批与审计 | 最长 160 字 |
| 凭据能力 | 勾选需要的凭据（如 `github-read`） | **只需勾选名称，永远不要填密钥本身**，最多 8 项 |
| MCP 服务 | 勾选需要的服务器（如 `github`、`docs`） | 最多 12 项 |

三档策略：

| 策略 | 工作区 | 网络 | 适用 |
| --- | --- | --- | --- |
| 标准研发 `balanced` | 读写 | 仅经凭据代理访问白名单服务 | 日常开发、改 Issue |
| 只读审阅 `review` | 只读 | **完全断网** | 安全审阅、依赖检查 |
| 受限构建 `build` | 临时目录 | 白名单 | CI 构建、依赖安装 |

也可以使用**任务模板**一键带入（依赖安全审阅 / 功能分支研发 / 夜间受限构建），创建后可再修改。创建后沙箱进入**待审批**状态，可点开查看编译后的启动清单（只含能力声明，不含任何密钥）。

- Creating a sandbox means picking an agent, one of three policies, an absolute workspace path, and the credential/MCP capabilities you need — never the secrets themselves. New sandboxes wait for admin approval.

---

## 5. 沙箱生命周期 / Lifecycle

```
创建 → 待审批 ─审批→ 运行中 ⇄ 已暂停 ─终止→ 已终止
            └─拒绝→ 已拒绝（终态）
```

| 动作 | 谁能做 | 结果 |
| --- | --- | --- |
| 审批 | 仅管理员 | 拉起隔离进程，签发短期外联凭据，记录审批事件；重复审批返回冲突 |
| 拒绝 | 仅管理员 | 需填写原因（默认"不符合安全策略"），进入终态，产生拦截级安全事件 |
| 暂停 | 沙箱所有者或管理员 | 进程冻结（SIGSTOP），外联与凭据注入同时冻结 |
| 恢复 | 沙箱所有者或管理员 | 进程与外联恢复 |
| 终止 | 沙箱所有者或管理员 | 进程结束，**egress 凭据立即失效**，状态置为已终止（终态） |

- Approve/reject is admin-only; owners can pause, resume, and terminate their own sandboxes. Termination instantly revokes the sandbox's egress credential.

---

## 6. 查询与管理 / Search, filter, manifest

- **搜索**：按名称、ID、工作区、用途、所有者关键字模糊匹配；
- **筛选**：可按状态 / Agent / 策略组合过滤；
- **启动清单**：点沙箱卡片可查看编译后的 `SandboxLaunchPlan`，确认文件系统模式、网络模式、凭据占位符（形如 `{{SD_CRED_xxx}}`，无法反推真实值）；
- **活动**：查看与该沙箱相关的安全事件。

---

## 7. 安全事件与审计（管理员）/ Audit (admin)

- **实时事件流**：工作台直接展示最近 40 条；
- **按级别筛选**：拦截（block）/ 放行（allow）/ 信息（info）；
- **历史审计**：支持关键字、级别、动作、时间起点过滤与分页；事件以 append-only 方式落盘 `audit.jsonl`，默认保留 30 天，过期数据在服务启动时自动清理。

- Admins get a capped live event stream plus a paginated, filterable audit history; events older than the retention window are pruned at startup.

---

## 8. 凭据管理（管理员）/ Credentials (admin)

在工作台"凭据"区：

1. 填写**凭据名称**（如 `github-read`）、**真实值**、**允许送达的目的主机**（必填，支持 `*.example.com` 通配）；
2. 列表只显示掩码（如 `ghp_****`），任何接口都不会回显明文；
3. 删除凭据后，新审批的沙箱不再获得对应能力；已运行沙箱不受影响，直到终止。

用户侧只看到凭据**名称**可勾选；注入发生在主机侧出站代理，沙箱进程从头到尾拿不到真实值。

- Admins register credentials with a destination allowlist (wildcards allowed). The console only shows masked values; injection happens host-side and never inside the sandbox.

---

## 9. 组织设置（管理员）/ Org settings (admin)

| 设置 | 说明 |
| --- | --- |
| 组织名称 | 工作台标题与审计文案 |
| 并发上限 `maxConcurrent` | 每个普通用户同时存活的（待审批+运行+暂停）沙箱数，超出创建返回冲突；管理员不受限 |
| 会话时长 `sessionTimeoutMin` | 登录会话展示用超时分钟数 |
| 公告 `notice` | 登录页/工作台提示语 |
| 工作区根目录 `workspaceRoots` | 沙箱工作区必须落在其中（`../` 逃逸会被拦截）；留空表示只要求绝对路径 |

设置修改立即生效并落盘，重启后不丢失。

---

## 10. 常见问题 / FAQ

**Q：登录手机收不到验证码？**
演示环境验证码会直接显示在页面上；生产环境需要接入短信网关（见开发文档 `SAFEDESK_OTP_ECHO`）。

**Q：创建沙箱提示"工作区不在允许的根目录内"？**
管理员在组织设置里配置了 `workspaceRoots`，把工作区放到白名单目录下，或联系管理员调整。

**Q：创建沙箱提示"已达到并发沙箱上限"？**
你有太多存活沙箱（待审批/运行/暂停都计数）。终止不再需要的沙箱后即可继续创建。

**Q：管理员改密后我被踢下线了？**
这是设计行为：管理员改密会吊销全部会话，重新登录即可；管理员自己也不会再能用旧密码登录。

**Q：沙箱里为什么要我填 API Key？**
不需要也不应该。SafeDesk 的设计就是密钥不进沙箱：勾选凭据能力即可，代签由主机完成。若某个流程要求你粘贴密钥，请拒绝并联系管理员。

**Q：终止沙箱后还能恢复吗？**
不能，终止是终态。短期会话凭据也随之失效，请重新创建沙箱。

---

相关文档：[开发文档](DEVELOPMENT.md) · [架构设计](ARCHITECTURE.md) · [运维手册](RUNBOOK.md) · [部署手册](DEPLOY-UBUNTU.md)
