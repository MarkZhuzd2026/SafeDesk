# SafeDesk 需求清单（100 项）

> 来源：基于《市场调研报告》第 4.3 节三阶段落地路线拆解，2026-10-24。
> 编号规则：`REQ-<模块>-<序号>`。模块：EX=执行器（Isolation Runtime）、BR=凭据代理（Host Credential Broker）、NW=网络代理（Egress Proxy）、GW=MCP 网关、AU=审计、PL=策略、SN=快照、TE=遥测、SC=安全与合规。
> 状态图例：⬜ 未开始 / 🚧 进行中 / ✅ 完成。

## Phase 1（P0）执行侧闭环——把设计变真

### EX 隔离执行器（Isolation Runtime，12 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-EX-001 | LaunchPlan → wasmer 命令组装 | 编译出的 `SandboxLaunchPlan` 可一一生成 `wasmer run` argv，`--volume/--env` 与白名单参数齐全且无注入面 | ✅ |
| REQ-EX-002 | 三策略收口映射 | balanced=rw 工作区+brokered 网络；review=ro+断网；build=ephemeral+allowlist，单元测试断言三个字 | ✅ |
| REQ-EX-003 | 资源限额强制执行 | `--max-cpu / --max-memory-mb` 映射到进程 rlimit（CPU、AS），超限沙箱终止并记录事件 | ✅ |
| REQ-EX-004 | dry-run 降级模式 | 无 wasmer 二进制时使用占位进程跑通完整生命周期，状态机与事件流一致 | ✅ |
| REQ-EX-005 | 审批后真实拉起 | approve 动作真正启动执行器，失败时沙箱进入 error 并保留审批链 | ✅ |
| REQ-EX-006 | pause/resume 信号语义 | pause=SIGSTOP、resume=SIGCONT、terminate=SIGTERM（超时后 SIGKILL），对 wasmer 与 dry-run 均成立 | ✅ |
| REQ-EX-007 | 孤儿进程清理 | 控制面重启后扫描 PID 表，标记已死亡沙箱为 `terminated(reason=orphan)` | ✅ |
| REQ-EX-008 | 工作区白名单校验 | 工作区必须落在组织配置的白名单根目录内，穿越攻击被 400 | ✅ |
| REQ-EX-009 | 并发节流 | 组织 `maxConcurrent` 对真实执行器生效，超限返回 409 | ✅ |
| REQ-EX-010 | 启动日志落盘 | 每个沙箱 stdout/stderr 写入 data/runners/，按沙箱 id 命名、环回截断 | ✅ |
| REQ-EX-011 | 沙箱健康检查 | `/api/sandboxes/{id}/activity` 能报告进程存活/退出码/资源占用 | ✅ |
| REQ-EX-012 | 启动超时 | 拉起超 N 秒未完成视为失败，自动终止并产生 block 事件 | 🚧 |

### BR 凭据代理（Host Credential Broker，13 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-BR-001 | 凭据注册（admin） | `/api/credentials` POST 可注册 name/value/allowedHosts，仅管理员 | ✅ |
| REQ-BR-002 | 值只写不读 | 任何 GET 返回均只含掩码（首 4 + `****`），原始值不出 API | ✅ |
| REQ-BR-003 | 沙箱占位符颁发 | 批准时为沙箱颁发 `{{SD_CRED_*}}` 占位符并写入 manifest 环境 | ✅ |
| REQ-BR-004 | 目的地白名单绑定 | resolve 只对该凭据 `allowedHosts` 中的主机返回真实值 | ✅ |
| REQ-BR-005 | 主机侧代签解析 | 由网络代理调用 resolve 注入 Authorization 头，沙箱进程不可见 | ✅ |
| REQ-BR-006 | 冻结语义 | pause 期间 resolve 一律 403；resume 恢复 | ✅ |
| REQ-BR-007 | 终止失效 | terminate 后立即撤销该沙箱所有占位符（映射置灰） | ✅ |
| REQ-BR-008 | 凭据操作审计 | 注册/update/颁发/代签/拒绝均产生安全事件（含 actor） | ✅ |
| REQ-BR-009 | 权限模型 | 注册/审计仅 admin；普通用户仅能引用能力名 | ✅ |
| REQ-BR-010 | 本地落盘加密/权限 | data/credentials.json 0600；密钥环可用（后续接 KMS） | ✅ |
| REQ-BR-011 | 每个沙箱独立 token | 占位符含 sandbox 前缀 + 随机性的抗推测 token，不复用 | ✅ |
| REQ-BR-012 | 凭据轮换 | 支持 update 后新值生效，旧代签失效 | ✅ |
| REQ-BR-013 | 凭据配额 | 每沙箱最多 8 条凭据，超限 400 | ✅ |

### NW 网络代理（Egress Proxy，15 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-NW-001 | 域名/IP 白名单放行 | 命中沙箱 allowlist 的目标放行，否则 fail closed 拒绝 | ✅ |
| REQ-NW-002 | 私网/回环/link-local 硬禁 | RFC1918、127.0.0.0/8、link-local、0.0.0.0/8 请求一律拒绝 | ✅ |
| REQ-NW-003 | 云元数据硬禁 | 169.254.169.254、fd00:ec2::254 等元数据端点拒绝 | ✅ |
| REQ-NW-004 | DNS 防重绑定 | 先解析目标域名核对 IP 归属再放行，拒绝解析到私网的域名 | ✅ |
| REQ-NW-005 | HTTP 明文代理 | 绝对 URI 请求经 `http.client` 转发、透明转发响应 | ✅ |
| REQ-NW-006 | CONNECT 隧道限制 | `CONNECT` 仅允许白名单主机:443，其余 403；隧道流量不解析但也审计 | ✅ |
| REQ-NW-007 | 每沙箱鉴权 | Proxy-Authorization `sbx:<sandbox_id>:<token>` 绑定策略，匿名拒绝 | ✅ |
| REQ-NW-008 | allow/block 决策事件 | 每次外联产生 `网络决策` 事件，包含目标主机与允许依据 | ✅ |
| REQ-NW-009 | 沙箱暂停即冻结 | paused 状态下同样拒绝其外联（含已建立隧道后续请求） | ✅ |
| REQ-NW-010 | 动态更新 allowlist | 管理员在沙箱详情侧可补充允许域,立即生效且无重启 | ⬜ |
| REQ-NW-011 | 速率限制 | 单沙箱 QPS 上限，超出拒绝且写入事件 | ⬜ |
| REQ-NW-012 | 响应大小上限 | 单笔响应超过阈值截断或拒绝，防大文件外泄 | ⬜ |
| REQ-NW-013 | 健康探针 | `/healthz` 返回代理存活与版本 | ✅ |
| REQ-NW-014 | 错误语义统一 | 所有拒绝统一 403 + JSON `{"error","reason","ref"}` | ✅ |
| REQ-NW-015 | 与 launcher 联动 | 启动时下发 `HTTP_PROXY/HTTPS_PROXY` 指向本代理，禁直接出网 | ✅ |

## Phase 2（P1）企业化补强

### GW MCP 网关（10 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-GW-001 | MCP 服务注册（admin） | 注册 name/endpoint/verifyHash，入白名单 | ⬜ |
| REQ-GW-002 | streamable-http 路由 | 沙箱 → 网关 → MCP 服务透明转发 | ⬜ |
| REQ-GW-003 | 每沙箱绑定 | 沙箱只能访问其 manifest `allowedServers` 中的服务 | ⬜ |
| REQ-GW-004 | 凭据绑定 | 每个 MCP 服务可绑定代签凭据，沙箱内仍以占位符引用 | ⬜ |
| REQ-GW-005 | 工具白名单过滤 | 可按服务声明允许的工具列表，未列工具拒绝 | ⬜ |
| REQ-GW-006 | 转发审计 | 每次转发产生事件，含服务/工具/沙箱 | ⬜ |
| REQ-GW-007 | 调用超时 | 单次 RPC 超时取消并记录 | ⬜ |
| REQ-GW-008 | 健康检查 | 网关对外暴露 `/healthz` 显示注册服务可达性 | ⬜ |
| REQ-GW-009 | 只从能力目录选择 | 前端创建沙箱时 MCP 列表只允许白名单内选择，禁手写 URL | ⬜ |
| REQ-GW-010 | 版本/pin | MCP 服务可声明版本或内容 hash，变更需管理员审核 | ⬜ |

### AU 审计与事件（12 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-AU-001 | append-only 落盘 | 每个安全事件追加 data/audit.jsonl，不因重启丢失 | ✅ |
| REQ-AU-002 | 保留期裁剪 | 按 `retainAuditDays` 裁剪过期事件 | ✅ |
| REQ-AU-003 | 分页查询 | `/api/events?limit&offset&since&q` 分页读取磁盘历史 | ✅ |
| REQ-AU-004 | 导出 | 可导出 JSON/CSV 一次拉全 | ⬜ |
| REQ-AU-005 | webhook 外送 | 关键事件 POST 至配置的 webhook URL,HMAC-SHA256 签名 | ⬜ |
| REQ-AU-006 | OTel 导出 | OTLP HTTP/JSON 端点导出事件，符合语义约定 | ⬜ |
| REQ-AU-007 | 级别去重去噪 | 连续相同 block 事件可聚合为 N 次汇总并以 `aggregated:true` 标注 | ⬜ |
| REQ-AU-008 | 哈希链完整性 | 每条事件带前一条 hash，重启后校验链完整性 | ⬜ |
| REQ-AU-009 | 时间戳规范 | 所有事件 ISO8601 UTC，毫秒精度，一致时区 | ⬜ |
| REQ-AU-010 | 审计自审计 | 任何删除/裁剪审计文件的操作也写入审计 | ⬜ |
| REQ-AU-011 | 审计摘要 | `/api/overview` 增加 24h/7d 的 allow/block 趋势 | ⬜ |
| REQ-AU-012 | 导出通讯加密 | webhook 与 OTel 出口强制 TLS，拒绝明文 | ⬜ |

### PL 策略引擎增强（8 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-PL-001 | 自定义策略 | admin 新增策略并保存,沙箱可选 | ⬜ |
| REQ-PL-002 | 策略版本 | 每次修改生成新版本，旧沙箱保持原版本 | ⬜ |
| REQ-PL-003 | 用户级配额 | 每用户 CPU/内存/并发上限与组织级叠加 | ⬜ |
| REQ-PL-004 | 工作区根白名单 | admin 配置允许的工作区根目录清单 | ✅ |
| REQ-PL-005 | 包白名单 | manifest `runtime.packages` 只允许组织登记的包 | ⬜ |
| REQ-PL-006 | 策略预演（dry-run） | POST 沙箱前先返回仿真启动计划 + 风险提示 | ⬜ |
| REQ-PL-007 | 策略变更审计 | 每次修改策略/配额/目录写入审计 | ⬜ |
| REQ-PL-008 | 策略继承/模板 | 可从内置 balanced/review/build 派生 | ⬜ |

## Phase 3（P2）体验对标

### SN 快照与生命周期（8 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-SN-001 | 快照 | 运行中沙箱可生成内存+磁盘快照 | ⬜ |
| REQ-SN-002 | 恢复 | 新沙箱可从快照冷启动，启动时间目标 <2s | ⬜ |
| REQ-SN-003 | 分叉 | 一快照可分叉多实例,彼此隔离 | ⬜ |
| REQ-SN-004 | AutoResume | 访问已暂停沙箱接口时自动唤醒 | ⬜ |
| REQ-SN-005 | 快照配额 | 每沙箱/组织快照数量与容量配额 | ⬜ |
| REQ-SN-006 | 快照 GC | 过期快照自动回收并记录事件 | ⬜ |
| REQ-SN-007 | 沙箱跨用户隔离 | 非拥有用户不可见/不可拉取快照 | ⬜ |
| REQ-SN-008 | 快照事件 | 快照/恢复/分叉/回收均写审计 | ⬜ |

### TE 代理级遥测（12 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-TE-001 | agent 级 span | 每次工具调用（文件、bash、网络）产生结构化 span | ⬜ |
| REQ-TE-002 | 网络决策 span | 代理每次 allow/deny 以 span 形式进 OTel | ⬜ |
| REQ-TE-003 | 审批链路 span | 创建→审批→启动→动作→终止全链路 trace | ⬜ |
| REQ-TE-004 | SIEM 集成 | webhook/OTel 到达常见 SIEM(Splunk/Elastic) 字段兼容 | ⬜ |
| REQ-TE-005 | 指标 dashboard 扩展 | 控制台展示资源使用曲线与外联趋势 | ⬜ |
| REQ-TE-006 | 会话回放元数据 | 会话节面为 WEBM 或 JSON replay 供事后查看 | ⬜ |
| REQ-TE-007 | 事件摘要 API | `/api/reports/daily` 返回当日关键安全摘要 | ⬜ |
| REQ-TE-008 | 语义约定遵守 | span 名称与属性名遵循 OpenTelemetry GenAI 约定 | ⬜ |
| REQ-TE-009 | 采样 | 高频事件可配置采样率 | ⬜ |
| REQ-TE-010 | 脱敏 | span/事件中密钥一律掩码,触发关键词清单过滤 | ⬜ |
| REQ-TE-011 | 事件保留期 | 遥测数据按 retainAuditDays 保留 | ⬜ |
| REQ-TE-012 | 告警 | allow/block 阈值触发后可推送 admin 通知(邮件/webhook) | ⬜ |

## Phase 4（P3）安全与合规（10 项）

| ID | 需求 | 验收标准 | 状态 |
| --- | --- | --- | --- |
| REQ-SC-001 | 安全模型文档 | SECURITY-MODEL.md：信任边界、担保/不担保清单 | ⬜ |
| REQ-SC-002 | 威胁模型文档 | THREAT-MODEL.md：已识别威胁 + 缓解措施映射到 REQ ID | ⬜ |
| REQ-SC-003 | 渗透测试计划 | 文档化测试范围、方法、接收准则 | ⬜ |
| REQ-SC-004 | SBOM | 构建产物生成 CycloneDX SBOM | ⬜ |
| REQ-SC-005 | 依赖扫描 CI | CI 运行依赖扫描，高危阻塞合并 | ⬜ |
| REQ-SC-006 | KMS 对接 | 凭据与 CA 可接外置 KMS(文件/Vault/AWS KMS) | ⬜ |
| REQ-SC-007 | 合规映射表 | SOC 2/T2 映射表:每个控制项 → REQ/文档 | ⬜ |
| REQ-SC-008 | 备份与恢复 | data 目录 -完整备份,灾难恢复文档 + 恢复演练 | ⬜ |
| REQ-SC-009 | 多节点规划 | 控制面支持横向扩展/节点分工的设计文档 | ⬜ |
| REQ-SC-010 | 中立部署文档 | 为私有云/本地化/公网三类部署写运维手册 | ⬜ |

---

合计：100 项（P0=40、P1=30、P2=20、P3=10）。本轮已落地 Phase 1 执行侧核心：EX×11、BR×13、NW×12、AU×3、PL×1 共 40 项带测试闭环（Node 191 + Python 199 全绿）；其余按状态持续追踪。
