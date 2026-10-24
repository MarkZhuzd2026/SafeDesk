# SafeDesk 运行说明 / Runbook

## 仓库基线 / Repository baseline

- 团队开发前基线 tag：`v0`
- 团队代码从 `v0` 之后以 Pull Request 提交
- 底层隔离运行时与上游来源见 [RUNTIME.md](RUNTIME.md)

- Baseline tag before team code: `v0`
- Team changes land after `v0` via pull requests
- Isolation runtime and upstream source: [RUNTIME.md](RUNTIME.md)

## 开发机 / Dev host

- SSH：`ssh -p 10649 root@218.11.5.249`
- 公网入口 / public endpoints：`https://218.11.5.249:10648/` 与 `https://111.62.156.213:10645/`（自签证书 / self-signed TLS）
- 内网端口 / internal port：`8022`
- 登录 / login：手机号验证码、微信扫码、管理员账户
- 默认管理员 / default admin：`admin` / `SafeDesk@Admin`（登录后可在组织设置中修改密码；改密后重启不会恢复默认值）

## 启动控制面 / Start the control plane

```bash
cd /opt/safedesk/apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 python3 server.py
```

健康检查 / health checks：

```bash
curl -I http://127.0.0.1:8022/
curl -s http://127.0.0.1:8022/api/auth/config
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8022/api/bootstrap
```

未登录访问 `/api/bootstrap` 应返回 `401`。

Unauthenticated `/api/bootstrap` must return `401`.

若已配置证书，可用 HTTPS：

```bash
SAFEDESK_TLS_CERT=/etc/safedesk/tls/cert.pem \
SAFEDESK_TLS_KEY=/etc/safedesk/tls/key.pem \
PORT=8443 HOST=0.0.0.0 python3 server.py
```

## 演示路径 / Demo path

1. 打开控制台，使用手机号、微信或管理员账户登录。
2. 查看总览指标，选择 Claude Code / Codex / DSH，或套用任务模板。
3. 选择策略：标准研发、只读审阅或受限构建。
4. 填写项目绝对路径，勾选凭据能力和 MCP 服务，不要填写任何密钥。
5. 创建待审批沙箱，查看编译后的启动清单。
6. 管理员审批启动后，安全事件会记录凭据代签与外联拦截。
7. 终止沙箱，确认状态变为 `terminated`。
