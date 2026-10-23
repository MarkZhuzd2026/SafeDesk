# SafeDesk 运行说明

## 仓库基线

- 开源底座：`wasmerio/wasmer` `v7.5.0`
- 团队开发前基线 tag：`v0`
- 团队代码从 `v0` 之后以 Pull Request 提交

## 开发机

- SSH：`ssh -p 10649 root@218.11.5.249`
- 公网入口：`http://218.11.5.249:10648/` 与 `http://111.62.156.213:10645/`
- 内网端口：`8022`

## 启动控制面

```bash
cd /opt/safedesk/apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 node server.mjs
```

健康检查：

```bash
curl -I http://127.0.0.1:8022/
curl -s http://127.0.0.1:8022/api/bootstrap
```

## 演示路径

1. 打开控制台，选择 Claude Code / Codex / DSH。
2. 选择策略：标准研发、只读审阅或受限构建。
3. 填写项目绝对路径，勾选凭据能力和 MCP 服务，不要填写任何密钥。
4. 创建待审批沙箱，查看编译后的启动清单。
5. 审批启动后，安全事件会记录凭据代签与外联拦截。
6. 终止沙箱，确认状态变为 `terminated`。
