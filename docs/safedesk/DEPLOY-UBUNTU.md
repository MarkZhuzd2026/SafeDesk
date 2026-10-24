# SafeDesk 控制面部署手册（Ubuntu 24.04 / 25.05）

> 适用系统：Ubuntu 24.04 LTS（Noble）、Ubuntu 25.04 / 25.05（Plucky）及以上 amd64 / arm64。
> 两条部署路线任选其一：**A. Python 零依赖**（仅标准库，受限主机首选）；**B. Node.js 22**（Node 20 亦可）。
> 本手册命令均可逐条复制执行，不含任何函数封装。文中 `VERSION-SPECIFIC...` 提示处按系统版本二选一。

## 1. 系统信息速览

| 项目 | Ubuntu 24.04 LTS | Ubuntu 25.05 |
| --- | --- | --- |
| 内置 Python | 3.12 | 3.13 |
| 推荐部署方式 | Python 零依赖 或 Node 22 | Python 零依赖 或 Node 22 |
| systemd | 252+ | 255+ |
| curl / openssl | 预装 | 预装 |

默认约定：安装根目录 `/opt/safedesk`，服务端口 `8022`，数据目录 `/opt/safedesk/apps/safedesk-control-plane/data`。

## 2. 准备系统

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y git curl openssl ufw
```

创建专用运行用户（不授予 sudo）：

```bash
sudo useradd --system --home /opt/safedesk --shell /usr/sbin/nologin safedesk || true
```

## 3. 获取代码

从 GitHub 拉取（私有仓库需先配好访问凭据）：

```bash
sudo git clone --depth 1 --branch main https://github.com/wuyeliang/SafeDesk.git /opt/safedesk
sudo chown -R safedesk:safedesk /opt/safedesk
```

本地升级已有部署时：

```bash
cd /opt/safedesk
sudo -u safedesk git fetch origin main
sudo -u safedesk git merge --ff-only origin/main
```

## 4. 路线 A：Python 零依赖（推荐）

Ubuntu 24.04 自带 Python 3.12、25.05 自带 Python 3.13，均满足要求（≥3.10）。确认：

```bash
python3 --version
```

冒烟运行（前台，看能否起服务）：

```bash
sudo -u safedesk python3 /opt/safedesk/apps/safedesk-control-plane/server.py
```

能打印 `SafeDesk control plane listening on http://0.0.0.0:8022` 即按 `Ctrl+C` 停掉，进入第 6 节。

## 5. 路线 B：Node.js 22

VERSION-SPECIFIC（Ubuntu 24.04，apt 自带版本过旧，用 NodeSource 源）：

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

VERSION-SPECIFIC（Ubuntu 25.05，apt 自带 Node ≥ 20，可直接用发行版源）：

```bash
sudo apt-get install -y nodejs
```

任一系统都要确认：

```bash
node --version
```

冒烟运行：

```bash
sudo -u safedesk node /opt/safedesk/apps/safedesk-control-plane/server.mjs
```

看到监听行后 `Ctrl+C`。

## 6. 生成自签 TLS 证书

```bash
sudo mkdir -p /opt/safedesk/tls
sudo openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout /opt/safedesk/tls/safedesk.key \
  -out /opt/safedesk/tls/safedesk.crt \
  -days 825 -subj "/CN=safedesk.local" \
  -addext "subjectAltName=IP:0.0.0.0,DNS:safedesk.local"
sudo chown safedesk:safedesk /opt/safedesk/tls/safedesk.key /opt/safedesk/tls/safedesk.crt
sudo chmod 600 /opt/safedesk/tls/safedesk.key
```

## 7. 环境变量一览

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `8022` | 控制面监听端口 |
| `HOST` | `0.0.0.0` | 监听地址；仅本机调试可用 `127.0.0.1` |
| `SAFEDESK_TLS_CERT` | 空 | TLS 证书路径；留空则跑 HTTP |
| `SAFEDESK_TLS_KEY` | 空 | TLS 私钥路径 |
| `SAFEDESK_AUTH` | `1` | 置 `0` 关闭登录（仅限本地调试） |
| `SAFEDESK_ADMIN_PASSWORD` | 内置默认 | 仅首次创建 admin 使用；改密后不再生效 |
| `SAFEDESK_EGRESS_PROXY_PORT` | `0` | 外联代理端口；0 为随机端口 |
| `SAFEDESK_START_TIMEOUT` | `30` | 沙箱拉起超时秒数（执行器看门狗前代参数） |
| `SAFEDESK_DATA_DIR` | `<app>/data` | 数据目录（sandboxes/settings/audit/credentials/runners） |

## 8. 安装 systemd 服务

路线 A（Python）写服务文件：

```bash
sudo tee /etc/systemd/system/safedesk.service > /dev/null <<'EOF'
[Unit]
Description=SafeDesk Enterprise Control Plane
After=network.target

[Service]
Type=simple
User=safedesk
Group=safedesk
WorkingDirectory=/opt/safedesk/apps/safedesk-control-plane
Environment=PORT=8022
Environment=HOST=0.0.0.0
Environment=SAFEDESK_TLS_CERT=/opt/safedesk/tls/safedesk.crt
Environment=SAFEDESK_TLS_KEY=/opt/safedesk/tls/safedesk.key
Environment=SAFEDESK_EGRESS_PROXY_PORT=8023
ExecStart=/usr/bin/python3 /opt/safedesk/apps/safedesk-control-plane/server.py
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

路线 B（Node）写服务文件：

```bash
sudo tee /etc/systemd/system/safedesk.service > /dev/null <<'EOF'
[Unit]
Description=SafeDesk Enterprise Control Plane
After=network.target

[Service]
Type=simple
User=safedesk
Group=safedesk
WorkingDirectory=/opt/safedesk/apps/safedesk-control-plane
Environment=PORT=8022
Environment=HOST=0.0.0.0
Environment=SAFEDESK_TLS_CERT=/opt/safedesk/tls/safedesk.crt
Environment=SAFEDESK_TLS_KEY=/opt/safedesk/tls/safedesk.key
Environment=SAFEDESK_EGRESS_PROXY_PORT=8023
ExecStart=/usr/bin/node /opt/safedesk/apps/safedesk-control-plane/server.mjs
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable safedesk
sudo systemctl start safedesk
sudo systemctl status safedesk --no-pager
```

服务重启后，此前 running/paused 的沙箱进程属于上一实例（内核侧治理的看门狗REQ-EX-012 落地前），管理面状态不受影响。

## 9. 防火墙

```bash
sudo ufw allow 8022/tcp
sudo ufw status
```

外联代理默认绑定 `127.0.0.1:8023`，仅沙箱本机使用，无需对外放行。

## 10. （可选）真实 wasmer 执行器

没有 wasmer 时沙箱以 dry-run 占位进程跑完整生命周期；要真实隔离执行（Claude Code / Codex / DSH）需装 wasmer：

```bash
curl https://get.wasmer.io -sSfL > /tmp/install-wasmer.sh
sudo sh /tmp/install-wasmer.sh
sudo -u safedesk wasmer --version
```

二进制不在 safedesk 用户 PATH 时，把绝对路径写进服务文件再重启：

```bash
wasmer_path=$(sudo -u safedesk sh -lc 'command -v wasmer || true'); echo "$wasmer_path"
```

VERSION-SPECIFIC（Ubuntu 24.04）：默认启用 AppArmor 的用户命名空间限制不影响本控制面（沙箱进程由 wasmer 自身完成隔离）；如另用 Claude Code 的 `srt` 裸沙箱功能，需先 `sudo apt-get install -y bubblewrap socat` 并按其官方文档放行 AppArmor profile。

## 11. 验收清单（逐条 curl）

未登录 401（必须拒绝）：

```bash
curl -sk https://127.0.0.1:8022/api/bootstrap
```

管理员登录拿 token（将下面密码换成部署时设置的，默认 `SafeDesk@Admin`，首登后请在组织设置改密）：

```bash
curl -sk -X POST https://127.0.0.1:8022/api/auth/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SafeDesk@Admin"}'
```

登记凭据（不出现明文回显）：

```bash
TOKEN=上一步返回的token
curl -sk -X POST https://127.0.0.1:8022/api/credentials \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"github-read","value":"ghp_替换为真实值","allowedHosts":["api.github.com"]}'
```

创建沙箱并审批：

```bash
SID=$(curl -sk -X POST https://127.0.0.1:8022/api/sandboxes \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"agent":"codex","policyId":"balanced","workspace":"/opt/safedesk/demo","credentials":["github-read"]}' | python3 -c "import json,sys;print(json.load(sys.stdin)['sandbox']['id'])")
echo "$SID"
curl -sk -X POST "https://127.0.0.1:8022/api/sandboxes/$SID/approve" -H "Authorization: Bearer $TOKEN"
```

查看审批事件与持久化审计：

```bash
curl -sk "https://127.0.0.1:8022/api/events?level=allow" -H "Authorization: Bearer $TOKEN"
curl -sk "https://127.0.0.1:8022/api/events?history=1&limit=5" -H "Authorization: Bearer $TOKEN"
sudo -u safedesk tail -n 3 /opt/safedesk/apps/safedesk-control-plane/data/audit.jsonl
```

## 12. 日常运维

看日志：

```bash
sudo journalctl -u safedesk -f
```

升级（重复第 3 节 git 步骤后）：

```bash
sudo systemctl restart safedesk
```

备份（审计、凭据、沙箱元数据全在 data 目录）：

```bash
sudo systemctl stop safedesk
sudo tar -czf /var/backups/safedesk-data-$(date +%F).tar.gz -C /opt/safedesk/apps/safedesk-control-plane data
sudo systemctl start safedesk
```

恢复（同目录还原后重启即可，权限必须为 safedesk）：

```bash
sudo tar -xzf /var/backups/safedesk-data-YYYY-MM-DD.tar.gz -C /opt/safedesk/apps/safedesk-control-plane
sudo chown -R safedesk:safedesk /opt/safedesk/apps/safedesk-control-plane/data
sudo systemctl restart safedesk
```

## 13. 常用排障

- 浏览器或 curl 报证书不受信：自签证书属预期，客户端加 `-k` 或在客户端导入 `safedesk.crt`。
- approve 返回 502「外联代理启动失败」：检查 `SAFEDESK_EGRESS_PROXY_PORT` 是否被占用，`sudo ss -ltnp | grep 8023`。
- approve 成功但沙箱很快终止：看 `journalctl -u safedesk` 与 `data/runners/<沙箱id>.log`；dry-run 模式下预期为 sleep 占位进程。
- 忘记 admin 密码：删除 data 目录下的 `users.json` 后重启（会重建默认 admin，需重新登录并改密；现有沙箱、审计不受影响）。
