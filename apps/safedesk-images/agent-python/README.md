# safedesk/agent-python 沙箱镜像

自定义 WAPM(webc) 沙箱镜像：CPython 运行时（来自 WAPM 官方 `python` 包）+ 三个 agent 引导脚本（`claude` / `codex` / `dsh`）。

控制面 `packages` 字段填本地产物绝对路径即可，launcher 无需改动：

```json
{"policyId": "build", "agent": "dsh", "workspace": "/srv/ci-demo", "packages": ["/opt/wasmer-images/safedesk-agent-python.webc"]}
```

## 工作原理

- wasmer `[fs]` 把 `agentroot/` 映射到 guest 根 `/`，于是 `/dsh`、`/claude`、`/codex` 三个引导文件存在。
- launcher 组装的 argv 结尾是 `-- <agent 命令>`；python 把位置参数当脚本路径打开，在 guest cwd=`/` 下命中引导文件。
- 引导脚本 `chdir /workspace` 并执行其 `run_ci.py`（当前是 CI 演示实现；接入真实 agent 时换成各自 CLI 引导即可）。

## 构建（Ubuntu 24.04，需先装 wasmer ≥ 7.5）

大体积运行时 blob（`cpython/`、`openssl/`、`modules/python`）不进仓库，按以下命令逐条在镜像主机上现拉（仓库路径按实际 checkout 位置替换）：

```bash
# 1. 准备目录与镜像源文件
mkdir -p /opt/agent-img
cp -r /path/to/repo/apps/safedesk-images/agent-python/wasmer.toml /opt/agent-img/
cp -r /path/to/repo/apps/safedesk-images/agent-python/agentroot /opt/agent-img/

# 2. 拉取并解包 python 运行时
wasmer package download --out-path /tmp/python.webc python
wasmer package unpack --out-dir /tmp/agent-python-unpacked /tmp/python.webc
cp -r /tmp/agent-python-unpacked/cpython /tmp/agent-python-unpacked/openssl /tmp/agent-python-unpacked/modules /opt/agent-img/

# 3. 引导脚本语法检查
python3 -m py_compile /opt/agent-img/agentroot/dsh /opt/agent-img/agentroot/claude /opt/agent-img/agentroot/codex

# 4. 构建 webc
mkdir -p /opt/wasmer-images
wasmer package build /opt/agent-img -o /opt/wasmer-images/safedesk-agent-python.webc
```

## 验证

```bash
wasmer run /opt/wasmer-images/safedesk-agent-python.webc \
  --volume /srv/ci-demo:/workspace \
  --env SAFEDESK_SANDBOX_ID=sbx-local-verify \
  -- dsh
```

预期输出 `[safedesk-agent:dsh] bootstrap online` → `run_ci.py` 结果 JSON，退出码 0。

## 注意

- `packages` 字段目前允许任意路径（包括本地 webc 与 WAPM 包名）。限制到组织白名单由 REQ-PL-005 跟进。
- 真实 agent 接入时，引导脚本位置不变：把 `agentroot/<agent>` 换成对应 CLI 的引导（同样由 python 承载或另起 wasm），不用改控制面。
