POLICIES = {
    "balanced": {"id": "balanced", "label": "标准研发", "description": "允许项目目录读写；网络仅允许经凭据代理访问已批准服务。", "workspaceMode": "rw", "networkMode": "brokered", "approval": "destructive", "maxCpu": 2, "maxMemoryMb": 4096},
    "review": {"id": "review", "label": "只读审阅", "description": "代码只读、无直接网络；适合安全审阅、依赖检查与分析任务。", "workspaceMode": "ro", "networkMode": "disabled", "approval": "all_writes", "maxCpu": 1, "maxMemoryMb": 2048},
    "build": {"id": "build", "label": "受限构建", "description": "临时工作区读写；默认无网络，依赖下载必须经批准的构建镜像或代理。", "workspaceMode": "ephemeral", "networkMode": "allowlist", "approval": "egress_and_destructive", "maxCpu": 4, "maxMemoryMb": 8192},
}

ALLOWED_AGENTS = {
    "claude-code": {"label": "Claude Code", "command": "claude"},
    "codex": {"label": "Codex", "command": "codex"},
    "dsh": {"label": "DSH", "command": "dsh"},
}

SECRET_PATHS = ["/.env", "/.env.*", "/.ssh/**", "/.aws/**", "/.config/**", "/.npmrc", "/.pypirc"]


from privacy import alias_profile  # noqa: E402


def compile_manifest(sandbox: dict) -> dict:
    policy = POLICIES[sandbox["policyId"]]
    return {
        "apiVersion": "safedesk.io/v1",
        "kind": "SandboxLaunchPlan",
        "id": sandbox["id"],
        "runtime": {"provider": "wasmer", "packages": sandbox["packages"], "network": policy["networkMode"], "volume": f"{sandbox['workspace']}:/workspace"},
        "agent": {"type": sandbox["agent"], "command": ALLOWED_AGENTS[sandbox["agent"]]["command"]},
        "filesystem": {"workspace": sandbox["workspace"], "mode": policy["workspaceMode"], "secretPaths": SECRET_PATHS},
        "credentialBroker": {"enabled": True, "exposedValues": False, "profiles": sandbox["credentials"]},
        "environment": dict(sandbox.get("credentialPlaceholders") or {}),
        "mcpGateway": {"enabled": True, "transport": "streamable-http", "allowedServers": sandbox["mcpServers"]},
        "privacy": {"curtain": bool(sandbox.get("privacyCurtain")), "alias": alias_profile(sandbox["id"]) if sandbox.get("privacyCurtain") else None},
        "enforcement": {"approval": policy["approval"], "maxCpu": policy["maxCpu"], "maxMemoryMb": policy["maxMemoryMb"], "audit": "append-only"},
    }
