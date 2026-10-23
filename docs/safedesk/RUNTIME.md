# SafeDesk Runtime Notes / 底层运行时说明

This file is the only product-facing place that names the isolation runtime used by SafeDesk. The root README stays focused on the enterprise sandbox product.

本文件是产品文档中单独说明底层隔离运行时的位置。仓库根目录 README 只讲 SafeDesk 产品本身。

## 中文

SafeDesk 的隔离底座来自 [Wasmer](https://wasmer.io/) 开源运行时。仓库在团队代码前导入了 `wasmerio/wasmer` `v7.5.0`，并打上 `v0` tag。

SafeDesk 在该底座上增加企业层：

- 把 `--volume` / `--net` / `--env` 收口为三种策略：标准研发、只读审阅、受限构建。
- 禁止把主机环境变量整包转发给沙箱。
- 模型与 MCP 流量走主机凭据代理，不把密钥注入 guest env。
- 启动前必须审批，终止后短期会话凭据立即失效。

相关上游文档：

- 官网：https://wasmer.io/
- 运行时文档：https://docs.wasmer.io/runtime/
- 开源仓库：https://github.com/wasmerio/wasmer

## English

SafeDesk uses [Wasmer](https://wasmer.io/) as the isolation runtime. The repository imported `wasmerio/wasmer` `v7.5.0` and tagged it as `v0` before any team code.

SafeDesk adds an enterprise layer on top of that runtime:

- Collapse `--volume` / `--net` / `--env` into three policies: Standard Development, Read-only Review, and Restricted Build.
- Never forward the full host environment into the sandbox.
- Route model and MCP traffic through a host credential broker instead of injecting secrets into the guest env.
- Require approval before start, and expire short-lived session credentials on terminate.

Upstream references:

- Website: https://wasmer.io/
- Runtime docs: https://docs.wasmer.io/runtime/
- Source repository: https://github.com/wasmerio/wasmer
