# Demo 06：携程公务出行订票（实名出票也不暴露员工画像）

> 场景：员工用 SafeDesk 沙箱在携程订购公务机票/火车票。机票腹胀需要真实姓名 + 身份证号，
> 企业希望做到"平台能出票 + 平台拼不出员工账户画像 + 隐藏支付渠道"。

与外卖场景的差异：

- 外卖（Demo 05）真实信息为**零**——纯替身模型（别名）。
- 订票实名制——**出行人卡片（Traveler Card）模型**：真实姓名/证件号/护照/手机号在主机侧登记，
  沙箱只持占位符 `{{SD_TRV_...}}`；出口代理只在携程白名单域上把它解析回真实值。
  管道顺序：①身份字段替身（联系人仍可用沙箱别名）②文本 PII 脱敏 ③按白名单解析占位符
  （出行人 + 支付 token 都在此阶段注入，注入不会反过来被脱敏销毁）。

关键技术点：

- `travelers.py` / `src/travelers.mjs`：主机侧出行人注册表（0600 落盘、掩码回显、handle 3-32 位、
  目的地白名单必填、证件/手机/护照格式校验）
- 沙箱 payload 增加 `travelerCards: ["traveller-li"]`（存在性+配额校验），manifest 带 `travelers.cards`
  （**不含任何真实值**，仅列出引用 handle）
- 审批时把出行人引用解析为"每条目的地白名单绑定"的注入项，与支付 token 一起进代理注入映射
- 代理对**请求体**做占位符扫描替换（`inject_body`），对未授权目的地的注入请求一律 403

## 逐步演示

前置：控制面已启动（见 demos/README.md），下面 `PORT=18022`，管理员登录后存 `TOKEN`。

### 1. 登记支付凭据与出行人卡片（真实值不出 API）

```bash
curl -s -X POST http://127.0.0.1:18022/api/credentials \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"ctrip-pay","value":"pay-token-ctrip-real","allowedHosts":["api.ctrip.demo.local"]}'
```

```bash
curl -s -X POST http://127.0.0.1:18022/api/travelers \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"handle":"traveller-li","name":"李雷","idCard":"110101199003071234","phone":"13812345678","passport":"E12345678","allowedHosts":["api.ctrip.demo.local"]}'
```

返回只有掩码：`"name":"李*","idCard":"1101**********34","phone":"138****5678"`。

### 2. 创建携程隐私沙箱

```bash
curl -s -X POST http://127.0.0.1:18022/api/sandboxes \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name":"ctrip-trip-ticket",
    "agent":"dsh",
    "policyId":"balanced",
    "workspace":"/srv/travel/bookings",
    "credentials":["ctrip-pay"],
    "travelerCards":["traveller-li"],
    "privacy":true,
    "purpose":"公务出行订票演示"
  }'
```

未登记的引用会 400：`{"error":"未知出行人卡片：ghost"}`。

manifest 里能看到隐私帘别名与出行人块：

```json
"privacy": {"curtain": true, "alias": {"name": "访客-…", "phone": "138…"}},
"travelers": {"cards": ["traveller-li"], "valuesExposed": false}
```

### 3. 管理员审批

```bash
SID=上一步sandbox.id
curl -s -X POST "http://127.0.0.1:18022/api/sandboxes/$SID/approve" -H "Authorization: Bearer $TOKEN"
```

### 4. 平台视角断言（本地自测版）

```bash
python3 -m unittest test.test_proxy.CtripCurtainProxyTest -v
```

Node 等价用例：

```bash
node --test test/proxy.test.mjs 2>&1 | grep -A2 -i "ctrip"
```

断言口径：

- 白名单域：占位符解析回真实姓名/证件/手机（可出票）；顺手暴露的 `note` 字段里的真实手机号被消除成 `[*手机号*]`
- 非白名单：若发送方向的目的地不在白名单，注入拿 403，平台和中介都拿不到真实证件
- 沙箱请求头带 `X-Safedesk-Alias-Id`（一次性身份标识，平台无法按"同一用户"画像）

### 5. 模板直通

控制台任务模板「携程公务出行订票」(`tpl-ctrip`) = dsh + balanced + ctrip-pay + privacy，点开即调上面调用链。
