# Demo 05：外卖隐私下单（个人信息不出沙箱）

> 场景：通过 SafeDesk 沙箱在外卖平台下单——沙箱内没有真实姓名/手机号/地址/银行卡，
> 平台收到的只有沙箱别名替身，支付凭据由主机在出口时代签。
> 济南=>平台拿不到可关联到真人或真实支付渠道的任何字段。

技术支点：

- `privacy: true` 沙箱开启**隐私帘**：`privacy.py`/`src/privacy.mjs` 为每个沙箱生成确定性别名
  （`访客-XXXX` 名称、`138********` 格式替身手机号、`SafeDesk 智能自提柜Xnn` 收货地址）
- 出口代理对所有出站请求做三级处理：①身份字段（name/phone/address）别名互换，②自由文本 PII 正则脱敏
  （手机号/身份证/Luhn 银行卡/邮箱），③支付字段（cardNo/cvv）直接丢弃
- 支付走 `meituan-proxy` 凭据：占位符进沙箱，真实 pay-token 仅对 `api.meituan.demo.local` 白名单在主机侧注入
- 响应头注 `X-Safedesk-Alias-Id`，脱敏次数进安全事件（`个人信息脱敏`）

## 逐步演示

前置：控制面已启动（见 demos/README.md），下面 `PORT=18022`，管理员登录后存 `TOKEN`。

### 1. 登记支付凭据（真实值不上 API 回显）

```bash
curl -s -X POST http://127.0.0.1:18022/api/credentials \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"meituan-proxy","value":"pay-token-real-9f81","allowedHosts":["api.meituan.demo.local"]}'
```

返回只有掩码：`{"name":"meituan-proxy","masked":"pay-****"}`。

### 2. 创建隐私沙箱（payload 带 `privacy: true`）

```bash
curl -s -X POST http://127.0.0.1:18022/api/sandboxes \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name":"takeout-order",
    "agent":"dsh",
    "policyId":"balanced",
    "workspace":"/srv/orders/takeout",
    "credentials":["meituan-proxy"],
    "privacy":true,
    "purpose":"隐私下单演示"
  }'
```

返回中 `sandbox.privacyCurtain=true`，启动清单 `manifest.privacy` 里能看到沙箱别名块：

```json
"privacy": {"curtain": true, "alias": {"aliasId":"sf-…","name":"访客-…","phone":"138…","address":"SafeDesk 智能自提柜..."}}
```

### 3. 管理员审批（执行器拉起 + 出口代理挂上隐私帘）

```bash
SID=上一步sandbox.id
curl -s -X POST "http://127.0.0.1:18022/api/sandboxes/$SID/approve" -H "Authorization: Bearer $TOKEN"
```

### 4. 模拟平台视角：真实信息 = 0（本地自测版）

仓库内已有可跑通“平台视角”的用例（主机真实 mock 美团端点）：

```bash
python3 -m unittest test.test_proxy.PrivacyCurtainProxyTest -v
```

Node 等价用例：

```bash
node --test test/proxy.test.mjs 2>&1 | grep takeout
```

断言口径：平台收到的 body 不含真实姓名/手机号/小区地址/Luhn 银行卡号；含别名手机与自提柜地址；
`X-Safedesk-Alias-Id` 头是 `sf-...`；`Authorization` 占位符被代签成真实 pay-token。

### 5. 事件复核

```bash
curl -s "http://127.0.0.1:18022/api/events?history=1&q=脱敏" -H "Authorization: Bearer $TOKEN"
```

应看到 `个人信息脱敏 N 项` 事件，验证 PII 在出沙箱前被处理。

## 与模板的联动

控制台任务模板新增的「外卖隐私下单」(`tpl-takeout`) 与上述流程完全一致：dsh + balanced + meituan-proxy + `privacy:true`。点击即可起沙箱。
