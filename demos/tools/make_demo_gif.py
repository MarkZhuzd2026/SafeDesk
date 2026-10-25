#!/usr/bin/env python3
"""Generate the SafeDesk scenarios demo video (Ctrip booking + CI build) as an animated GIF.

All content is sourced from the actual e2e demo outputs (2026-10-25) and contains
ONLY fabricated identities (假名/假卡/演示域名) — nothing from the developer machine.
Run with: python3 make_demo_gif.py  (requires Pillow)
"""
from __future__ import annotations

import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 800, 450
FPS = 8
REVEAL_FRAMES = 2       # frames between lines (0.25s @ 8fps)
SCENE_HOLD = 10         # frames held after the last line of a scene
TITLE_HOLD = 18         # hold frames on title cards

BG = (15, 20, 27)
BG_TITLE = (12, 17, 24)
FG_DIM = (120, 132, 148)
FG = (205, 214, 224)
FG_BRIGHT = (240, 246, 252)
GREEN = (125, 216, 125)
CYAN = (90, 200, 215)
AMBER = (235, 185, 90)
RED = (235, 110, 110)
BLUE = (120, 170, 235)

FONT_PATHS = [
    "/System/Library/Fonts/STHeiti Medium.ttc",
    "/System/Library/Fonts/Supplemental/Songti.ttc",
    "/System/Library/Fonts/Menlo.ttc",
]


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for candidate in FONT_PATHS:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


F_TITLE = load_font(30)
F_SUB = load_font(15)
F_HDR = load_font(15)
F_BODY = load_font(13)
F_SMALL = load_font(11)


def new_canvas(color=BG) -> tuple:
    image = Image.new("RGB", (W, H), color)
    return image, ImageDraw.Draw(image)


def draw_chrome(draw: ImageDraw.ImageDraw, header: str) -> int:
    draw.rectangle([0, 0, W, 30], fill=(24, 31, 40))
    for idx, color in enumerate([(235, 110, 110), (235, 185, 90), (125, 216, 125)]):
        x = 14 + idx * 16
        draw.ellipse([x, 10, x + 9, 19], fill=color)
    draw.text((60, 8), header, font=F_HDR, fill=FG_DIM)
    return 44


def title_scene(kicker: str, title: str, subtitle: str) -> list:
    image, draw = new_canvas(BG_TITLE)
    draw.text((60, 150), kicker, font=F_SUB, fill=GREEN)
    draw.text((60, 185), title, font=F_TITLE, fill=FG_BRIGHT)
    draw.text((60, 235), subtitle, font=F_SUB, fill=FG_DIM)
    draw.rectangle([60, 280, 220, 283], fill=GREEN)
    return [image.copy() for _ in range(TITLE_HOLD)]


SCENES = [
    (
        "demo shell — 携程公务订票 · 隐私帘",
        [
            ("$ curl -X POST /api/credentials -d '{\"name\":\"ctrip-pay\",\"value\":\"pay-token-ctrip-real\",\"allowedHosts\":[\"api.ctrip.demo.local\"]}'", GREEN),
            ('  → {"credential":{"name":"ctrip-pay","masked":"pay-****","allowedHosts":["api.ctrip.demo.local"]}}', FG),
            ("  ① 支付凭据登记：返回值只有掩码，真实 token 不回显", AMBER),
            ("", FG),
            ("$ curl -X POST /api/travelers -d '{\"handle\":\"traveller-li\",\"name\":\"李雷\",\"idCard\":\"110101199003071234\",…}'", GREEN),
            ('  → {"traveler":{"handle":"traveller-li","name":"李*","idCard":"1101**********34","phone":"138****5678"}}', FG),
            ("  ② 出行人卡片登记：姓名/证件/手机全部掩码展示，真实值只进主机注册表", AMBER),
            ("", FG),
        ],
    ),
    (
        "demo shell — 创建隐私沙箱 + 审批",
        [
            ("$ curl -X POST /api/sandboxes -d '{\"agent\":\"dsh\",\"policyId\":\"balanced\",", GREEN),
            ('    "travelerCards":["traveller-li"],"credentials":["ctrip-pay"],"privacy":true}\'', FG),
            ("  → 201 pending_approval   启动清单 (SandboxLaunchPlan)：", CYAN),
            ('  manifest.privacy = {"curtain":true,"alias":{"name":"访客-E516","phone":"138…","address":"智能自提柜C85"}}', FG),
            ('  manifest.travelers = {"cards":["traveller-li"],"valuesExposed":false}  ← 清单里没有任何真实值', AMBER),
            ("", FG),
            ("$ curl -X POST /api/sandboxes/sbx-80341ee2/approve", GREEN),
            ('  → {"status":"running","runtime":{"mode":"wasmer","pid":70554,"command":"/usr/local/bin/wasmer"}}', FG),
            ("  审批后真实拉起 wasmer；出口代理挂上隐私帘 + 出行人注入映射", AMBER),
        ],
    ),
    (
        "出口代理视角 — 白名单域（api.ctrip.demo.local）",
        [
            ("沙箱发出（只有占位符，零真实信息）：", CYAN),
            ('  POST /openapi/book {"traveler":{"name":"{{SD_TRV_…name_ab12}}","idCard":"{{SD_TRV_…idCard_ab12}}",', FG),
            ('    "phone":"{{SD_TRV_…phone_ab12}}"},"note":"紧急电话 13812345678 别漏接","route":"北京-上海 CA1837"}', FG),
            ("", FG),
            ("携程平台实际收到（代理解析注入 + 尾声脱敏）：", CYAN),
            ('  {"traveler":{"name":"李雷","idCard":"110101199003071234","phone":"13812345678"},', GREEN),
            ('   "note":"紧急电话 [*手机号*] 别漏接","route":"北京-上海 CA1837"}', GREEN),
            ("  ✓ 白名单域上实名出票成立；手滑把真实手机号写进 note 被消掉；带 X-Safedesk-Alias-Id 一次性标识", AMBER),
        ],
    ),
    (
        "出口代理视角 — 非白名单与审计",
        [
            ("同一占位符发往 other.not-allowed：", CYAN),
            ('  ← 403 {"error":"egress denied","reason":"凭据不允许发送到 other.not-allowed"}', RED),
            ("  ✗ 没在携程白名单域上，真实姓名/证件号绝不外泄", AMBER),
            ("", FG),
            ("审计落盘（audit.jsonl）：", CYAN),
            ("  allow  人工审批    ctrip-trip-ticket 已启动（wasmer 模式）", FG),
            ("  info   登记出行人卡片 traveller-li 已登记（目的地白名单 1 条）", FG),
            ("  info   网络决策    POST api.ctrip.demo.l… 个人信息脱敏 3 项", FG),
            ("  block  网络决策    占位符注入被拒绝：非白名单目的地", FG),
            ("  block  终止沙箱    ctrip-trip-ticket 已终止，短期会话凭据失效", FG),
        ],
    ),
    (
        "demo shell — CI 打包（build 策略 + 自定义镜像）",
        [
            ("$ curl -X POST /api/sandboxes -d '{\"agent\":\"dsh\",\"policyId\":\"build\",", GREEN),
            ('    "workspace":"/srv/ci-demo","packages":["/opt/wasmer-images/safedesk-agent-python.webc"]}\'', FG),
            ("  → 201 pending_approval", CYAN),
            ("$ curl -X POST /api/sandboxes/SID/approve", GREEN),
            ('  → {"status":"running","runtime":{"mode":"wasmer","pid":70554}}', FG),
            ("", FG),
            ("launcher 日志（guest 内真实执行）：", CYAN),
            ("  [safedesk-agent:dsh] bootstrap online", GREEN),
            ("  [safedesk-agent:dsh] sandbox=sbx-80341ee2 network=default", FG),
            ("  [safedesk-agent:dsh] executing /workspace/run_ci.py", GREEN),
            ("  [ci] syntax-check: PASS", GREEN),
            ('  ------  Ran 4 tests in 0.001s  \\n[ci] unit-tests: PASS 4 tests  \\n{"ok": true}  exit=0', FG),
        ],
    ),
    (
        "demo shell — 生命周期收尾",
        [
            ("$ curl -X POST /api/sandboxes/SID/terminate", GREEN),
            ('  → {"status":"terminated"}', FG),
            ("  wasmer 进程 SIGTERM 退出，代理注销，占位符全部失效", AMBER),
            ("", FG),
            ("审计尾部：", CYAN),
            ("  allow  人工审批    ci-night-build-agent-img 已启动（wasmer 模式）", FG),
            ("  block  终止沙箱    ci-night-build-agent-img 已终止，短期会话凭据失效", FG),
            ("", FG),
            ("双端测试：Python 244 / Node 215 全绿；CI 用例另逐模块复核", CYAN),
        ],
    ),
]


def scene_frames(header: str, lines: list) -> list:
    frames = []
    visible: list = []
    for index, (text, color) in enumerate(lines):
        visible.append((text, color))
        if index % REVEAL_FRAMES == 0 or index == len(lines) - 1:
            image, draw = new_canvas()
            baseline = draw_chrome(draw, header)
            y = baseline + 6
            for content, line_color in visible:
                for wrapped in wrap_line(content, line_color):
                    draw.text((18, y), wrapped[0], font=F_BODY if len(content) > 2 else F_SMALL, fill=wrapped[1])
                    y += 17
                labels = None
            frames.append(image)
    for _ in range(SCENE_HOLD):
        frames.append(frames[-1].copy())
    return frames


MAX_CHARS = 92


def wrap_line(text: str, color) -> list:
    if "\\n" in text:
        chunks = text.split("\\n")
        return [(chunk, color) for chunk in chunks]
    if len(text) <= MAX_CHARS:
        return [(text, color)]
    pieces = []
    remaining = text
    while len(remaining) > MAX_CHARS:
        cut = remaining.rfind(" ", 0, MAX_CHARS)
        # cut<=2 would only strip the indent prefix -> infinite loop; fall back to a hard cut.
        if cut <= 2:
            cut = MAX_CHARS
        pieces.append(remaining[:cut])
        rest = remaining[cut:]
        remaining = ("  " + rest.lstrip()) if rest else ""
    if remaining:
        pieces.append(remaining)
    return [(piece, color) for piece in pieces]


def build() -> list:
    frames = []
    frames += title_scene("SAFEDESK · 场景演示 1/2", "携程公务订票（隐私帘）", "实名出票仅对携程白名单解析注入 · 平台拿不到员工画像与支付渠道")
    for header, lines in SCENES[:4]:
        frames += scene_frames(header, lines)
    frames += title_scene("SAFEDESK · 场景演示 2/2", "CI 打包（build 策略）", "自定义 WAPM 镜像 → approve 真实拉起 → guest 内跑完 CI 流水线")
    for header, lines in SCENES[4:]:
        frames += scene_frames(header, lines)
    frames += title_scene("SAFEDESK", "安全优先 · 配置友好", "演示数据全部为假名/假卡/演示域名 · 录制过程零本机信息")
    return frames


def main() -> None:
    out_dir = Path(os.environ.get("SAFEDESK_VIDEO_OUT", "artifacts/demo"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "safedesk-ctrip-ci-demo.gif"
    frames = build()
    fg = frames[0].convert("P", palette=Image.ADAPTIVE, colors=200)
    fg.save(
        out,
        save_all=True,
        append_images=[frame.convert("P", palette=Image.ADAPTIVE, colors=200) for frame in frames[1:]],
        duration=int(1000 / FPS),
        loop=0,
        optimize=True,
    )
    size_mb = out.stat().st_size / (1024 * 1024)
    print(f"wrote {out} frames={len(frames)} size={size_mb:.1f}MB duration={len(frames) / FPS:.1f}s")


if __name__ == "__main__":
    main()
