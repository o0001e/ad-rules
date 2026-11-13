#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""针对单个 App 重新抓取广告子域（DoH 解析 + 通配检测），覆写 apps/<App>.txt。

相比 crawl_rules 的改进：
  1. 用 DoH（阿里 223.5.5.5）解析，避免本机 DNS 不可靠
  2. 通配域检测：随机 nonce 子域能解析的主域标记为通配，跳过字典爆破，只用 CT 真名
  3. 只保留广告/埋点类子域，避免误杀视频 CDN、登录等业务域

用法：
  python3 scripts/crawl_app.py 红果短剧
  python3 scripts/crawl_app.py 红果短剧 --with-sdk
  python3 scripts/crawl_app.py 红果短剧 --discover     # 只打印发现的域名，不写文件
"""
import concurrent.futures as cf
import json
import os
import random
import re
import string
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crawl_rules as cr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPS = os.path.join(ROOT, "apps")
DOH = "https://dns.alidns.com/resolve"

# 字节系广告 SDK
SDK_APEXES = ["csjplatform.com", "gromore.com", "pangolin.io"]

# 广告/埋点关键字（含字节系常见写法）
AD_RE = re.compile(
    r"(^|[.-])("
    r"ads?|adx|adn|adsdk|adimg|adlog|adstat|adtrack|adbanner|adclick|adcache|adbid|"
    r"adapi|adservice|adsrv|adserver|adview|adm|adnet|adunion|"
    r"pangle|pangolin|gromore|csj|pgl|gdt|union|ssp|dsp|"
    r"track|tracker|tracklog|log|logs|logdata|stat|stats|statistic|analytics|"
    r"metric|metrics|monitor|mon|beacon|sensor|report|reports|click|clk|"
    r"impression|exposure|promote|promotion|promo|banner|splash|sdk|mobads|cpro|"
    r"misc|splash|feedad|drawad|reward|rewardvideo|interstitial"
    r")([.-]|$)",
    re.I,
)


def doh_a(name, timeout=8):
    url = DOH + "?" + urllib.parse.urlencode({"name": name, "type": "A"})
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.loads(r.read().decode())
        return [a["data"] for a in (d.get("Answer") or []) if a.get("type") == 1]
    except Exception:  # noqa: BLE001
        return []


def nonce_sub(apex):
    tag = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    return "zz%s%d.%s" % (tag, random.randint(1, 9999), apex)


def is_wildcard(apex):
    return bool(doh_a(nonce_sub(apex)))


def load_apps():
    with open(os.path.join(ROOT, "app_list.json"), encoding="utf-8") as f:
        return json.load(f)


def main():
    if len(sys.argv) < 2:
        print("用法: python3 scripts/crawl_app.py <App名> [--with-sdk] [--discover]")
        return 1

    app = sys.argv[1]
    with_sdk = "--with-sdk" in sys.argv
    discover = "--discover" in sys.argv

    apps = load_apps()
    if app not in apps:
        print("app_list.json 里没有这个 App:", app)
        return 1

    apexes = list(apps[app])
    if with_sdk:
        apexes += SDK_APEXES

    print("[%s] 待查主域 %d 个" % (app, len(apexes)))

    # 1) 通配检测（主域无 A 记录不代表子域不存在，不能据此跳过）
    alive, wild = [], []
    for apex in apexes:
        if is_wildcard(apex):
            wild.append(apex)
            print("  %-26s ⚠️ 通配域（只用 CT 真名，不做字典爆破）" % apex)
        else:
            alive.append(apex)
            has_a = bool(doh_a(apex))
            print("  %-26s ✅ 正常域（主域%s）" % (apex, "有A记录" if has_a else "无A记录，子域仍可查"))

    if not alive and not wild:
        print("没有可抓取的主域")
        return 1

    # 2) 收集候选
    cands = set()
    for apex in alive + wild:
        print("  CT日志:", apex)
        ct = cr.ct_subdomains(apex)
        print("    CT 返回 %d 个子域" % len(ct))
        cands |= ct
        if apex in alive:  # 通配域不做字典爆破
            for w in cr.AD_WORDS:
                cands.add("%s.%s" % (w, apex))

    # 3) DoH 校验
    print("  候选总数:", len(cands))
    verified = {}
    with cf.ThreadPoolExecutor(max_workers=120) as ex:
        for h, ans in zip(sorted(cands), ex.map(doh_a, sorted(cands))):
            if ans:
                verified[h] = True
    print("  真实存在:", len(verified))

    # 4) 过滤
    apex_all = set(apexes)
    blocked = sorted(
        h for h in verified
        if h not in apex_all and not h.startswith("zz") and AD_RE.search(h)
    )

    if discover:
        print("\n=== 命中的广告类子域（%d 条）===" % len(blocked))
        for h in blocked:
            print("  " + h)
        return 0

    # 5) 写文件
    os.makedirs(APPS, exist_ok=True)
    out = os.path.join(APPS, "%s.txt" % app)
    old = 0
    if os.path.exists(out):
        with open(out, encoding="utf-8") as f:
            old = sum(1 for line in f if line.startswith("0.0.0.0"))

    with open(out, "w", encoding="utf-8") as f:
        f.write("# %s 广告拦截 %d条\n" % (app, len(blocked)))
        for h in blocked:
            f.write("0.0.0.0 %s\n" % h)

    print("  写入 %s：%d 条（原 %d 条）" % (out, len(blocked), old))
    return 0


if __name__ == "__main__":
    sys.exit(main())
