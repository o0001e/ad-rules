#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GKD 订阅规则自动更新（GitHub Actions 内运行）

1. 官方镜像 @gkd-kit/subscription → 改名「ADST持续更新」，version +5
2. oklazeno 上游镜像 → id 固定 73，改名「x随缘更新」，version +1

任一环节失败只跳过该环节，不覆盖旧文件。
"""
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OFFICIAL_URL = "https://registry.npmmirror.com/@gkd-kit/subscription/latest/files/dist/gkd.json5"
OKLAZENO_VER_URL = "https://gcore.jsdelivr.net/gh/oklazeno/gkd-subscription@main/gkd.version.json5"
OKLAZENO_URL = "https://gcore.jsdelivr.net/gh/oklazeno/gkd-subscription@main/gkd.json5"

TARGET = os.path.join(ROOT, "gkd.json")
TARGET_CUSTOM = os.path.join(ROOT, "gkd-custom.json")
TARGET_VER = os.path.join(ROOT, "gkd.version.json5")

MIN_SIZE = 100 * 1024


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "ad-rules-bot"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def head_section(text, size=2000):
    return text[:size]


def get_field(head, field):
    # 兼容 name:'x' / "version":186 两种写法
    m = re.search(r"""%s["']?\s*:\s*["']?([0-9]+)""" % field, head)
    return int(m.group(1)) if m else None


def replace_num(text, field, value):
    """替换数字型字段，兼容 key 带引号与 value 带引号"""
    pattern = r"""%s(["']?\s*:\s*)["']?[0-9]+["']?""" % field
    return re.sub(pattern, lambda m: "%s%s%s" % (field, m.group(1), value), text, count=1)


def replace_str(text, field, value):
    """整段替换字符串型字段，避免只吃掉前半截"""
    pattern = r"""%s["']?\s*:\s*'[^']*'""" % field
    return re.sub(pattern, "%s:'%s'" % (field, value), text, count=1)


def patch_official():
    print("[官方镜像] 拉取", OFFICIAL_URL)
    text = fetch(OFFICIAL_URL)
    head = head_section(text)
    old_ver = get_field(head, "version")
    if not old_ver:
        raise RuntimeError("未取到官方 version")

    new_name = "ADST持续更新"
    text = replace_str(text, "name", new_name)
    text = replace_num(text, "version", old_ver + 5)

    head2 = head_section(text)
    if new_name not in head2:
        raise RuntimeError("name 替换未生效")
    if len(text.encode()) < MIN_SIZE:
        raise RuntimeError("文件过小 %d bytes" % len(text.encode()))

    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(text)
    print("[官方镜像] 完成 version %d → %d, 大小 %d KB"
          % (old_ver, old_ver + 5, len(text.encode()) // 1024))
    return old_ver + 5


def patch_oklazeno():
    print("[x随缘] 拉取版本", OKLAZENO_VER_URL)
    ver_text = fetch(OKLAZENO_VER_URL, timeout=30)
    up_ver = get_field(ver_text[:600], "version")
    if not up_ver:
        raise RuntimeError("未取到上游 version")

    print("[x随缘] 拉取规则", OKLAZENO_URL)
    text = fetch(OKLAZENO_URL, timeout=90)
    if len(text.encode()) < MIN_SIZE:
        raise RuntimeError("文件过小")

    text = replace_num(text, "id", 73)
    text = replace_str(text, "name", "x随缘更新")
    text = replace_num(text, "version", up_ver + 1)

    with open(TARGET_CUSTOM, "w", encoding="utf-8") as f:
        f.write(text)
    with open(TARGET_VER, "w", encoding="utf-8") as f:
        json.dump({"id": 73, "version": up_ver + 1}, f)

    print("[x随缘] 完成 上游 v%d → 本地 v%d, 大小 %d KB"
          % (up_ver, up_ver + 1, len(text.encode()) // 1024))
    return up_ver + 1


def main():
    failed = []
    try:
        patch_official()
    except Exception as e:
        failed.append("官方镜像: %s" % e)
        print("[跳过] 官方镜像更新失败:", e)

    try:
        patch_oklazeno()
    except Exception as e:
        failed.append("x随缘: %s" % e)
        print("[跳过] x随缘更新失败:", e)

    if failed:
        print("[总结] 有环节失败:", "; ".join(failed))
        # 两个都失败才算整体失败，单边失败不阻断
        if len(failed) >= 2:
            sys.exit(1)
    else:
        print("[总结] 全部更新成功")


if __name__ == "__main__":
    main()
