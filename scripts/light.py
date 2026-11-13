#!/usr/bin/env python3
"""每小时轻量检查：只拉 5 个核心源，有新域名才合并

比全量快得多，用于把更新延迟从 8 小时压到 1 小时。
新增少于 THRESHOLD 条时直接跳过，不动产物。
"""
import os, sys, importlib.util, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = [
    "https://anti-ad.net/easylist.txt",
    "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adrules_domainset.txt",
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/reject.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
]
THRESHOLD = 15
MAX_NEW = 300

spec = importlib.util.spec_from_file_location("adblock", os.path.join(ROOT, "adblock.py"))
ab = importlib.util.module_from_spec(spec)

def main():
    spec.loader.exec_module(ab)
    files = ab.read_sources_from(CORE)
    if not files:
        print("[轻量] 源全部失败，跳过本轮")
        return 0
    doms, srcs = ab.collect(files)
    white = ab.load_white()
    fresh = set()
    for d, c in doms.items():
        if d in white or ab.is_protected(d):
            continue
        if ab.SAFE_WORDS.search(d) and not ab.ad_like(d):
            continue
        if ab.SHARED_INFRA.search(d):
            continue
        if c >= 2 or ab.ad_like(d):
            fresh.add(d)
    cur = ab.load_current()
    new = fresh - cur
    # 按广告特征 + 收录次数排序，单轮最多并入 MAX_NEW 条，避免冲破总限额
    ranked = sorted(new, key=lambda d: (ab.ad_like(d), doms[d], -len(d)), reverse=True)
    new = set(ranked[:MAX_NEW])
    print("[轻量] 核心源 %d 条，当前产物 %d 条，本轮合并 %d 条" % (len(fresh), len(cur), len(new)))
    if len(new) < THRESHOLD:
        print("[轻量] 新增不足 %d 条，跳过" % THRESHOLD)
        return 0
    merged = cur | new
    if len(merged) > ab.TARGET:
        merged = set(sorted(merged, key=lambda d: (ab.ad_like(d), doms.get(d, 0), -len(d)), reverse=True)[:ab.TARGET])
    blocked, _ = ab.collapse(merged, white)
    dead = ab.load_dead()
    blocked -= dead
    apps = ab.load_apps()
    ab.write(blocked, white, apps, srcs)
    with open(os.path.join(ROOT, ".cache", "light_new.txt"), "w", encoding="utf-8") as f:
        f.write("".join(d + "\n" for d in sorted(new)))
    print("[轻量] 已合并新增 %d 条，总数 %d" % (len(new), len(blocked)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
