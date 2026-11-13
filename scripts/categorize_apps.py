#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把合并后的规则按国内 App 归类，输出 apps/ 目录与汇总表。"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
OUT = os.path.join(ROOT, "apps")

# App -> 归属标签（命中任一标签即归入该 App；先到先得）
APPS = [
    ("红果免费短剧", ["fqnovel", "novelquickapp", "hongguoduanju", "changdunovel", "qznovel"]),
    ("红果免费漫剧", ["fqmanhua", "qzmanhua", "manju"]),
    ("番茄小说", ["fanqie", "tomato", "novelquickapp"]),
    ("抖音", ["douyin", "amemv", "snssdk", "douyinpic", "douyinvod", "pangle", "pangolin", "gromore", "csj"]),
    ("抖音极速版", ["douyinlite", "snssdk"]),
    ("快手", ["kuaishou", "kwaicdn", "gifshow", "kwai", "ksad"]),
    ("快手极速版", ["kuaishoulite"]),
    ("微信", ["weixin", "wechat", "wx.qq", "qlogo"]),
    ("QQ", ["qq.com", "qzone", "gtimg"]),
    ("哔哩哔哩", ["bilibili", "hdslb", "bilivideo", "biliapi", "b23"]),
    ("小红书", ["xiaohongshu", "xhscdn", "xhs"]),
    ("微博", ["weibo", "sinaimg", "sina.com"]),
    ("知乎", ["zhihu", "zhimg"]),
    ("豆瓣", ["douban", "doubanio"]),
    ("爱奇艺", ["iqiyi", "qiyi", "71.am"]),
    ("腾讯视频", ["v.qq.com", "gtimg", "video.qq", "mgtv"]),
    ("优酷", ["youku", "ykimg"]),
    ("芒果TV", ["mgtv", "hunantv"]),
    ("搜狐", ["sohu", "itc.cn"]),
    ("百度", ["baidu", "bdstatic", "bdimg", "mobads"]),
    ("夸克", ["quark", "alipay"]),
    ("UC浏览器", ["ucweb", "uc.cn", "uczzd"]),
    ("淘宝", ["taobao", "tbcdn", "tmall", "alicdn", "alimama"]),
    ("支付宝", ["alipay", "alipayobjects"]),
    ("京东", ["jd.com", "jdimg", "360buy", "union.jd"]),
    ("拼多多", ["pinduoduo", "pddcdn", "pddpic", "yangkeduo"]),
    ("美团", ["meituan", "meituan.net", "dianping"]),
    ("饿了么", ["ele.me", "elemecdn"]),
    ("高德地图", ["amap", "gaode"]),
    ("滴滴", ["didi", "xiaojukeji", "didiglobal"]),
    ("携程", ["ctrip", "trip.com", "qunar"]),
    ("网易", ["163.com", "netease", "126.net", "127.net"]),
    ("QQ音乐", ["y.qq.com", "qqmusic", "music.qq"]),
    ("酷狗音乐", ["kugou", "kglink"]),
    ("网易云音乐", ["music.163", "163cn"]),
    ("喜马拉雅", ["ximalaya", "xmcdn"]),
    ("WPS", ["wps.cn", "wps.com", "kingsoft", "kdocs"]),
    ("58同城", ["58.com", "58cdn", "ganji"]),
    ("闲鱼", ["goofish", "2.taobao"]),
    ("得物", ["dewu", "poizon"]),
    ("Keep", ["keep.com", "gotokeep"]),
    ("墨迹天气", ["moji", "mojichina"]),
    ("咪咕", ["migu", "cmvideo"]),
    ("唯品会", ["vip.com", "vipcdn"]),
    ("苏宁", ["suning", "suningcdn"]),
    ("汽车之家", ["autohome", "autohome.com"]),
    ("懂车帝", ["dongchedi", "snssdk"]),
    ("起点读书", ["qidian", "yue.qq"]),
    ("晋江文学", ["jjwxc", "jjwxc.net"]),
    ("世纪佳缘", ["zhenai", "jiayuan"]),
    ("BOSS直聘", ["zhipin", "bosszhipin"]),
    ("智联招聘", ["zhaopin", "zhaopin.com"]),
]

SDK_BUCKET = "通用广告与追踪SDK"
SDK_KEYS = ["pangle", "gromore", "csj", "gdt", "mintegral", "sigmob", "topon", "umeng",
            "talkingdata", "adjust", "appsflyer", "branch", "openinstall", "doubleclick",
            "googlesyndication", "google-analytics", "googletagmanager", "applovin",
            "unityads", "inmobi", "vungle", "chartboost", "ironsource", "adcolony",
            "tapjoy", "pubmatic", "rubicon", "criteo", "taboola", "outbrain", "openx",
            "adnxs", "moatads", "smartadserver", "adform", "growingio", "getui",
            "jpush", "igexin", "sensorsdata", "agora", "bugly"]


def main():
    domains = [l.strip() for l in open(os.path.join(DIST, "domains.txt"), encoding="utf-8") if l.strip()]
    white = [l.strip() for l in open(os.path.join(DIST, "whitelist.txt"), encoding="utf-8")
             if l.strip() and not l.startswith("#")]
    os.makedirs(OUT, exist_ok=True)
    buckets, assigned = {}, set()
    for name, keys in APPS:
        hit = []
        for d in domains:
            if d in assigned:
                continue
            low = d.lower()
            if any(k in low for k in keys):
                hit.append(d)
        buckets[name] = hit
        assigned |= set(hit)
    sdk = [d for d in domains if d not in assigned and any(k in d for k in SDK_KEYS)]
    assigned |= set(sdk)
    rest = [d for d in domains if d not in assigned]

    rows = []
    for name, hit in buckets.items():
        if not hit:
            continue
        with open(os.path.join(OUT, name + ".txt"), "w", encoding="utf-8") as f:
            f.write(f"# {name} 可拦截广告/追踪域名（{len(hit)} 条）\n")
            f.write("\n".join(sorted(hit)) + "\n")
        wl = [w for w in white if any(k in w.lower() for k in dict(APPS)[name])]
        if wl:
            with open(os.path.join(OUT, name + "_白名单.txt"), "w", encoding="utf-8") as f:
                f.write(f"# {name} 必须放行的业务主机（{len(wl)} 条，精确匹配）\n")
                f.write("\n".join(sorted(wl)) + "\n")
        rows.append((name, len(hit), len(wl)))

    with open(os.path.join(OUT, SDK_BUCKET + ".txt"), "w", encoding="utf-8") as f:
        f.write(f"# 广告 SDK / 监测 / 归因域名（{len(sdk)} 条）\n")
        f.write("\n".join(sorted(sdk)) + "\n")
    with open(os.path.join(OUT, "其他广告域名.txt"), "w", encoding="utf-8") as f:
        f.write(f"# 未能归到具体 App 的广告域名（{len(rest)} 条）\n")
        f.write("\n".join(sorted(rest)) + "\n")

    total = len(domains)
    md = ["# 国内 App 广告域名分类清单", "",
          f"拦截合计：{total} 条；归类覆盖：{len(assigned)} 条；未归类：{len(rest)} 条", "",
          "| App | 拦截条数 | 配套白名单 |", "| --- | --- | --- |"]
    for name, n, wn in sorted(rows, key=lambda x: -x[1]):
        md.append(f"| {name} | {n} | {wn} |")
    md += ["", f"| {SDK_BUCKET} | {len(sdk)} | - |", f"| 其他广告域名 | {len(rest)} | - |", ""]
    open(os.path.join(OUT, "汇总.md"), "w", encoding="utf-8").write("\n".join(md))
    print("\n".join(md[:6]))
    print(f"输出目录: {OUT}")


if __name__ == "__main__":
    main()
