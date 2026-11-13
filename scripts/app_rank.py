#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""抓国内热门 App 名单，并自动匹配它们的根域名。

名字来源：Apple 中国区免费榜（总榜 + 各分类，叠到 500 个去重 App）
域名来源：
  1) app_list.json 已有手工映射（优先）
  2) 拼音匹配：App 名转拼音，在上游域名池里找包含该拼音的根域
     （淘宝 → taobao.com，拼多多 → pinduoduo.com）
  3) 都没命中 → 不生成，交给通用 SDK 分组兜底

产出 app_list_auto.json：{"App名": ["root.com", ...]}
"""
import json
import os
import re
import urllib.request
import concurrent.futures as cf

try:
    from pypinyin import lazy_pinyin
except ImportError:
    lazy_pinyin = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_LIST = os.path.join(ROOT, "app_list.json")
AUTO_LIST = os.path.join(ROOT, "app_list_auto.json")
SRC_CACHE = os.path.join(ROOT, "src_cache")
TARGET = 500

GENRES = [6014, 6005, 6024, 6016, 6008, 6012, 6011, 6009, 6015, 6013,
          6017, 6020, 6018, 6023, 6000]

MULTI = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw"}


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "ignore")


def fetch_names():
    names = []

    def one(url):
        try:
            d = json.loads(get(url))
            return [x["im:name"]["label"].strip() for x in d["feed"]["entry"]]
        except Exception:
            return []

    urls = ["https://itunes.apple.com/cn/rss/topfreeapplications/limit=100/json"]
    urls += ["https://itunes.apple.com/cn/rss/topfreeapplications/limit=100/genre=%d/json" % g
             for g in GENRES]
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for lst in ex.map(one, urls):
            names.extend(lst)

    seen, uniq = set(), []
    for n in names:
        base = re.split(r"[-—:|（(]", n)[0].strip()
        if base and base not in seen:
            seen.add(base)
            uniq.append(base)
    return uniq[:TARGET]


def root_of(host):
    p = host.split(".")
    if len(p) < 2:
        return host
    if ".".join(p[-2:]) in MULTI and len(p) >= 3:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def load_pool():
    roots = set()
    if os.path.isdir(SRC_CACHE):
        for fn in os.listdir(SRC_CACHE):
            if not fn.endswith(".txt"):
                continue
            with open(os.path.join(SRC_CACHE, fn), encoding="utf-8", errors="ignore") as f:
                for line in f:
                    h = line.strip().lower()
                    if not h or h[0] in "#![":
                        continue
                    h = re.sub(r"^0\.0\.0\.0\s+|^127\.0\.0\.1\s+|^::1\s+", "", h)
                    h = h.replace("||", "").replace("^", "").strip(". ")
                    h = h.split("$")[0].split("/")[0]
                    if re.fullmatch(r"[a-z0-9.-]+", h) and "." in h and len(h) < 60:
                        roots.add(root_of(h))
    return roots


COMPANY = {
    "腾讯": ["qq.com", "tencent.com", "gtimg.cn"],
    "阿里": ["alibaba.com", "taobao.com", "tmall.com", "alipay.com", "aliyun.com"],
    "字节": ["douyin.com", "bytedance.com", "snssdk.com", "fqnovel.com"],
    "百度": ["baidu.com", "bdstatic.com", "bcebos.com"],
    "快手": ["kuaishou.com", "gifshow.com", "kwai.com"],
    "网易": ["163.com", "netease.com", "126.net"],
    "美团": ["meituan.com", "dianping.com"],
    "京东": ["jd.com", "360buy.com"],
    "拼多多": ["pinduoduo.com", "yangkeduo.com", "pddpic.com"],
    "小米": ["mi.com", "xiaomi.com"],
    "华为": ["huawei.com", "hicloud.com"],
    "携程": ["ctrip.com", "trip.com"],
    "微博": ["weibo.com", "sina.com.cn"],
    "哔哩哔哩": ["bilibili.com", "hdslb.com"],
    "知乎": ["zhihu.com"],
    "小红书": ["xiaohongshu.com", "xhscdn.com"],
    "滴滴": ["didiglobal.com", "xiaojukeji.com"],
    "爱奇艺": ["iqiyi.com", "iqiyipic.com"],
    "优酷": ["youku.com", "ykimg.com"],
    "芒果": ["mgtv.com", "hitv.com"],
}


def match(name, pool, known):
    if name in known:
        return known[name], "已知映射"

    # 名称里包含已知 App 名 → 继承它的域名（抖音商城 → 抖音）
    best = ""
    for k in known:
        if len(k) >= 2 and k in name and len(k) > len(best):
            best = k
    if best:
        return known[best], "名称继承(%s)" % best

    # 大厂关键词
    for company, roots in COMPANY.items():
        if company in name:
            hit = [r for r in roots if r in pool] or roots
            return hit[:3], "大厂(%s)" % company

    if not re.search(r"[\u4e00-\u9fff]", name):
        low = re.sub(r"[^a-z0-9]", "", name.lower())
        if len(low) >= 4:
            hit = sorted(r for r in pool if r.split(".")[0].startswith(low))
            if hit:
                return hit[:3], "英文名匹配"
        return [], ""

    if lazy_pinyin is None:
        return [], ""
    py = re.sub(r"[^a-z0-9]", "", "".join(lazy_pinyin(name)))
    if len(py) < 4:
        return [], ""
    # 收紧：根域首段必须以下列之一开头，避免零散命中
    hit = sorted(r for r in pool if r.split(".")[0].startswith(py)
                 or r.split(".")[0] == py or (len(py) >= 6 and py in r.split(".")[0]))
    if hit:
        return hit[:3], "拼音匹配"
    return [], ""


def main():
    print("拉取榜单...")
    names = fetch_names()
    print("去重后 App 名: %d" % len(names))

    known = {}
    if os.path.exists(APP_LIST):
        for k, v in json.load(open(APP_LIST, encoding="utf-8")).items():
            known[k] = v if isinstance(v, list) else [v]

    pool = load_pool()
    print("上游域名池根域: %d" % len(pool))

    auto, stats = {}, {}
    for n in names:
        roots, how = match(n, pool, known)
        if roots:
            auto[n] = roots
            stats[how] = stats.get(how, 0) + 1

    json.dump(auto, open(AUTO_LIST, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("匹配成功 %d / %d 个 App" % (len(auto), len(names)))
    print("明细:", stats)
    for n in names[:10]:
        print("  %-14s → %s" % (n, auto.get(n, "未匹配")))


if __name__ == "__main__":
    main()
