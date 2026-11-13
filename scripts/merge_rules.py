#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""星盾 / AD-QGG 规则构建脚本（可直接在 CI 里跑）

流程：
  1. 读 sources.txt 里的上游规则源（广告域名库）
  2. 解析成纯域名集合（兼容 AdGuard / hosts / 裸域名三种写法）
  3. 安全过滤：业务接口（api/passport/pay/cdn…）与品牌主域不进拦截，转为白名单
  4. 后缀压缩：父域已拦截的子域删掉，效果不变、体积和耗电下降
  5. 输出拦截：adguard.txt / domains.txt / hosts.txt
     输出白名单：whitelist.txt / whitelist_adguard.txt / whitelist_suffix.txt

用法：
  python3 scripts/merge_rules.py            # 联网拉源并构建
  python3 scripts/merge_rules.py --offline  # 只用本地缓存 src_cache/*.txt
"""
import os, re, sys, json, glob, time, urllib.request, datetime, collections
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "src_cache")
OUT = os.path.join(ROOT, "dist")
SOURCES = os.path.join(ROOT, "sources.txt")

AD_TOKENS = re.compile(
    r"(^|[.-])(ads?|adt|adx|adn|adsrv|adserv|adservice|adsdk|adimg|adlog|adstat|adtrack|adv|"
    r"adbanner|banner|pangle|gromore|track|tracker|logs?|stats?|analytics|metrics?|click|clk|"
    r"imp|impression|prom|promote|cpc|cmc|splash|sdk|report|dsp|ssp|union|aff|beacon|csj|gdt|"
    r"ksad|mmstat|mmachina)([.-]|$)", re.I)
CORE_API = re.compile(
    r"^(api|open|mapi|passport|pass|login|sso|pay|payments?|order|trade|update|upgrade|dl|"
    r"download|dns|ntp|mtalk|message|push|sync|config|conf|feed|search|living|live)([.-]|$)", re.I)
BIZ = re.compile(r"(img|pic|pics|cdn|static|res|asset|video|vod|pkg|oss|file|files|upload|"
                 r"download|dl|dbank|store|pay|mail|map|music|news|book|api|dns|gtimg|alicdn)", re.I)
LABEL_BAD = re.compile(r"(ad|ads|adx|adv|click|clk|track|trk|stat|banner|promo|imp|log|metric|"
                       r"sensor|analytic)", re.I)

BIG_BRANDS = set("""
tencent.com qq.com weixin.com alibaba.com taobao.com tmall.com alipay.com aliyun.com
jd.com pinduoduo.com meituan.com dianping.com ele.me xiaohongshu.com douyin.com
bytedance.com toutiao.com ixigua.com amemv.com snssdk.com kuaishou.com kwai.com
gifshow.com bilibili.com iqiyi.com youku.com mgtv.com sohu.com sina.com weibo.com
zhihu.com douban.com 163.com netease.com 126.com ctrip.com qunar.com didi.cn
xiaojukeji.com baidu.com bdstatic.com sogou.com 360.cn qhimg.com mi.com xiaomi.com
huawei.com honor.com oppo.com vivo.com realme.com oneplus.com wps.cn kingsoft.com
lianjia.com ke.com 58.com zhaopin.com 51job.com smzdm.com qiniu.com upyun.com
fqnovel.com novelquickapp.com hongguoduanju.com qznovel.com qzmanhua.com changdunovel.com gitee.com
""".split())

# 公认广告网络，上游缺失时也补上（DNS 层拦截它们不影响业务）
GLOBAL_AD = """
doubleclick.net googlesyndication.com googleadservices.com google-analytics.com
googletagmanager.com googletagservices.com applovin.com unityads.unity3d.com inmobi.com
vungle.com mintegral.com chartboost.com ironsource.com adcolony.com tapjoy.com
pubmatic.com rubiconproject.com criteo.com criteo.net taboola.com outbrain.com
openx.net casalemedia.com adnxs.com moatads.com smartadserver.com adform.net
""".split()

# 白名单兜底：大厂业务接口前缀（即使上游没有这些条目也放行）
WHITE_BASES = ["163.com", "qq.com", "weibo.com", "douyin.com", "amemv.com", "kuaishou.com",
               "taobao.com", "tmall.com", "jd.com", "pinduoduo.com", "meituan.com",
               "xiaohongshu.com", "bilibili.com", "iqiyi.com", "youku.com", "mgtv.com",
               "zhihu.com", "baidu.com", "mi.com", "huawei.com", "fqnovel.com",
               "novelquickapp.com", "hongguoduanju.com", "qznovel.com", "qzmanhua.com",
               "fqmanhua.com", "changdunovel.com", "douban.com", "ctrip.com", "dianping.com"]
WHITE_PREFIXES = ["api", "passport", "pay", "open", "m", "im", "live", "user", "order", "cdn", "message"]
CURATED = [
    "hongguoduanju.com", "www.hongguoduanju.com", "novelquickapp.com", "www.novelquickapp.com",
    "fqnovel.com", "www.fqnovel.com", "fqnovelvod.com", "fqmanhua.com", "fqmanhua.cn",
    "qznovel.com", "qznovelvod.com", "qzmanhua.com", "changdunovel.com",
    "douyin.com", "www.douyin.com", "amemv.com", "snssdk.com", "douyinpic.com",
    "douyinvod.com", "byteimg.com", "bytedance.net", "bytecdn.cn",
    "kuaishou.com", "gifshow.com", "kwai.com", "kwaicdn.com", "kuaishouapp.com",
    "bilibili.com", "hdslb.com", "bilivideo.com", "biliapi.net", "b23.tv",
    "xiaohongshu.com", "xhscdn.com", "weibo.com", "sinaimg.cn", "zhihu.com", "zhimg.com",
    "doubanio.com", "iqiyi.com", "iqiyi.cn", "youku.com", "mgtv.com",
    "qq.com", "gtimg.cn", "weixin.qq.com", "weixin.com", "wx.qlogo.cn",
    "taobao.com", "tmall.com", "alicdn.com", "alipay.com", "jd.com", "jdimg.com",
    "pinduoduo.com", "pddcdn.com", "pddpic.com", "meituan.com", "meituan.net",
    "dianping.com", "ele.me", "12306.cn", "163.com", "www.163.com", "baidu.com",
    "bdstatic.com", "mi.com", "huawei.com", "wps.cn", "ctrip.com", "58cdn.com",
    "360buyimg.com", "dbankcdn.com", "smzdm.com", "qcloud.com", "myqcloud.com",
    "lianjia.com", "ke.com", "zhaopin.com", "51job.com", "didi.cn", "xiaojukeji.com",
    "amap.com", "gaode.com", "qiniu.com", "aliyuncs.com", "sogou.com", "so.com",
    "360.cn", "360.com", "qhimg.com",
    "gitee.com", "www.gitee.com", "api.gitee.com", "raw.giteeusercontent.com",
    "giteeusercontent.com",
    "acs.m.taobao.com", "guide-acs.m.taobao.com",
]


def normalize(line):
    h = line.strip().lower()
    if not h or h.startswith("#") or h.startswith("!") or h.startswith("["):
        return None
    h = re.sub(r"^0\.0\.0\.0\s+|^127\.0\.0\.1\s+|^::1\s+", "", h)
    # Clash / Surge 风格：DOMAIN-SUFFIX,qq.com / DOMAIN,ad.x.com
    m = re.match(r"^(domain-suffix|domain|host|domain-wildcard)\s*,\s*(.*)$", h)
    if m:
        h = m.group(2).strip().lstrip(".")
    h = h.replace("||", "").replace("^", "").replace("@@", "").strip(". ")
    h = h.split("$")[0].split("/")[0].strip()
    if re.fullmatch(r"[a-z0-9.-]+", h) and "." in h and len(h) < 80:
        return h
    return None


def read_sources(offline=False):
    urls = []
    if os.path.exists(SOURCES):
        for l in open(SOURCES, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#"):
                urls.append(l)
    os.makedirs(CACHE, exist_ok=True)
    TTL = 6 * 3600          # 6 小时内不重复下载

    def fetch(i, u):
        fn = os.path.join(CACHE, f"src{i:02d}.txt")
        if offline:
            return [fn] if os.path.exists(fn) else []
        if os.path.exists(fn) and time.time() - os.path.getmtime(fn) < TTL:
            print(f"[源{i:02d}] 用缓存 {os.path.getsize(fn)} 字节")
            return [fn]
        for attempt in range(1, 4):          # 失败重试 3 次，退避 2s/4s
            try:
                req = urllib.request.Request(u, headers={"User-Agent": "AD-QGG-builder/1.0"})
                data = urllib.request.urlopen(req, timeout=90).read().decode("utf-8", "ignore")
                if not data.strip():
                    raise ValueError("空响应")
                open(fn, "w", encoding="utf-8").write(data)
                print(f"[源{i:02d}] {len(data)} 字符  {u}")
                return [fn]
            except Exception as e:
                print(f"[源{i:02d}] 第 {attempt} 次拉取失败: {str(e)[:60]}")
                time.sleep(2 * attempt)
        # 全部失败仍回落旧缓存（有总比没有强）
        if os.path.exists(fn):
            print(f"[源{i:02d}] 回落到旧缓存")
            return [fn]
        print(f"[源{i:02d}][警告] 无可用数据，本源跳过: {u}")
        return []

    # 并发拉取，15 个源从「串行 ~2 分钟」降到几秒
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda p: fetch(*p), list(enumerate(urls))))
    files = [f for r in results for f in r]
    return files


def parse(files):
    block = set()
    support = {}          # 域名 -> 收录它的源数量
    for f in files:
        seen_here = set()
        for line in open(f, encoding="utf-8", errors="ignore"):
            if "@@" in line:        # 源内条件式放行（$domain=），DNS 层无法按条件生效，忽略
                continue
            h = normalize(line)
            if h:
                block.add(h)
                seen_here.add(h)
        for h in seen_here:
            support[h] = support.get(h, 0) + 1
    block |= {h for h in GLOBAL_AD if "." in h}
    # 自建补充清单（仓库内维护，随源一起并入）
    custom = os.path.join(ROOT, "custom.txt")
    if os.path.exists(custom):
        for line in open(custom, encoding="utf-8", errors="ignore"):
            h = normalize(line)
            if h:
                block.add(h)
    global SOURCE_SUPPORT
    SOURCE_SUPPORT = support
    return block


SOURCE_SUPPORT = {}


def build(block):
    # 安全过滤：业务接口 / 品牌主域 → 白名单，不进拦截
    def adish(h):
        return bool(re.search(r"(^|[.-])ads?", h, re.I)) or "ad" in h.replace(".", "")

    rescue, kept = set(), set()
    for h in block:
        # 只救"我们已知是业务接口"的域名，不让新源里的随机垃圾混进白名单
        if h in CURATED or h in BIG_BRANDS:
            if not AD_TOKENS.search(h) and not adish(h):
                rescue.add(h)
            continue
        if CORE_API.match(h) and not AD_TOKENS.search(h) and not adish(h):
            # 单标签业务域只在已知大厂白名单里才救
            if h.count(".") == 1 and h in BIG_BRANDS:
                rescue.add(h)
                continue
        kept.add(h)
    kept -= rescue

    # 硬放行：仅订阅源本身永不拦截（baidu 等大厂广告子域不再整域放行，否则 mobads/eclick 等广告域名漏拦）
    KEEP_ALIVE = ["gitee.com", "giteeusercontent.com", "gitee.io"]
    kept = {h for h in kept if not any(h == base or h.endswith("." + base) for base in KEEP_ALIVE)}

    # 大厂内容 CDN 主域禁止"整域"拦截：这些主域承载图片/音频资源，整域封会直接让 App 加载失败。
    # 只剔除裸主域本身，其下确实带广告特征的子域仍然保留拦截。
    APEX_NEVER_BLOCK = {"126.net", "127.net", "bdimg.com", "bdstatic.com",
                        "alicdn.com", "gtimg.cn", "sinaimg.cn", "qpic.cn"}
    dropped_apex = kept & APEX_NEVER_BLOCK
    if dropped_apex:
        print("[保护] 剔除整域拦截的内容CDN主域: %s" % sorted(dropped_apex))
        kept -= dropped_apex

    # 清洗：只保留合法域名（字母数字开头、含点、无 - 开头的脏行）
    import re as _re
    DOMAIN_RE = _re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    kept = {h for h in kept if DOMAIN_RE.match(h)}

    # 只保留热门 App 与主流广告 SDK 的拦截，冷门长尾一律丢弃
    POPULAR = set("""
bytedance.com douyin.com toutiao.com ixigua.com amemv.com snssdk.com zijieapi.com pangle.io
pangolin-sdk-toutiao.com csjplatform.com csj.com fenbi.com
tencent.com qq.com weixin.com wechat.com qq.com gdt.qq.com e.qq.com gtimg.com qlogo.cn
gdtimg.com ugdtimg.com gtimg.cn
baidustatic.com bcebos.com
bytecdn.cn ctobsnssdk.com byteadverts.com
adkwai.com adukwai.com
alibaba.com taobao.com tmall.com alipay.com alimama.com aliyun.com tanx.com
jd.com jd.hk 360buyimg.com pinduoduo.com pddpic.com pddcdn.com
meituan.com dianping.com ele.me meituan.net
xiaohongshu.com xhscdn.com xiaohongshu.com
kuaishou.com kuaishouzt.com gifshow.com kwai.com kwcdn.com
bilibili.com hdslb.com bilivideo.com biliapi.net b23.tv
iqiyi.com qiyi.com iqiyipic.com youku.com ykimg.com mgtv.com hunantv.com
sina.com weibo.com sinaimg.cn zhihu.com zhimg.com douban.com doubanio.com
baidu.com bdstatic.com bdimg.com baidubcs.com sogou.com so.com
163.com netease.com 126.net 127.net music.163.com
ximalaya.com xmcdn.com kugou.com kugou.com qianqian.com
wps.cn wps.com kingsoft.com kdocs.cn
58.com 58.com 58cdn.com ganji.com lianjia.com ke.com
ctrip.com qunar.com didi.cn xiaojukeji.com amap.com gaode.com
mi.com xiaomi.com huawei.com honor.com oppo.com vivo.com realme.com
fqnovel.com novelquickapp.com hongguoduanju.com qznovel.com qzmanhua.com
fqmanhua.com changdunovel.com fanqienovel.com fanqie.com qznovelvod.com
smzdm.com zhaopin.com 51job.com zhipin.com gof.cn
ele.me meituan.com taopiaopiao.com
vip.com vipcdn.com suning.com suning.com
autohome.com dongchedi.com dongchedi.com
keep.com gotokeep.com moji.com mojichina.com
migu.com cmvideo.cn weibo.com
""".split())
    SDK_NET = set("""pangle.io gromore.com mintegral.com sigmob.com toponad.com
umeng.com umengcloud.com talkingdata.com adjust.com appsflyer.com
branch.io openinstall.io admob.com doubleclick.net googlesyndication.com
googleadservices.com google-analytics.com googletagmanager.com
applovin.com unityads.unity3d.com inmobi.com vungle.com chartboost.com
ironsource.com adcolony.com tapjoy.com pubmatic.com rubiconproject.com
criteo.com criteo.net taboola.com outbrain.com openx.net casalemedia.com
adnxs.com moatads.com smartadserver.com adform.net growingio.com
getui.com igexin.com jpush.cn sensorsdata.cn bugly.qq.com
tanx.com alimama.com cpro.baidu.com pos.baidu.com admaster.cn
domob.cn tuia.cn sigmob.cn toponad.com tradplusad.com
dmp.163.com.ad td.toutiao.com sf3g.com pglstatp-toutiao.com
""".split())
    def keep_popular(h: str) -> bool:
        for base in POPULAR:
            if h == base or h.endswith("." + base):
                return True
        for net in SDK_NET:
            if h == net or h.endswith("." + net):
                return True
        # 明显是广告/监测/归因标签的域名也保留（ad.* / track.* / analytics.* 等）
        return bool(AD_TOKENS.search(h))
    kept = {h for h in kept if keep_popular(h)}

    # 后缀压缩（O(labels) 哈希查表）
    blocked = set()
    for h in sorted(kept, key=lambda x: (x.count("."), len(x))):
        rest, covered = h, False
        while True:
            i = rest.find(".")
            if i < 0:
                break
            rest = rest[i + 1:]
            if rest in blocked:
                covered = True
                break
        if not covered:
            blocked.add(h)

    # 每个厂商/广告 SDK 最多保留 300 条，避免一家把库撑爆
    def vendor_of(h: str) -> str:
        for base in POPULAR:
            if h == base or h.endswith("." + base):
                return base
        for net in SDK_NET:
            if h == net or h.endswith("." + net):
                return "SDK:" + net
        return "GENERIC"
    groups = {}
    for h in blocked:
        groups.setdefault(vendor_of(h), []).append(h)
    capped = set()
    for v, arr in groups.items():
        arr.sort(key=lambda x: (x.count("."), len(x)))
        capped.update(arr[:300])
    blocked = capped

    # 共识补充：多家独立上游都收录的域名，即使没有广告特征词也纳入（上限 6000）
    # 只补没有被白名单/业务接口保护的，且至少有 2 家源支持
    TARGET = 6010
    consensus = sorted((h for h, n in SOURCE_SUPPORT.items() if n >= 2),
                       key=lambda h: (-SOURCE_SUPPORT[h], h.count("."), len(h)))
    if len(blocked) < TARGET:
        for h in consensus:
            if len(blocked) >= TARGET:
                break
            if h in blocked or h in rescue or h in CURATED:
                continue
            if CORE_API.match(h) and not AD_TOKENS.search(h):
                continue
            if any(h == b or h.endswith("." + b) for b in APEX_NEVER_BLOCK):
                continue
            blocked.add(h)
        print("[合并] 共识补充后规则数: %d" % len(blocked))

    # 白名单
    def ad_like(h):
        return bool(AD_TOKENS.search(h)) or any(LABEL_BAD.search(l) for l in h.split("."))

    white = {h for h in CURATED if "." in h}
    white |= {h for h in rescue if h.count(".") <= 3}
    # 读仓库已有 whitelist.txt 作为基础白名单，避免重建时丢掉历史积累
    existing_wl = os.path.join(ROOT, "whitelist.txt")
    if os.path.exists(existing_wl):
        for line in open(existing_wl, encoding="utf-8", errors="ignore"):
            h = line.strip().lower()
            if h and not h.startswith("#") and "." in h:
                white.add(h)
    white |= {p + "." + b for b in WHITE_BASES for p in WHITE_PREFIXES}
    white = {h for h in white if not ad_like(h)}
    blocked -= white  # 白名单中的域名从拦截列表中剔除（如 acs.m.taobao.com）

    # 后缀白名单：主域下没有被拦子域才可 *. 放行
    ancestors = set()
    for h in blocked:
        rest = h
        while True:
            i = rest.find(".")
            if i < 0:
                break
            rest = rest[i + 1:]
            ancestors.add(rest)
    bases = [b for b in CURATED if b.count(".") == 1]
    suffix_ok = [b for b in sorted(set(bases)) if b not in ancestors]
    suffix_exact = [b for b in sorted(set(bases)) if b in ancestors]
    return blocked, sorted(white), suffix_ok, suffix_exact


def per_company_stats(blocked):
    """按公司粗分统计，用于构建报告。"""
    groups = [
        ("字节/抖音/红果", ["bytedance.com","douyin.com","toutiao.com","ixigua.com","amemv.com","snssdk.com",
                          "zijieapi.com","pangle.io","pangolin","csj","fqnovel","qznovel","qzmanhua",
                          "hongguoduanju","novelquickapp","changdunovel","bytecdn","byteimg","byteadverts",
                          "douyinpic","douyinvod","ctobsnssdk"]),
        ("腾讯/微信/QQ", ["qq.com","gtimg","qlogo","weixin","wechat","gdt","ugdtimg","qzone"]),
        ("快手", ["kuaishou","gifshow","kwai","kwcdn","ksad","adkwai","adukwai"]),
        ("阿里/淘宝", ["alibaba","taobao","tmall","alipay","alimama","aliyun","tanx","alicdn"]),
        ("百度", ["baidu","bdstatic","bdimg","baidubcs","bcebos","sogou"]),
        ("拼多多", ["pdd","pinduoduo","yangkeduo"]),
        ("京东", ["jd.com","360buy"]),
        ("美团/饿了么", ["meituan","dianping","ele.me","maoyan","taopiaopiao"]),
        ("小红书", ["xiaohongshu","xhs","xhscdn"]),
        ("B站", ["bilibili","hdslb","bilivideo","b23"]),
        ("微博", ["weibo","sina","sinaimg"]),
        ("知乎", ["zhihu","zhimg"]),
        ("长视频", ["iqiyi","qiyi","youku","ykimg","mgtv","hunantv"]),
        ("地图出行", ["amap","gaode","didi","xiaojukeji","ctrip","qunar","fliggy"]),
        ("厂商商店", ["mi.com","xiaomi","huawei","honor","oppo","vivo","realme","oneplus"]),
    ]
    rows = []
    for name, kws in groups:
        c = sum(1 for h in blocked if any(k in h for k in kws))
        if c:
            rows.append((name, c))
    rows.sort(key=lambda x: -x[1])
    return rows



def _save(path, content):
    """内容与磁盘一致时不重写，减少无意义变更。"""
    try:
        if open(path, encoding="utf-8").read() == content:
            return False
    except OSError:
        pass
    open(path, "w", encoding="utf-8").write(content)
    return True

def write(blocked, white, suffix_ok, suffix_exact):
    os.makedirs(OUT, exist_ok=True)
    ver = datetime.datetime.now().strftime("%Y%m%d")
    n = len(blocked)

    # 健康检查 1：上游抽风时不要把规则清空
    if n < 1000:
        print(f"[警告] 本次只生成 {n} 条规则，低于安全线 1000，拒绝覆盖已有文件")
        sys.exit(2)

    # 健康检查 2：自己的仓库域名不能被拦
    leaked = [h for h in blocked if "gitee.com" in h or "giteeusercontent" in h]
    if leaked:
        print(f"[警告] 仓库域名被误拦: {leaked[:3]}，自动剔除")
        blocked = {h for h in blocked if h not in leaked}
        n = len(blocked)

    # 健康检查 3：白名单不能和拦截重叠
    white_set = set(white)
    overlap = blocked & white_set
    if overlap:
        print(f"[警告] 白名单与拦截重叠 {len(overlap)} 条，从拦截中剔除")
        blocked -= overlap
        n = len(blocked)

    hosts_note = "AD-QGG 国内热门App广告拦截（多源合并 + 配套白名单）"

    adg = [f"! Title: {hosts_note}",
           "! Description: 主接口切断——广告/监测/统计/SDK/推送域名；业务接口与品牌主域转白名单保护",
           f"! Version: {ver}", "! Expires: 1 day",
           "! Homepage: https://github.com/o0001e/ad-rules",
           f"! 拦截条数: {n}",
           "! 配套白名单: whitelist.txt / whitelist_adguard.txt", ""]
    adg += ["||" + h + "^" for h in sorted(blocked)]
    _save(os.path.join(OUT, "adguard.txt"), "\n".join(adg) + "\n")
    _save(os.path.join(OUT, "domains.txt"), "\n".join(sorted(blocked)) + "\n")

    # Lite 版：只保留国内厂商 + .cn 域名，给手机 DNS 订阅用（条数少、解析快）
    def root_of(d):
        parts = d.split(".")
        if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "gov") and parts[-1] == "cn":
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else d

    domestic_roots = set()
    try:
        for v in json.load(open(os.path.join(ROOT, "app_list.json"), encoding="utf-8")).values():
            for h in (v if isinstance(v, list) else [v]):
                domestic_roots.add(h.strip().lower())
    except Exception:
        pass
    domestic_roots |= {b.lower() for b in BIG_BRANDS}
    lite = {h for h in blocked if root_of(h) in domestic_roots or h.endswith(".cn")}
    _save(os.path.join(OUT, "lite.txt"),
          "# AD-QGG Lite（仅国内厂商域名）\n# Version: %s\n" % ver +
          "\n".join("0.0.0.0 " + h for h in sorted(lite)) + "\n")
    _save(os.path.join(OUT, "lite_domains.txt"), "\n".join(sorted(lite)) + "\n")
    print("[Lite] 国内域名 %d 条（占全量 %.0f%%）" % (len(lite), len(lite) * 100.0 / max(n, 1)))
    open(os.path.join(OUT, "hosts.txt"), "w", encoding="utf-8").write(
        "\n".join([f"# AD-QGG hosts {ver} 条数: {n}"] + ["0.0.0.0 " + h for h in sorted(blocked)]) + "\n")

    open(os.path.join(OUT, "whitelist.txt"), "w", encoding="utf-8").write(
        "\n".join(["# 配套白名单（精确放行：只放行该主机，广告子域仍被拦）",
                   f"# 条数: {len(white)}", ""] + white) + "\n")
    open(os.path.join(OUT, "whitelist_adguard.txt"), "w", encoding="utf-8").write(
        "\n".join([f"! 白名单 {len(white)} 条，@@|主机^ 精确匹配，不放行子域", ""] +
                  ["@@|" + h + "^" for h in white]) + "\n")
    sfx = [f"# 可后缀放行主域（{len(suffix_ok)} 条）：无被拦广告子域，可写 *.域名", ""]
    sfx += ["*." + b for b in suffix_ok]
    sfx += ["", f"# 必须精确放行主域（{len(suffix_exact)} 条）：有广告子域被拦，禁止写 *.", ""]
    sfx += ["# " + b for b in suffix_exact]
    open(os.path.join(OUT, "whitelist_suffix.txt"), "w", encoding="utf-8").write("\n".join(sfx) + "\n")

    rep = [f"规则版本: {ver}", f"拦截域名: {n}", f"白名单: {len(white)}",
           f"可后缀放行: {len(suffix_ok)}", f"必须精确放行: {len(suffix_exact)}", ""]
    rep.append("== 分公司覆盖 ==")
    for name, cnt in per_company_stats(blocked):
        rep.append(f"  {name}: {cnt}")
    open(os.path.join(OUT, "build_report.txt"), "w", encoding="utf-8").write("\n".join(rep) + "\n")
    print("\n".join(rep))


if __name__ == "__main__":
    offline = "--offline" in sys.argv
    files = read_sources(offline)
    if not files:
        sys.exit("没有可用的规则源")
    blocked, white, suffix_ok, suffix_exact = build(parse(files))
    write(blocked, white, suffix_ok, suffix_exact)
