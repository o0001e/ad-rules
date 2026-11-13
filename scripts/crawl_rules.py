#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自建抓取：DNS 字典爆破 + 证书透明日志，只保留真实存在的子域。
红果短剧/漫剧：全部子域拦截。
其他热门 App：只保留广告/埋点类子域，按热度排序，每家最多 100 条。
输出到 .publish/{d,a,h,w}。
"""
import concurrent.futures as cf
import json
import os
import re
import socket
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUB = os.path.join(ROOT, ".publish")

# 保证能导入同目录下的 gen_apps
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 热度顺序（靠前优先保留）
HEAT = [
    "红果短剧", "红果漫剧",
    "字节-抖音", "今日头条", "番茄小说",
    "快手", "腾讯-微信", "腾讯广告", "腾讯视频",
    "阿里巴巴", "支付宝", "淘宝联盟",
    "京东", "京东联盟", "拼多多", "美团", "饿了么",
    "小红书", "哔哩哔哩", "爱奇艺", "优酷", "芒果TV",
    "微博", "百度", "知乎", "网易", "网易云音乐", "QQ音乐", "酷狗音乐",
    "喜马拉雅", "WPS", "58同城", "贝壳找房", "携程", "去哪儿",
    "滴滴", "高德", "小米", "华为", "OPPO", "vivo", "荣耀",
    "咪咕", "汽车之家", "懂车帝", "闲鱼", "得物", "唯品会", "苏宁",
    "Keep", "墨迹天气", "起点读书", "晋江文学", "BOSS直聘", "智联招聘",
    "大众点评", "豆瓣",
]

# 从 app_list.json 加载App列表（如果存在），否则用内置默认列表
DEFAULT_COMPANIES = {
    "红果短剧": ["fqnovel.com", "novelquickapp.com", "hongguoduanju.com", "fqnovelvod.com", "qznovel.com", "qznovelvod.com"],
    "红果漫剧": ["fqmanhua.com", "fqmanhua.cn", "qzmanhua.com", "changdunovel.com"],
    "字节-抖音": ["douyin.com", "bytedance.com", "amemv.com", "snssdk.com", "pangle.io", "gromore.com", "csjplatform.com", "pangolin-sdk-toutiao.com"],
    "今日头条": ["toutiao.com", "ixigua.com"],
    "番茄小说": ["fanqienovel.com", "fanqie.com"],
    "快手": ["kuaishou.com", "gifshow.com", "kwai.com", "kuaishouzt.com", "kwcdn.com"],
    "腾讯-微信": ["weixin.com", "wechat.com"],
    "腾讯广告": ["gdt.qq.com", "e.qq.com"],
    "腾讯视频": ["v.qq.com"],
    "阿里巴巴": ["taobao.com", "tmall.com", "alibaba.com", "alicdn.com"],
    "支付宝": ["alipay.com", "alipayobjects.com"],
    "淘宝联盟": ["alimama.com"],
    "京东": ["jd.com", "360buyimg.com"],
    "京东联盟": ["union.jd.com"],
    "拼多多": ["pinduoduo.com", "pddpic.com", "pddcdn.com", "yangkeduo.com"],
    "美团": ["meituan.com", "meituan.net", "dianping.com"],
    "饿了么": ["ele.me", "elemecdn.com"],
    "小红书": ["xiaohongshu.com", "xhscdn.com"],
    "哔哩哔哩": ["bilibili.com", "hdslb.com", "bilivideo.com", "biliapi.net"],
    "爱奇艺": ["iqiyi.com", "qiyi.com", "iqiyipic.com"],
    "优酷": ["youku.com", "ykimg.com"],
    "芒果TV": ["mgtv.com", "hunantv.com"],
    "微博": ["weibo.com", "sina.com", "sinaimg.cn"],
    "百度": ["baidu.com", "bdstatic.com", "bdimg.com"],
    "知乎": ["zhihu.com", "zhimg.com"],
    "网易": ["163.com", "netease.com", "126.net", "127.net"],
    "网易云音乐": ["music.163.com"],
    "QQ音乐": ["y.qq.com", "qqmusic.com"],
    "酷狗音乐": ["kugou.com", "kglink.com"],
    "喜马拉雅": ["ximalaya.com", "xmcdn.com"],
    "WPS": ["wps.cn", "wps.com", "kingsoft.com", "kdocs.cn"],
    "58同城": ["58.com", "58cdn.com", "ganji.com"],
    "贝壳找房": ["ke.com", "lianjia.com"],
    "携程": ["ctrip.com", "qunar.com", "trip.com"],
    "去哪儿": ["qunar.com"],
    "滴滴": ["didi.cn", "xiaojukeji.com", "didiglobal.com"],
    "高德": ["amap.com", "gaode.com"],
    "小米": ["mi.com", "xiaomi.com", "miui.com"],
    "华为": ["huawei.com", "honor.com", "hicloud.com"],
    "OPPO": ["oppo.com", "coloros.com"],
    "vivo": ["vivo.com", "iqoo.com"],
    "荣耀": ["honor.com"],
    "咪咕": ["migu.com", "cmvideo.cn"],
    "汽车之家": ["autohome.com"],
    "懂车帝": ["dongchedi.com"],
    "闲鱼": ["goofish.com"],
    "得物": ["dewu.com", "poizon.com"],
    "唯品会": ["vip.com", "vipcdn.com"],
    "苏宁": ["suning.com"],
    "Keep": ["keep.com", "gotokeep.com"],
    "墨迹天气": ["moji.com", "mojichina.com"],
    "起点读书": ["qidian.com"],
    "晋江文学": ["jjwxc.net"],
    "BOSS直聘": ["zhipin.com"],
    "智联招聘": ["zhaopin.com"],
    "大众点评": ["dianping.com"],
    "豆瓣": ["douban.com", "doubanio.com"],
}

# 加载 app_list.json（如果存在），否则用默认列表
app_list_path = os.path.join(ROOT, "app_list.json")
if os.path.exists(app_list_path):
    try:
        import json as _json
        COMPANIES = _json.load(open(app_list_path, encoding="utf-8"))
        print(f"[加载] app_list.json: {len(COMPANIES)} 个App")
    except Exception as e:
        print(f"[警告] app_list.json 加载失败({e})，使用默认列表")
        COMPANIES = DEFAULT_COMPANIES
else:
    COMPANIES = DEFAULT_COMPANIES
    print(f"[加载] 默认列表: {len(COMPANIES)} 个App")

# 爆破字典：广告/埋点/SDK 常见前缀
AD_WORDS = ["ad", "ads", "adx", "adn", "adapi", "ad-api", "adsdk", "adservice",
            "adimg", "adlog", "adstat", "adtrack", "adbanner", "adclick", "adcache",
            "adbid", "adplay", "adsys", "adengine", "adsrv", "adserver", "adview",
            "pangle", "pangolin", "gromore", "csj", "gdt", "union", "ssp", "dsp",
            "track", "tracker", "tracklog", "tracking", "log", "logs", "logdata",
            "stat", "stats", "statistic", "analytics", "metric", "metrics",
            "monitor", "beacon", "sensor", "report", "reports", "click", "clk",
            "impression", "exposure", "promote", "promotion", "promo", "banner",
            "splash", "sdk", "mobads", "cpro", "adm", "adnet", "adunion",
            "config", "cfg", "setting", "abtest", "experiment",
            "req", "request", "cgi", "api-ad", "api.ads", "inner-ad",
            "ad1", "ad2", "ad3", "ad-test", "ad-stg", "ad-uat", "ad-online",
            "adcdn", "adhost", "adimp", "adevent", "adfloat", "adfeed",
            "adpop", "adpush", "adslot", "adunit", "adzone", "adview",
            "adjs", "adcss", "adstatic", "adres", "adimg2", "adimg3",
            "track1", "track2", "log1", "log2", "stat1", "stat2",
            "report1", "report2", "beacon1", "beacon2",
            "ad-sdk", "ad-sdk-test", "ad-sdk-online", "ad-sdk-prod",
            "ad-prod", "ad-online1", "ad-online2", "ad-cn", "ad-us",
            "ads-cn", "ads-us", "ad-cdn", "ad-cdn1", "ad-cdn2",
            "ad-img", "ad-img1", "ad-img2", "ad-video", "ad-video1",
            "ad-media", "ad-res", "ad-res1", "ad-res2",
            "ad-analytics", "ad-monitor", "ad-track", "ad-tracker",
            "ad-exposure", "ad-impression", "ad-click", "ad-click1",
            "ad-banner", "ad-splash", "ad-feed", "ad-inter",
            "ad-reward", "ad-video-ad", "ad-native", "ad-banner-ad",
            "union-ad", "union-sdk", "union-log", "union-track",
            "union-report", "union-stat", "union-config",
            "ssp-ad", "dsp-ad", "ad-ssp", "ad-dsp",
            "gdt-ad", "gdt-log", "gdt-track", "gdt-report",
            "csj-ad", "csj-log", "csj-track", "csj-report",
            "pangle-ad", "pangle-log", "pangle-track", "pangle-report",
            "gromore-ad", "gromore-log", "gromore-track",
            "tt-ad", "tt-log", "tt-track", "tt-report", "tt-config",
            "ks-ad", "ks-log", "ks-track", "ks-report",
            "wx-ad", "wx-log", "wx-track",
            "qq-ad", "qq-log", "qq-track",
            "bd-ad", "bd-log", "bd-track", "bd-report",
            "ali-ad", "ali-log", "ali-track",
            "tx-ad", "tx-log", "tx-track",
            "wb-ad", "wb-log", "wb-track",
            "bili-ad", "bili-log", "bili-track",
            "iqiyi-ad", "iqiyi-log", "iqiyi-track",
            "youku-ad", "youku-log", "youku-track",
            "mg-ad", "mg-log", "mg-track",
            "xhs-ad", "xhs-log", "xhs-track",
            "pdd-ad", "pdd-log", "pdd-track",
            "jd-ad", "jd-log", "jd-track",
            "mt-ad", "mt-log", "mt-track",
            "meituan-ad", "meituan-log", "meituan-track",
            "ele-ad", "ele-log", "ele-track",
            "ximalaya-ad", "ximalaya-log", "ximalaya-track",
            "wps-ad", "wps-log", "wps-track",
            "mi-ad", "mi-log", "mi-track",
            "hw-ad", "hw-log", "hw-track",
            "oppo-ad", "oppo-log", "oppo-track",
            "vivo-ad", "vivo-log", "vivo-track",
            "sn-ad", "sn-log", "sn-track",
            "ctrip-ad", "ctrip-log", "ctrip-track",
            "didi-ad", "didi-log", "didi-track",
            "amap-ad", "amap-log", "amap-track",
            "zhipin-ad", "zhipin-log", "zhipin-track",
            "autohome-ad", "autohome-log", "autohome-track",
            "dongchedi-ad", "dongchedi-log", "dongchedi-track",
            "dewu-ad", "dewu-log", "dewu-track",
            "keep-ad", "keep-log", "keep-track",
            "moji-ad", "moji-log", "moji-track",
            "qidian-ad", "qidian-log", "qidian-track",
            "jjwxc-ad", "jjwxc-log", "jjwxc-track",
            "58-ad", "58-log", "58-track",
            "ke-ad", "ke-log", "ke-track",
            "ct-ad", "ct-log", "ct-track",
            "qunar-ad", "qunar-log", "qunar-track",
            "weibo-ad", "weibo-log", "weibo-track",
            "zhihu-ad", "zhihu-log", "zhihu-track",
            "douban-ad", "douban-log", "douban-track",
            "netease-ad", "netease-log", "netease-track",
            "music-ad", "music-log", "music-track",
            "qqmusic-ad", "qqmusic-log", "qqmusic-track",
            "kugou-ad", "kugou-log", "kugou-track",
            "suning-ad", "suning-log", "suning-track",
            "vip-ad", "vip-log", "vip-track",
            "honor-ad", "honor-log", "honor-track",
            "migu-ad", "migu-log", "migu-track",
            "qznovel-ad", "qznovel-log", "qznovel-track",
            "fqnovel-ad", "fqnovel-log", "fqnovel-track",
            "fqmanhua-ad", "fqmanhua-log", "fqmanhua-track",
            "fanqie-ad", "fanqie-log", "fanqie-track",
            "douyin-ad", "douyin-log", "douyin-track",
            "toutiao-ad", "toutiao-log", "toutiao-track",
            "ixigua-ad", "ixigua-log", "ixigua-track",
            "kuaishou-ad", "kuaishou-log", "kuaishou-track",
            "bilibili-ad2", "iqiyi-ad2", "youku-ad2",
            "mgtv-ad2", "weibo-ad2", "zhihu-ad2",
            "163-ad", "163-log", "163-track",
            "126-ad", "126-log", "126-track",
            "127-ad", "127-log", "127-track",
            "taobao-ad", "taobao-log", "taobao-track",
            "tmall-ad", "tmall-log", "tmall-track",
            "alipay-ad", "alipay-log", "alipay-track",
            "alimama-ad", "alimama-log", "alimama-track",
            "jd-ad2", "pdd-ad2", "meituan-ad2",
            "eleme-ad", "eleme-log", "eleme-track",
            "xhs-ad2", "hdslb-ad", "hdslb-log",
            "iqiyipic-ad", "ykimg-ad", "sinaimg-ad",
            "zhimg-ad", "doubanio-ad", "alicdn-ad",
            "360buyimg-ad", "pddpic-ad", "pddcdn-ad",
            "kwcdn-ad", "kglink-ad", "xmcdn-ad",
            "58cdn-ad", "suningcdn-ad", "vipcdn-ad",
            "elemecdn-ad", "xhscdn-ad", "biliapi-ad",
            "bilivideo-ad", "iqiyipic-log", "ykimg-log",
            "sinaimg-log", "zhimg-log", "doubanio-log",
            "alicdn-log", "360buyimg-log", "pddpic-log",
            "pddcdn-log", "kwcdn-log", "kglink-log",
            "xmcdn-log", "58cdn-log", "suningcdn-log",
            "vipcdn-log", "elemecdn-log", "xhscdn-log",
            "biliapi-log", "bilivideo-log"]

# 通用广告词：对每个根域都爆破。真正高频命中的就是这一批。
CORE_WORDS = ["ad", "ads", "adx", "adn", "adapi", "ad-api", "adsdk", "adservice", "adimg",
              "adlog", "adstat", "adtrack", "track", "tracker", "tracklog", "log", "logs",
              "stat", "stats", "analytics", "metric", "monitor", "beacon", "report", "click",
              "clk", "impression", "exposure", "promote", "promo", "banner", "splash", "sdk",
              "union", "dsp", "ssp", "pangle", "pangolin", "gromore", "csj", "gdt",
              "adslot", "adunit", "adzone", "adfeed", "adpop", "adpush", "adcdn", "adimg2",
              "log1", "log2", "stat1", "track1", "report1", "beacon1"]


def word_applies(word, apex):
    """品牌专属词只用于对应品牌的根域，避免产生大量无意义的无效候选。"""
    if word in CORE_WORDS:
        return True
    label = apex.split(".")[0].lower()
    base = word.lower()
    for suf in ("-ad2", "-log2", "-track2", "-report2", "-ad", "-log", "-track", "-report", "-config"):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    return base in label or label in base or label in word.lower()


# 业务主域白名单前缀（永不拦截）
BIZ_WORDS = ["www", "m", "api", "cdn", "static", "res", "img", "pic", "image",
             "video", "vod", "download", "passport", "login", "pay", "order",
             "im", "live", "open", "user", "message", "push", "search", "feed",
             "book", "music", "map", "home", "main", "app", "wap", "web",
             "help", "about", "mail", "smtp", "ns1", "ns2", "dns", "o", "sso"]

AD_RE = re.compile(r"(^|[.-])(ads?|adx|adn|adsdk|adimg|adlog|adstat|adtrack|adbanner|"
                   r"adclick|adcache|adbid|adapi|adservice|adsrv|adserver|adview|"
                   r"pangle|pangolin|gromore|csj|gdt|union|dsp|ssp|track|tracker|"
                   r"tracklog|log|stat|stats|analytics|metric|monitor|beacon|sensor|"
                   r"report|click|clk|impression|exposure|promote|promotion|promo|"
                   r"banner|splash|sdk|mobads|cpro|adm|adnet|adunion)([.-]|$)", re.I)


def is_wildcard(apex):
    """通配检测：随机子域能解析说明该主域是通配，字典爆破会产出大量假域名。"""
    import random
    import string
    tag = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    probe = "zz%s%d.%s" % (tag, random.randint(1, 9999), apex)
    return resolvable(probe, timeout=2.0)


# ---------------- DNS 校验（DoH 优先，带结果缓存） ----------------
# 本地/CI 的系统 DNS 经常不可靠（容器内 resolv.conf 指向内网地址时会整体判死），
# 所以优先用阿里云公共 DoH，失败再退回系统解析。结果写盘缓存，减少重复探测。
DOH_URL = "https://dns.alidns.com/resolve"
CACHE_FILE = os.path.join(PUB, "dns_cache.json")
DEAD_TTL = 7 * 86400      # 判定死的域名 7 天内不重复探测
ALIVE_TTL = 20 * 3600     # 判定活的域名 20 小时后重新校验
_CACHE = {}
_cache_dirty = False
_cache_lock = __import__("threading").Lock()


def _cache_load():
    global _CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, encoding="utf-8") as f:
                _CACHE = json.load(f)
        except Exception:
            _CACHE = {}


def _cache_save():
    if not _cache_dirty:
        return
    try:
        os.makedirs(PUB, exist_ok=True)
        tmp = CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_CACHE, f)
        os.replace(tmp, CACHE_FILE)
    except Exception as e:
        print("[缓存] 写入失败:", e)


def _doh_lookup(host, timeout=4.0):
    """DoH 查询 A 记录。
    返回 True=存在；False=确定不存在（仅 NXDOMAIN）；None=结果不确定（限流/超时/空应答），
    调用方必须换系统解析兜底，并且绝不能把 None 缓存成"死"。"""
    import urllib.parse as up
    url = DOH_URL + "?" + up.urlencode({"name": host, "type": "A"})
    for _ in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            d = json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())
            status = d.get("Status")
            ans = d.get("Answer") or []
            if ans:                      # 有应答记录
                return True
            if status == 3:              # NXDOMAIN：明确不存在
                return False
            return None                  # SERVFAIL / 空应答：不确定
        except Exception:
            continue
    return None


def resolvable(host, timeout=3.0):
    """优先 DoH，其次系统解析；只缓存确定的结论。"""
    global _cache_dirty
    import time as _t
    now = _t.time()
    c = _CACHE.get(host)
    if isinstance(c, dict):
        if c.get("v") and now - c.get("t", 0) < ALIVE_TTL:
            return True
        if not c.get("v") and now - c.get("t", 0) < DEAD_TTL:
            return False

    # 系统解析优先：NXDOMAIN 能立刻判定为死，_比每个域名都走一次 DoH 快一个数量级
    ok = None
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(host)
        ok = True
    except socket.gaierror as e:
        if e.errno == -2:      # EAI_NONAME / NXDOMAIN，确定不存在
            ok = False
    except Exception:
        ok = None
    if ok is None:             # 超时或解析器异常才用 DoH 复核
        ok = _doh_lookup(host, timeout=max(timeout, 2.0))

    if ok is not None:
        with _cache_lock:
            _CACHE[host] = {"v": bool(ok), "t": now}
            _cache_dirty = True
    return bool(ok)


def http_probe(host, timeout=3.0):
    """HTTP探测：判断域名是否真的是广告服务器。返回True=是广告服务。"""
    try:
        import urllib.request as ur
        for scheme in ["https", "http"]:
            try:
                url = "%s://%s/" % (scheme, host)
                req = ur.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = ur.urlopen(req, timeout=timeout)
                code = resp.getcode()
                # 200/302/403都算存活服务
                if code in (200, 301, 302, 403, 404):
                    return True
            except urllib.error.HTTPError as e:
                # HTTP错误码也算服务存活
                if e.code in (403, 404, 401, 405):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _ct_cache_path():
    return os.path.join(PUB, "ct_cache.json")


def _load_ct_cache():
    """CT 结果缓存：同一根域 7 天内不重复抓，省掉每天十几分钟的重复请求。"""
    import time as _t
    p = _ct_cache_path()
    if not os.path.exists(p):
        return {}
    try:
        raw = json.load(open(p, encoding="utf-8"))
    except Exception:
        return {}
    now = _t.time()
    return {k: v.get("names", []) for k, v in raw.items()
            if isinstance(v, dict) and now - v.get("t", 0) < 7 * 86400}


def _save_ct_cache(names_map):
    import time as _t
    try:
        os.makedirs(PUB, exist_ok=True)
        now = _t.time()
        data = {k: {"t": now, "names": v} for k, v in names_map.items()}
        json.dump(data, open(_ct_cache_path(), "w", encoding="utf-8"))
    except Exception as e:
        print("[CT缓存] 写入失败:", e)


def ct_subdomains(apex):
    """证书透明日志抓真实子域（certspotter + crt.sh 双源）。失败返回空。"""
    out = set()
    # 源1: certspotter
    try:
        url = ("https://api.certspotter.com/v1/issuances?domain=%s"
               "&include_subdomains=true&expand=dns_names" % apex)
        req = urllib.request.Request(url, headers={"User-Agent": "XWDNS/1.0"})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read().decode("utf-8", "ignore"))
        for cert in data if isinstance(data, list) else []:
            for n in cert.get("dns_names", []):
                n = n.lower().strip().lstrip("*.")
                if n.endswith("." + apex) and "." in n:
                    out.add(n)
    except Exception:
        pass
    # 源2: crt.sh（备用）
    try:
        url = "https://crt.sh/?q=%25.%s&output=json" % apex
        req = urllib.request.Request(url, headers={"User-Agent": "XWDNS/1.0"})
        data = json.loads(urllib.request.urlopen(req, timeout=15).read().decode("utf-8", "ignore"))
        for cert in data:
            for n in cert.get("name_value", "").split("\n"):
                n = n.lower().strip().lstrip("*.")
                if n.endswith("." + apex) and "." in n:
                    out.add(n)
    except Exception:
        pass
    return out


def is_biz(host, apex):
    prefix = host[:-(len(apex)+1)] if host.endswith("."+apex) else host
    first = prefix.split(".")[0]
    return first in BIZ_WORDS


def main():
    os.makedirs(PUB, exist_ok=True)
    _cache_load()
    print("  DNS 缓存: %d 条" % len(_CACHE))
    socket.setdefaulttimeout(2.0)

    # 先并发把根域的通配属性和 CT 子域一次性取回来（原来是串行逐个抓，光这一步就要十几分钟）
    all_apexes = sorted({a for v in COMPANIES.values() for a in v})
    print("根域 %d 个，先并发做通配检测 + CT 抓取…" % len(all_apexes), flush=True)
    wild_flags, ct_map = {}, {}
    ct_cache = _load_ct_cache()

    def _apex_task(apex):
        w = is_wildcard(apex)
        ct = ct_cache.get(apex)
        if ct is None:
            ct = sorted(ct_subdomains(apex))
        return apex, w, set(ct)

    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        for apex, w, ct in ex.map(_apex_task, all_apexes):
            wild_flags[apex] = w
            ct_map[apex] = ct
            if ct:
                ct_cache[apex] = sorted(ct)
            if w:
                print("  %s 通配域，跳过字典爆破（只用 CT 真名）" % apex)
    _save_ct_cache(ct_cache)
    print("通配域 %d 个，CT 抓到子域 %d 个（未命中的根域 %d 个）"
          % (sum(1 for v in wild_flags.values() if v),
             sum(len(v) for v in ct_map.values()),
             sum(1 for v in ct_map.values() if not v)), flush=True)

    # 收集每个公司的候选子域
    company_hosts = {}
    all_candidates = set()
    for company, apexes in COMPANIES.items():
        hosts = set()
        for apex in apexes:
            if not wild_flags.get(apex):
                for w in AD_WORDS:
                    if word_applies(w, apex):
                        hosts.add(w + "." + apex)
            hosts |= ct_map.get(apex, set())
        company_hosts[company] = hosts
        all_candidates |= hosts

    print("候选总数:", len(all_candidates), flush=True)

    # CT 日志里的名字来自真实签发的证书，一定存在，不用再花时间校验
    ct_confirmed = {n for v in ct_map.values() for n in v}
    resolved = {h: True for h in ct_confirmed if h in all_candidates}
    # 并发 DNS 校验（带进度，避免 CI 日志长时间无输出像卡死）
    clist = sorted(all_candidates - ct_confirmed)
    total = len(clist)
    print("开始 DNS 校验 %d 个候选（CT 已证实 %d 个免校验）…" % (total, len(all_candidates) - total), flush=True)
    with cf.ThreadPoolExecutor(max_workers=300) as ex:
        for i, (h, ok) in enumerate(zip(clist, ex.map(resolvable, clist)), 1):
            if ok:
                resolved[h] = True
            if i % 20000 == 0:
                print("  进度 %d/%d（%.0f%%），已确认存活 %d"
                      % (i, total, i * 100.0 / max(total, 1), len(resolved)), flush=True)
    print("真实存在:", len(resolved))

    # 同族扩展：已存活广告域里带编号的（v5-reading-ad / mon11-misc / log3-applog），
    # 把编号换成 1..N 继续探测，补齐 CT 日志没收录的兄弟域名（红果就是靠这招补全的）。
    def sibling_candidates(hosts, max_seed=3, span=60):
        extra = set()
        seeds = [h for h in sorted(hosts) if re.search(r"\d", h.split(".")[0])][:max_seed]
        for h in seeds:
            labels = h.split(".")
            m = re.search(r"\d+", labels[0])
            if not m:
                continue
            base = labels[0][:m.start()] + "%d" + labels[0][m.end():]
            for n in range(1, span + 1):
                cand = base % n
                if cand != labels[0]:
                    extra.add(".".join([cand] + labels[1:]))
        return extra - all_candidates

    sib_by_company = {}
    sib = set()
    for company, hosts in company_hosts.items():
        s = sibling_candidates({h for h in hosts if h in resolved})
        sib_by_company[company] = s
        sib |= s
    if sib:
        print("同族扩展候选 %d 个，开始校验…" % len(sib), flush=True)
        sibl = sorted(sib)
        with cf.ThreadPoolExecutor(max_workers=100) as ex:
            for h, ok in zip(sibl, ex.map(resolvable, sibl)):
                if ok:
                    resolved[h] = True
        alive_new = {h for h in sibl if h in resolved}
        print("同族扩展存活 %d 个" % len(alive_new), flush=True)
        for company, s in sib_by_company.items():
            company_hosts[company] |= {h for h in s if h in resolved}

    # 按公司分类
    blocked = set()
    redfruit = {"fqnovel.com", "novelquickapp.com", "hongguoduanju.com", "fqnovelvod.com",
                "qznovel.com", "qznovelvod.com", "fqmanhua.com", "fqmanhua.cn",
                "qzmanhua.com", "changdunovel.com"}
    for company, hosts in company_hosts.items():
        live = sorted(h for h in hosts if h in resolved)
        if company in ("红果短剧", "红果漫剧"):
            # 红果不能整域全拦：会给通配 CDN 造出一堆假域名，且可能误杀播放
            # 改为只保留广告/埋点类子域，上限放宽到 300
            keep = [h for h in live if AD_RE.search(h)]
            keep = [h for h in keep if not any(h == a for a in COMPANIES[company])]
            keep = keep[:300]
        else:
            # 只保留广告类，按热度顺序，每家≤100
            keep = [h for h in live if AD_RE.search(h)]
            keep = [h for h in keep if not any(h == a for a in COMPANIES[company])]
            keep = keep[:300]
        blocked |= set(keep)
        print("%s: 保留 %d / 真实 %d" % (company, len(keep), len(live)))

    # 硬放行：这些主域绝不进黑名单
    HARD_ALLOW = {"baidu.com", "bdstatic.com", "bdimg.com", "gitee.com",
                  "giteeusercontent.com", "gitee.io", "raw.giteeusercontent.com",
                  "www.baidu.com", "m.baidu.com"}
    blocked = {h for h in blocked if h not in HARD_ALLOW}
    blocked = {h for h in blocked
               if not any(h == a or h.endswith("."+a) for a in
                          ["baidu.com", "bdstatic.com", "bdimg.com",
                           "gitee.com", "giteeusercontent.com", "gitee.io"])}

    blocked = sorted(blocked)

    # 白名单：所有 apex + 业务前缀 + 硬放行
    white = set(HARD_ALLOW)
    for apexes in COMPANIES.values():
        for apex in apexes:
            white.add(apex)
            for w in BIZ_WORDS:
                white.add(w + "." + apex)
    # 校验白名单真实存在
    wlist = []
    wls = sorted(white)
    with cf.ThreadPoolExecutor(max_workers=100) as ex:
        for h, ok in zip(wls, ex.map(resolvable, wls)):
            if ok:
                wlist.append(h)
    # 白名单优先，黑名单命中白名单的剔除
    wset = set(wlist)
    blocked = [h for h in blocked if h not in wset]

    # 写文件
    _cache_save()
    with open(os.path.join(PUB, "d"), "w") as f:
        f.write("\n".join(blocked) + "\n")
    with open(os.path.join(PUB, "a"), "w") as f:
        f.write("! XWDNS 自建抓取 拦截%d\n" % len(blocked))
        f.write("! 生成时间自动\n")
        f.write("\n".join("||" + h + "^" for h in blocked) + "\n")
    with open(os.path.join(PUB, "h"), "w") as f:
        f.write("# XWDNS hosts 拦截%d\n" % len(blocked))
        f.write("\n".join("0.0.0.0 " + h for h in blocked) + "\n")
    with open(os.path.join(PUB, "w"), "w") as f:
        f.write("# 配套白名单 %d\n" % len(wlist))
        f.write("\n".join(wlist) + "\n")

    # 按厂商输出单独文件到 apps/ 目录（交由 gen_apps 统一处理，可独立重跑）
    try:
        import gen_apps
        gen_apps.main()
    except Exception as e:
        print("[分组] 生成 apps/ 失败:", e)
    print("拦截:", len(blocked), "白名单:", len(wlist), "厂商文件:", len(company_hosts))


def cleanup_expired():
    """巡检 custom.txt：连续2次DNS解析失败才标记为失效，移到 expired.txt。"""
    import json
    custom_path = os.path.join(ROOT, "custom.txt")
    expired_path = os.path.join(ROOT, "expired.txt")
    fail_count_path = os.path.join(ROOT, ".fail_count.json")
    if not os.path.exists(custom_path):
        return

    # 加载历史失败计数
    fail_count = {}
    if os.path.exists(fail_count_path):
        try:
            fail_count = json.load(open(fail_count_path))
        except Exception:
            fail_count = {}

    all_domains = []
    for line in open(custom_path, encoding="utf-8", errors="ignore"):
        h = line.strip()
        if h and not h.startswith("#") and "." in h:
            all_domains.append(h)
    print(f"\n[巡检] custom.txt 共 {len(all_domains)} 条，开始DNS校验（连续2次失败才删）...")

    # 并发校验
    alive, dead = [], []
    with cf.ThreadPoolExecutor(max_workers=200) as ex:
        results = list(ex.map(resolvable, sorted(all_domains)))
    for h, ok in zip(sorted(all_domains), results):
        if ok:
            alive.append(h)
            fail_count.pop(h, None)  # 恢复了就清除计数
        else:
            fail_count[h] = fail_count.get(h, 0) + 1
            if fail_count[h] >= 2:  # 连续2次失败才删
                dead.append(h)

    # 从fail_count里删掉已删除的
    for h in dead:
        fail_count.pop(h, None)

    print(f"[巡检] 存活: {len(alive)}, 本次失败待观察: {len(all_domains) - len(alive) - len(dead)}, 连续失败删除: {len(dead)}")

    # 写回 custom.txt（保留存活的 + 本次失败待观察的）
    kept = set(alive) | (set(all_domains) - set(dead))
    with open(custom_path, "w", encoding="utf-8") as f:
        f.write("# 自建规则（存活域名）\n")
        f.write("\n".join(sorted(kept)) + "\n")

    # 保存失败计数
    json.dump(fail_count, open(fail_count_path, "w"), indent=2)

    # 失效的追加到 expired.txt
    existing_expired = set()
    if os.path.exists(expired_path):
        for line in open(expired_path, encoding="utf-8"):
            h = line.strip()
            if h and not h.startswith("#"):
                existing_expired.add(h)
    existing_expired |= set(dead)
    with open(expired_path, "w", encoding="utf-8") as f:
        f.write(f"# 失效域名备份（{len(existing_expired)}条，连续2次DNS解析失败）\n")
        f.write("\n".join(sorted(existing_expired)) + "\n")

    print(f"[巡检] 本次删除 {len(dead)} 条，待观察 {len(all_domains) - len(alive) - len(dead)} 条")


def load_previous_crawl():
    """加载上次抓取结果，用于增量比对。"""
    prev_file = os.path.join(ROOT, ".publish", "d")
    if os.path.exists(prev_file):
        return set(l.strip() for l in open(prev_file) if l.strip())
    return set()


def auto_git_commit():
    """自动提交并推送（仅限本机手动运行；GitHub Actions 里由工作流负责提交，避免双重推送）。"""
    import subprocess
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        print("[Git] 检测到 CI 环境，跳过脚本内提交（交给工作流）")
        return
    token_file = os.path.expanduser("~/.config/adqgg/gitee_token")
    if not os.path.exists(token_file):
        print("[Git] 无token文件，跳过自动提交")
        return
    token = open(token_file).read().strip()
    try:
        subprocess.run(["git", "add", "-A"], cwd=ROOT, check=True, capture_output=True)
        # 检查有没有变更
        diff = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT)
        if diff.returncode == 0:
            print("[Git] 无变更，跳过提交")
            return
        msg = "自动抓取更新 " + __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")
        subprocess.run(["git", "-c", "user.name=AutoRuleBot", "-c", "user.email=bot@local",
                        "commit", "-m", msg], cwd=ROOT, check=True, capture_output=True)
        subprocess.run(["git", "push",
                        "https://oauth2:%s@gitee.com/ADS9/ad.git" % token, "m"],
                       cwd=ROOT, check=True, capture_output=True)
        print("[Git] 自动提交并推送成功")
    except Exception as e:
        print(f"[Git] 自动提交失败: {e}")


if __name__ == "__main__":
    import sys
    if "--cleanup" in sys.argv:
        cleanup_expired()
    else:
        prev = load_previous_crawl()
        main()
        cleanup_expired()
        # 增量统计
        current = set(l.strip() for l in open(os.path.join(PUB, "d")) if l.strip())
        new_domains = current - prev
        print(f"\n[增量] 新增域名: {len(new_domains)} 条")
        auto_git_commit()
