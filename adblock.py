#!/usr/bin/env python3
"""AD-QGG Filters：纯合并流水线（无爬虫、无 DNS 校验）

思路同 217heidai/adblockfilters：
  1. 读 sources.txt 里的上游规则源，多线程下载
  2. 把 hosts / AdGuard / dnsmasq / Clash / 裸域名 统一解析成域名集合
  3. 过滤噪音域名 + 应用白名单
  4. 按 eTLD+1 归并：父域已拦则删除子域（白名单子域保留）
  5. 一次输出多格式（hosts / AdGuard / dnsmasq / domains / Clash / Surge / Lite）
  6. 按 app_list.json 的厂商根域拆出单 App 分组
产物由工作流上传到 Release，仓库只放源码。
"""
import os, re, sys, json, time, collections, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "rules")
CACHE = os.path.join(ROOT, ".cache", "src")
SOURCES = os.path.join(ROOT, "sources.txt")
WHITE = os.path.join(ROOT, "whitelist.txt")
CUSTOM = os.path.join(ROOT, "custom.txt")
APPS = os.path.join(ROOT, "app_list.json")
DEAD = os.path.join(ROOT, "dead.txt")
UA = {"User-Agent": "Mozilla/5.0 (AdQggFilters/1.0)"}

# 绝不拦截：登录 / 支付 / 政务 / 系统服务 / 仓库自身
PROTECT = """
qq.com weixin.qq.com wechat.com alipay.com taobao.com tmall.com jd.com
gov.cn 12306.cn baidu.com aliimg.com taobao.org alibaba.com
gitee.com github.com githubusercontent.com jsdelivr.net
apple.com icloud.com microsoft.com google.com gstatic.com
""".split()

NOISE = ("localhost", )

# 广告特征词：命中即优先收录
AD_WORDS = re.compile(r"(^|[-.])(ad|ads|adv|advert|adserver|adx|track|tracker|tracking|analytic|analytics|"
                      r"stat|stats|statsd|log|logs|logserver|beacon|impression|click|promo|market|marketing|"
                      r"push|sdk|pangolin|gdt|doubleclick|umeng|gromore|bytedance|snssdk|splash)([-.]|$)")

# 业务接口/品牌主域：绝不拦（登录、支付、内容接口）
SAFE_WORDS = re.compile(r"(^|[-.])(api|login|passport|pay|cashier|order|user|account|auth|oauth|"
                        r"mail|im|chat|upload|download|static|img|image|video|vod|play|live|cdn|"
                        r"frontier|pull|stream)([-.]|$)")

CN_VENDORS = set("""
qq.com gtimg.cn gtimg.com qpic.cn qlogo.cn weixin.qq.com wechat.com
bytedance.com snssdk.com zijieapi.com byteimg.com bytednsdoc.com toutiao.com
umeng.com aliyun.com alibaba.com taobao.com tmall.com alipay.com
baidu.com bdstatic.com sina.com.cn weibo.com sohu.com 163.com 126.net
tencentmusic.com kugou.com migu.cn iqiyi.com youku.com bilibili.com
mi.com xiaomi.com huawei.com honor.com oppo.com vivo.com meizu.com
jd.com pinduoduo.com xiaohongshu.com kuaishou.com
""".split())

TARGET = 8000

# 云厂商 / CDN 共享域：只允许拦具体子域，绝不允许拦父域
SHARED_INFRA = re.compile(
    r"([-.])(amazonaws\.com|cloudfront\.net|azurewebsites\.net|azureedge\.net|"
    r"appspot\.com|googleapis\.com|edgesuite\.net|akamaihd\.net|akamaized\.net|"
    r"cloudflare\.net|herokuapp\.com|vercel\.app|netlify\.app|githubusercontent\.com|"
    r"aliyuncs\.com|myqcloud\.com|qiniucdn\.com|bcebos\.com)$")


def is_protected(d):
    return any(d == p or d.endswith("." + p) for p in PROTECT)


HOST_PREFIXES = ("0.0.0.0", "127.0.0.1", "::1", "::")
DOM_FIX = re.compile(r"^(domain-suffix|domain|host|domain-wildcard)\\s*,\\s*")
OK_DOM = re.compile(r"[a-z0-9.-]+$")


def normalize(line):
    h = line.strip()
    if not h or h[0] in "#![" or h.startswith("//"):
        return None
    h = h.lower()
    # hosts 格式快速路径
    first = h.split(" ", 1)
    if len(first) == 2 and first[0] in HOST_PREFIXES:
        h = first[1].strip()
        if not h or h[0] == "#":
            return None
    elif first[0] in HOST_PREFIXES:
        return None
    if h.startswith("domain"):
        m = DOM_FIX.match(h)
        if m:
            h = h[m.end():].lstrip(".")
    if h[:2] in ("+.", "*."):
        h = h[2:]
    if h.startswith("||"):
        h = h[2:]
    if h.startswith("@@"):
        h = h[2:]
        if h.startswith("||"):
            h = h[2:]
    if "|" in h:
        h = h.replace("|", "")
    if "^" in h:
        h = h.replace("^", "")
    if "$" in h:
        h = h.split("$", 1)[0]
    if "/" in h:
        h = h.split("/", 1)[0]
    h = h.strip(". ")
    if "." not in h or len(h) > 79:
        return None
    if not OK_DOM.fullmatch(h):
        return None
    return h


def download(url, idx):
    os.makedirs(CACHE, exist_ok=True)
    f = os.path.join(CACHE, "src%02d.txt" % idx)
    meta_f = os.path.join(CACHE, "meta.json")
    meta = {}
    if os.path.exists(meta_f):
        try:
            meta = json.load(open(meta_f, encoding="utf-8"))
        except Exception:
            meta = {}

    def save_meta():
        try:
            json.dump(meta, open(meta_f, "w", encoding="utf-8"))
        except Exception:
            pass

    cached = os.path.exists(f)
    if cached and time.time() - os.path.getmtime(f) < 6 * 3600:
        return f

    headers = dict(UA)
    if cached and meta.get(url):
        headers.update(meta[url])

    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                data = r.read()
            open(f, "wb").write(data)
            etag = {"If-None-Match": r.headers.get("ETag")} if r.headers.get("ETag") else {}
            lm = r.headers.get("Last-Modified")
            if lm:
                etag["If-Modified-Since"] = lm
            if etag:
                meta[url] = etag
                save_meta()
            return f
        except urllib.error.HTTPError as e:
            if e.code == 304 and cached:
                os.utime(f, None)
                return f
            if attempt == 1:
                print(f"[源{idx}] 失败 {url} HTTP {e.code}")
                return f if cached else None
        except Exception as e:
            if attempt == 1:
                print(f"[源{idx}] 失败 {url} {e}")
                return f if cached else None
            time.sleep(0.5)
    return f if cached else None


def read_sources():
    urls = [l.strip() for l in open(SOURCES, encoding="utf-8")
            if l.strip() and not l.strip().startswith("#")]
    files = []
    with ThreadPoolExecutor(max_workers=24) as ex:
        for i, f in enumerate(ex.map(lambda a: download(*a), [(u, i) for i, u in enumerate(urls)]), 1):
            if f:
                files.append((i, f))
    print("[下载] %d/%d 个源就绪" % (len(files), len(urls)))
    return files


def ad_like(d):
    return bool(AD_WORDS.search(d))


def collect(files):
    doms = collections.Counter()
    srcs = collections.defaultdict(set)
    for idx, f in files:
        n = 0
        with open(f, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                d = normalize(line)
                if d and not is_protected(d):
                    doms[d] += 1
                    srcs[d].add(idx)
                    n += 1
        print("[解析] 源%02d %d 条" % (idx, n))
    return doms, srcs


def collapse(blocked, white):
    """eTLD+1 归并：父域已拦 → 删子域"""
    dropped = set()
    for d in blocked:
        if d in white or SHARED_INFRA.search(d):
            continue
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in blocked:
                dropped.add(d)
                break
    return blocked - dropped, len(dropped)


def write(blocked, white, apps, srcs=None):
    os.makedirs(OUT, exist_ok=True)
    srcs = srcs or {}
    ver = time.strftime("%Y%m%d %H:%M")
    n = len(blocked)
    if n < 1000:
        print("[熔断] 只生成 %d 条，低于安全线，拒绝覆盖" % n)
        sys.exit(2)
    prev_f = os.path.join(OUT, "hosts.txt")
    prev = 0
    if os.path.exists(prev_f):
        for l in open(prev_f, encoding="utf-8"):
            if l.startswith("# Count:"):
                try:
                    prev = int(l.split(":")[1])
                except Exception:
                    prev = 0
                break
    if prev >= 1000:
        ratio = n / float(prev)
        if ratio < 0.75 or ratio > 1.35:
            print("[熔断] 条数由 %d 变为 %d（%.0f%%），超出安全区间，中止发布" % (prev, n, ratio * 100))
            sys.exit(3)
    print("[合并] 最终 %d 条（白名单 %d）" % (n, len(white)))

    with open(os.path.join(OUT, "hosts.txt"), "w", encoding="utf-8") as f:
        f.write("# AD-QGG Filter\n# Update: %s\n# Count: %d\n" % (ver, n))
        f.write("".join("0.0.0.0 %s\n" % d for d in sorted(blocked)))
    with open(os.path.join(OUT, "adguard.txt"), "w", encoding="utf-8") as f:
        f.write("! AD-QGG Filter\n! Update: %s\n" % ver)
        f.write("".join("||%s^\n" % d for d in sorted(blocked)))
    with open(os.path.join(OUT, "domains.txt"), "w", encoding="utf-8") as f:
        f.write("".join(d + "\n" for d in sorted(blocked)))
    with open(os.path.join(OUT, "dnsmasq.conf"), "w", encoding="utf-8") as f:
        f.write("".join("address=/%s/0.0.0.0\n" % d for d in sorted(blocked)))
    with open(os.path.join(OUT, "clash.yaml"), "w", encoding="utf-8") as f:
        f.write("# AD-QGG Clash rule-provider (behavior: domain)\n# Update: %s\npayload:\n" % ver)
        f.write("".join("  - '+.%s'\n" % d for d in sorted(blocked)))
    with open(os.path.join(OUT, "surge.list"), "w", encoding="utf-8") as f:
        f.write("".join("DOMAIN,%s\n" % d for d in sorted(blocked)))

    # 白名单产物（给 DNS App 的「放行」列表用）
    with open(os.path.join(OUT, "whitelist.txt"), "w", encoding="utf-8") as f:
        f.write("".join("0.0.0.0 %s\n" % d for d in sorted(white)))
    with open(os.path.join(OUT, "whitelist_adguard.txt"), "w", encoding="utf-8") as f:
        f.write("! AD-QGG 白名单\n# Update: %s\n" % ver)
        f.write("".join("@@||%s^\n" % d for d in sorted(white)))

    # 按厂商根域拆分组
    roots, names = {}, {}
    for name, cfg in apps.items():
        rs = cfg if isinstance(cfg, list) else [cfg]
        for r in rs:
            roots.setdefault(r.strip().lower(), []).append(name)
            names[name] = rs
    os.makedirs(os.path.join(OUT, "apps"), exist_ok=True)
    groups = collections.defaultdict(list)
    for d in blocked:
        for r, ns in roots.items():
            if d == r or d.endswith("." + r):
                for nm in ns:
                    groups[nm].append(d)
                break
    for nm, ds in sorted(groups.items()):
        if not ds:
            continue
        safe = re.sub(r'[\\\\/:*?"<>|]', "_", nm)
        with open(os.path.join(OUT, "apps", safe + ".txt"), "w", encoding="utf-8") as f:
            f.write("".join("0.0.0.0 %s\n" % d for d in sorted(set(ds))))
    print("[分组] %d 个 App 分组" % len(groups))

    # all.txt：全量 + 全分组去重
    allset = set(blocked)
    for ds in groups.values():
        allset.update(ds)
    with open(os.path.join(OUT, "all.txt"), "w", encoding="utf-8") as f:
        f.write("".join("0.0.0.0 %s\n" % d for d in sorted(allset)))

    # 源评分：每个源贡献多少条、最终存活多少条（无来源数据时保留原文件）
    if srcs:
        src_total = collections.Counter()
        for d, ids in srcs.items():
            for i in ids:
                src_total[i] += 1
        live_cnt = collections.Counter()
        for d in blocked:
            for i in srcs.get(d, ()):
                live_cnt[i] += 1
        with open(os.path.join(OUT, "source_score.txt"), "w", encoding="utf-8") as f:
            f.write("# 源编号\t解析域名数\t最终存活\t存活率\n")
            for i in sorted(src_total):
                f.write("%02d\t%d\t%d\t%.1f%%\n" % (i, src_total[i], live_cnt[i], live_cnt[i] * 100.0 / max(src_total[i], 1)))

    # 来源统计：无来源数据时保留原文件（修剪任务走这条分支）
    if srcs:
        with open(os.path.join(OUT, "source_report.txt"), "w", encoding="utf-8") as f:
            f.write("# 域名\t收录源数\t来源编号\n")
            for d in sorted(blocked):
                ids = ",".join(str(x) for x in sorted(srcs.get(d, ())))
                f.write("%s\t%d\t%s\n" % (d, len(srcs.get(d, ())), ids))

    # 白名单产物
    with open(os.path.join(OUT, "whitelist.txt"), "w", encoding="utf-8") as f:
        f.write("# AD-QGG 白名单（一行一个域名）\n# Update: %s\n# Count: %d\n" % (ver, len(white)))
        f.write("".join(d + "\n" for d in sorted(white)))
    with open(os.path.join(OUT, "whitelist_adguard.txt"), "w", encoding="utf-8") as f:
        f.write("! AD-QGG 白名单\n# Update: %s\n" % ver)
        f.write("".join("@@||%s^\n" % d for d in sorted(white)))

    with open(os.path.join(OUT, "build_report.txt"), "w", encoding="utf-8") as f:
        f.write("构建时间: %s\n总规则: %d\n白名单: %d\nApp 分组: %d\n"
                % (ver, n, len(white), len(groups)))


def read_sources_from(urls, base=90):
    files = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for i, f in enumerate(ex.map(lambda a: download(*a), [(u, base + i) for i, u in enumerate(urls)]), 1):
            if f:
                files.append((i, f))
    return files


def load_white():
    w = set()
    for p in (WHITE, CUSTOM):
        if os.path.exists(p):
            for l in open(p, encoding="utf-8"):
                d = normalize(l)
                if d and p == WHITE:
                    w.add(d)
    return w


def load_current():
    f = os.path.join(OUT, "hosts.txt")
    if not os.path.exists(f):
        return set()
    out = set()
    for l in open(f, encoding="utf-8"):
        if l.startswith("0.0.0.0 "):
            out.add(l.split()[1].strip().lower())
    return out


def load_dead():
    if not os.path.exists(DEAD):
        return set()
    return {l.strip() for l in open(DEAD, encoding="utf-8") if l.strip() and not l.strip().startswith("#")}


def load_apps():
    try:
        return json.load(open(APPS, encoding="utf-8"))
    except Exception:
        return {}


def main():
    t0 = time.time()
    files = read_sources()
    doms, srcs = collect(files)
    white = set()
    for p in (WHITE, CUSTOM):
        if os.path.exists(p):
            for l in open(p, encoding="utf-8"):
                d = normalize(l)
                if d:
                    white.add(d) if p == WHITE else None
    # custom.txt 是补充规则（要拦），单独并入
    extra = set()
    if os.path.exists(CUSTOM):
        for l in open(CUSTOM, encoding="utf-8"):
            d = normalize(l)
            if d:
                extra.add(d)
    keep = set()
    for d, c in doms.items():
        if d in white or is_protected(d):
            continue
        if SAFE_WORDS.search(d) and not ad_like(d):
            continue   # 业务接口，非广告特征
        if c >= 2 or (ad_like(d) and not SHARED_INFRA.search(d)):
            keep.add(d)
    # App 厂商根域下的域名一律保留（否则分组会空）
    apps_pre = json.load(open(APPS, encoding="utf-8")) if os.path.exists(APPS) else {}
    ap_roots = set()
    for cfg in apps_pre.values():
        for r in (cfg if isinstance(cfg, list) else [cfg]):
            ap_roots.add(r.strip().lower())
    def root2(d):
        p = d.split(".")
        return ".".join(p[-2:]) if len(p) >= 2 else d
    for d in doms:
        if d in white or is_protected(d):
            continue
        r = root2(d)
        if r in ap_roots and not SAFE_WORDS.search(d):
            keep.add(d)

    # 超出上限时按「出现次数 + 广告特征」排序截断
    if len(keep) > TARGET:
        ranked = sorted(keep, key=lambda d: (ad_like(d), doms[d], -len(d)), reverse=True)
        keep = set(ranked[:TARGET])
        print("[限额] 截断到 %d 条" % TARGET)
    dead = set()
    if os.path.exists(DEAD):
        dead = {l.strip() for l in open(DEAD, encoding="utf-8")
                if l.strip() and not l.strip().startswith("#")}
    blocked = (keep | extra) - dead
    if dead:
        print("[死域] 跳过 %d 条已确认无效的域名" % len(dead & (keep | extra)))
    def covered_by_white(d):
        parts = d.split(".")
        return any(".".join(parts[i:]) in white for i in range(len(parts) - 1))
    fixed = {d for d in blocked if covered_by_white(d)}
    if fixed:
        print("[修复] 剔除 %d 个被白名单父域覆盖的域名" % len(fixed))
        blocked -= fixed
    blocked, dropped = collapse(blocked, white)
    if dropped:
        print("[归并] 去掉 %d 个冗余子域" % dropped)
    apps = json.load(open(APPS, encoding="utf-8")) if os.path.exists(APPS) else {}
    write(blocked, white, apps, srcs)
    print("[完成] 用时 %.1f 秒" % (time.time() - t0))


if __name__ == "__main__":
    main()
