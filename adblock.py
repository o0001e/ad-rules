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


def is_protected(d):
    return any(d == p or d.endswith("." + p) for p in PROTECT)


def normalize(line):
    h = line.strip().lower()
    if not h or h[0] in "#![" or h.startswith("//"):
        return None
    h = re.sub(r"^0\.0\.0\.0\s+|^127\.0\.0\.1\s+|^::1\s+|^::\s+", "", h)
    m = re.match(r"^(domain-suffix|domain|host|domain-wildcard)\s*,\s*(.*)$", h)
    if m:
        h = m.group(2).strip().lstrip(".")
    h = re.sub(r"^[+*]\.", "", h)
    h = h.replace("||", "").replace("^", "").replace("@@", "").strip(". ")
    h = h.split("$")[0].split("/")[0].strip()
    if re.fullmatch(r"[a-z0-9.-]+", h) and "." in h and len(h) < 80:
        return h
    return None


def download(url, idx):
    os.makedirs(CACHE, exist_ok=True)
    f = os.path.join(CACHE, "src%02d.txt" % idx)
    if os.path.exists(f) and time.time() - os.path.getmtime(f) < 6 * 3600:
        return f
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            open(f, "wb").write(data)
            return f
        except Exception as e:
            if attempt == 2:
                print(f"[源{idx}] 失败 {url} {e}")
                return None
            time.sleep(2)


def read_sources():
    urls = [l.strip() for l in open(SOURCES, encoding="utf-8")
            if l.strip() and not l.strip().startswith("#")]
    files = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        for i, f in enumerate(ex.map(lambda a: download(*a), [(u, i) for i, u in enumerate(urls)]), 1):
            if f:
                files.append((i, f))
    print("[下载] %d/%d 个源就绪" % (len(files), len(urls)))
    return files


def ad_like(d):
    return bool(AD_WORDS.search(d))


def collect(files):
    doms = collections.Counter()
    for idx, f in files:
        n = 0
        with open(f, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                d = normalize(line)
                if d and not is_protected(d):
                    doms[d] += 1
                    n += 1
        print("[解析] 源%02d %d 条" % (idx, n))
    return doms


def collapse(blocked, white):
    """eTLD+1 归并：父域已拦 → 删子域"""
    dropped = set()
    for d in blocked:
        if d in white:
            continue
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in blocked:
                dropped.add(d)
                break
    return blocked - dropped, len(dropped)


def write(blocked, white, apps):
    os.makedirs(OUT, exist_ok=True)
    ver = time.strftime("%Y%m%d %H:%M")
    n = len(blocked)
    if n < 1000:
        print("[警告] 只生成 %d 条，低于安全线，拒绝覆盖" % n)
        sys.exit(2)
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

    # Lite：只留国内厂商 + .cn
    def root_of(d):
        p = d.split(".")
        if len(p) >= 3 and p[-2] in ("com", "net", "org", "gov") and p[-1] == "cn":
            return ".".join(p[-3:])
        return ".".join(p[-2:]) if len(p) >= 2 else d
    lite = {d for d in blocked
            if root_of(d) in roots or root_of(d) in CN_VENDORS or d.endswith(".cn")}
    with open(os.path.join(OUT, "lite.txt"), "w", encoding="utf-8") as f:
        f.write("# AD-QGG Lite（国内）\n# Update: %s\n" % ver)
        f.write("".join("0.0.0.0 %s\n" % d for d in sorted(lite)))
    with open(os.path.join(OUT, "lite_domains.txt"), "w", encoding="utf-8") as f:
        f.write("".join(d + "\n" for d in sorted(lite)))
    print("[Lite] %d 条" % len(lite))

    # all.txt：全量 + 全分组去重
    allset = set(blocked)
    for ds in groups.values():
        allset.update(ds)
    with open(os.path.join(OUT, "all.txt"), "w", encoding="utf-8") as f:
        f.write("".join("0.0.0.0 %s\n" % d for d in sorted(allset)))

    with open(os.path.join(OUT, "build_report.txt"), "w", encoding="utf-8") as f:
        f.write("构建时间: %s\n总规则: %d\n白名单: %d\nApp 分组: %d\nLite: %d\n"
                % (ver, n, len(white), len(groups), len(lite)))


def main():
    t0 = time.time()
    files = read_sources()
    doms = collect(files)
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
        if c >= 2 or ad_like(d):
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
    blocked = keep | extra
    blocked, dropped = collapse(blocked, white)
    if dropped:
        print("[归并] 去掉 %d 个冗余子域" % dropped)
    apps = json.load(open(APPS, encoding="utf-8")) if os.path.exists(APPS) else {}
    write(blocked, white, apps)
    print("[完成] 用时 %.1f 秒" % (time.time() - t0))


if __name__ == "__main__":
    main()
