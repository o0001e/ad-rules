#!/usr/bin/env python3
"""AD-QGG Filters：纯合并流水线（无爬虫、无 DNS 校验）

思路同 217heidai/adblockfilters：
  1. 读 sources.txt 里的上游规则源，多线程下载
  2. 把 hosts / AdGuard / dnsmasq / Clash / 裸域名 统一解析成域名集合
  3. 过滤噪音域名 + 应用白名单
  4. 按 eTLD+1 归并：父域已拦则删除子域（白名单子域保留）
  5. 一次输出多格式（hosts / AdGuard / dnsmasq / domains / Clash / Surge / Lite）
产物由工作流上传到 Release，仓库只放源码。
"""
import os, re, sys, json, time, socket, collections, datetime, urllib.request, urllib.parse
import gzip, http.client, ssl, threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as _wait, FIRST_COMPLETED

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("OUT_DIR") or os.path.join(ROOT, "rules")
CACHE = os.environ.get("CACHE_DIR") or os.path.join(ROOT, ".cache", "src")
SOURCES = os.path.join(ROOT, "sources.txt")
WHITE = os.path.join(ROOT, "whitelist.txt")
CUSTOM = os.path.join(ROOT, "custom.txt")
DEAD = os.path.join(ROOT, "dead.txt")
UA = {"User-Agent": "Mozilla/5.0 (AdQggFilters/1.0)"}
socket.setdefaulttimeout(15)

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



# ---------------------------------------------------------------- HTTP 连接池
_POOL_LOCAL = threading.local()


class _Pool:
    """按主机复用 TCP/TLS 连接，省掉每次握手的开销"""

    def __init__(self):
        self.ctx = ssl.create_default_context()

    def _conns(self):
        c = getattr(_POOL_LOCAL, "m", None)
        if c is None:
            c = _POOL_LOCAL.m = {}
        return c

    def _new(self, scheme, host):
        if scheme == "https":
            return http.client.HTTPSConnection(host, timeout=20, context=self.ctx)
        return http.client.HTTPConnection(host, timeout=20)

    def _get(self, scheme, host):
        m = self._conns()
        c = m.get(host)
        if c is None:
            c = m[host] = self._new(scheme, host)
        return c

    def request(self, url, headers, follow=2):
        for _ in range(follow + 1):
            parts = urllib.parse.urlsplit(url)
            scheme = parts.scheme or "https"
            host = parts.netloc
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            for attempt in (0, 1):
                conn = self._get(scheme, host)
                try:
                    conn.request("GET", path, headers=headers)
                    resp = conn.getresponse()
                    if attempt == 0 and resp.will_close:
                        conn.close()
                        self._conns()[host] = self._new(scheme, host)
                        continue
                    break
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    self._conns()[host] = self._new(scheme, host)
                    if attempt == 1:
                        raise
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                body = resp.read()
                if not loc:
                    return resp, body
                url = urllib.parse.urljoin(url, loc)
                continue
            return resp, resp.read()
        raise RuntimeError("too many redirects")


POOL = _Pool()


_TIMING = {}
_SRC_STATUS = {}
_HOST_SEM = {}
_HOST_LOCK = threading.Lock()
PER_HOST = 6


def _sem(url):
    host = urllib.parse.urlsplit(url).netloc
    with _HOST_LOCK:
        sem = _HOST_SEM.get(host)
        if sem is None:
            sem = _HOST_SEM[host] = threading.BoundedSemaphore(PER_HOST)
        return sem


def download(url, idx):
    t_start = time.time()
    try:
        with _sem(url):
            return _download(url, idx)
    finally:
        _TIMING[idx] = time.time() - t_start


def _cpath(url):
    import hashlib as _h
    return os.path.join(CACHE, "src-%s.txt" % _h.sha1(url.encode()).hexdigest()[:12])


def _download(url, idx):
    os.makedirs(CACHE, exist_ok=True)
    f = _cpath(url)
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

    headers["Accept-Encoding"] = "gzip"
    for attempt in range(2):
        try:
            resp, data = POOL.request(url, headers)
            if resp.status == 304 and cached:
                os.utime(f, None)
                return f
            if resp.status != 200:
                raise RuntimeError("HTTP %s" % resp.status)
            if (resp.getheader("Content-Encoding") or "").lower() == "gzip":
                data = gzip.decompress(data)
            if len(data) < 200:
                raise RuntimeError("内容过短 %d 字节" % len(data))
            open(f, "wb").write(data)
            etag = {"If-None-Match": resp.getheader("ETag")} if resp.getheader("ETag") else {}
            lm = resp.getheader("Last-Modified")
            if lm:
                etag["If-Modified-Since"] = lm
            if etag:
                meta[url] = etag
                save_meta()
            return f
        except Exception as e:
            if attempt == 1:
                print(f"[源{idx}] 失败 {url} {e}")
                return f if cached else None
            time.sleep(0.3)
    return f if cached else None


def read_sources():
    urls = [l.strip() for l in open(SOURCES, encoding="utf-8")
            if l.strip() and not l.strip().startswith("#")]
    files = []
    missing = [i for i, u in enumerate(urls)
               if not os.path.exists(_cpath(u))]
    budget = 45 if missing else 12
    ex = ThreadPoolExecutor(max_workers=40)
    futs = {ex.submit(download, u, i): i for i, u in enumerate(urls)}
    done, pending = _wait(futs, timeout=budget)
    for f in done:
        try:
            p = f.result()
        except Exception:
            p = None
        if p:
            files.append((futs[f], p))
    if pending:
        for f in pending:
            i = futs[f]
            p = _cpath(urls[i])
            _SRC_STATUS[i] = "超时用缓存" if os.path.exists(p) else "超时丢弃"
            if os.path.exists(p):
                files.append((i, p))
            else:
                print("[下载] 源%02d 超时且无缓存，丢弃" % i)
        print("[下载] %d 个源超时，用旧缓存兜底" % len(pending))
    ex.shutdown(wait=False)
    slow = sorted(_TIMING.items(), key=lambda kv: -kv[1])[:5]
    print("[下载] 最慢: " + ", ".join("源%02d %.1fs" % (i, t) for i, t in slow))
    print("[下载] %d/%d 个源就绪" % (len(files), len(urls)))
    return files


def ad_like(d):
    return bool(AD_WORDS.search(d))


SRC_COUNTS = {}


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
        SRC_COUNTS[idx] = n
        _SRC_STATUS[idx] = "缓存" if _TIMING.get(idx, 0) < 0.05 else "在线"
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


def write(blocked, white, srcs=None):
    ver = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d %H:%M")
    p = lambda n: os.path.join(OUT, n)
    with open(p("hosts.txt"), "w", encoding="utf-8") as f:
        f.write("# AD-QGG Filter\n# Update: %s\n# Count: %d\n" % (ver, len(blocked)))
        f.write("".join("0.0.0.0 %s\n" % d for d in sorted(blocked)))
    with open(p("adguard.txt"), "w", encoding="utf-8") as f:
        f.write("! AD-QGG Filter\n! Update: %s\n" % ver)
        f.write("".join("||%s^\n" % d for d in sorted(blocked)))
    with open(p("domains.txt"), "w", encoding="utf-8") as f:
        f.write("".join(d + "\n" for d in sorted(blocked)))
    with open(p("all.txt"), "w", encoding="utf-8") as f:
        f.write("".join("0.0.0.0 %s\n" % d for d in sorted(blocked)))
    with open(p("dnsmasq.conf"), "w", encoding="utf-8") as f:
        f.write("".join("address=/%s/#\n" % d for d in sorted(blocked)))
    with open(p("clash.yaml"), "w", encoding="utf-8") as f:
        f.write("payload:\n")
        f.write("".join("  - DOMAIN-SUFFIX,%s\n" % d for d in sorted(blocked)))
    with open(p("surge.list"), "w", encoding="utf-8") as f:
        f.write("".join("DOMAIN,%s\n" % d for d in sorted(blocked)))
    with open(p("whitelist.txt"), "w", encoding="utf-8") as f:
        f.write("# AD-QGG 白名单\n# Count: %d\n" % len(white))
        f.write("".join("0.0.0.0 %s\n" % d for d in sorted(white)))
    with open(p("whitelist_adguard.txt"), "w", encoding="utf-8") as f:
        f.write("! AD-QGG 白名单\n")
        f.write("".join("@@||%s^\n" % d for d in sorted(white)))


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


def load_dead():
    """dead.txt 每行：域名<TAB>YYYY-MM-DD（最后确认失效的日期）"""
    if not os.path.exists(DEAD):
        return {}
    out = {}
    for l in open(DEAD, encoding="utf-8"):
        s = l.strip()
        if not s or s.startswith("#"):
            continue
        p = s.split("\t")
        out[p[0]] = p[1] if len(p) > 1 else ""
    return out


def dns_alive(d, tries=2):
    for _ in range(tries):
        try:
            socket.setdefaulttimeout(2.5)
            socket.getaddrinfo(d, None, socket.AF_INET)
            return True
        except Exception:
            continue
    return False


def check_dead(blocked, workers=60):
    """DNS 巡检：解析不出来的域名判为失效，直接从结果里删掉"""
    t = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(dns_alive, blocked))
    dead = {d for d, ok in zip(blocked, res) if not ok}
    cost = time.time() - t
    if not dead:
        print("[死域] DNS 巡检 %.1fs，无失效域名" % cost)
        return dead
    if len(dead) > len(blocked) * 0.2:
        print("[死域] 警告：失效 %d/%d 超过 20%%，疑似 DNS 异常，本轮不删除" % (len(dead), len(blocked)))
        return set()
    print("[死域] DNS 巡检 %.1fs，失效 %d 条，已删除" % (cost, len(dead)))
    return dead


def save_dead(dead, dead_days=30, workers=60):
    """已确认失效的域名带日期入库；超过 30 天（或没有日期）的重新解析一次，能解析就放回规则"""
    today = datetime.date.today()
    old = load_dead()
    expired = [d for d, dt in old.items() if not dt or (today - datetime.date.fromisoformat(dt)).days >= dead_days]
    revived = set()
    if expired:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            res = list(ex.map(dns_alive, expired))
        revived = {d for d, ok in zip(expired, res) if ok}
        for d in expired:
            if d not in revived:
                old[d] = today.isoformat()
        print("[死域复核] %d 条到期复验，%d 条已恢复解析，移出 dead.txt" % (len(expired), len(revived)))
    for d in dead:
        old[d] = today.isoformat()
    with open(DEAD, "w", encoding="utf-8") as f:
        f.write("# 已确认失效的域名（域名 + 最后确认日期），超过 30 天自动复验\n")
        f.write("".join("%s\t%s\n" % (d, dt or today.isoformat()) for d, dt in sorted(old.items())))
    print("[死域] dead.txt 累计 %d 条" % len(old))
    return revived


def main():
    t0 = time.time()
    files = read_sources()
    print("[计时] 下载+准备 %.1fs" % (time.time() - t0))
    t1 = time.time()
    doms, srcs = collect(files)
    print("[计时] 解析 %.1fs" % (time.time() - t1))
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
    # 超出上限时按「出现次数 + 广告特征」排序截断
    if len(keep) > TARGET:
        ranked = sorted(keep, key=lambda d: (ad_like(d), doms[d], -len(d)), reverse=True)
        keep = set(ranked[:TARGET])
        print("[限额] 截断到 %d 条" % TARGET)
    dead = set(load_dead().keys())
    blocked = (keep | extra) - dead
    if dead:
        print("[死域] 跳过 %d 条已确认无效的域名" % len(dead & (keep | extra)))
    def covered_by_white(d):
        parts = d.split(".")
        return any(".".join(parts[i:]) in white for i in range(len(parts) - 1))
    fixed = {d for d in (blocked - extra) if covered_by_white(d)}   # custom 里的规则优先，不被白名单父域吃掉
    if fixed:
        print("[修复] 剔除 %d 个被白名单父域覆盖的域名" % len(fixed))
        blocked -= fixed
    blocked, dropped = collapse(blocked, white)
    if dropped:
        print("[归并] 去掉 %d 个冗余子域" % dropped)
    if os.environ.get("DNS_CHECK", "1") == "1":
        dead = check_dead(sorted(blocked))
        if dead:
            blocked -= dead
        save_dead(dead)
    write(blocked, white, srcs)
    print("[完成] 用时 %.1f 秒" % (time.time() - t0))


if __name__ == "__main__":
    main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)
