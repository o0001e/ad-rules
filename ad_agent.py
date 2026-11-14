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
import gzip, http.client, ssl, threading, hashlib
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as _wait

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

TARGET = int(os.environ.get("TARGET", "8000"))
CN_TARGET = int(os.environ.get("CN_TARGET", "20000"))

# 云厂商 / CDN 共享域：只允许拦具体子域，绝不允许拦父域
SHARED_INFRA = re.compile(
    r"([-.])(amazonaws\.com|cloudfront\.net|azurewebsites\.net|azureedge\.net|"
    r"appspot\.com|googleapis\.com|edgesuite\.net|akamaihd\.net|akamaized\.net|"
    r"cloudflare\.net|herokuapp\.com|vercel\.app|netlify\.app|githubusercontent\.com|"
    r"aliyuncs\.com|myqcloud\.com|qiniucdn\.com|bcebos\.com)$")


def is_protected(d):
    return any(d == p or d.endswith("." + p) for p in PROTECT)


HOST_PREFIXES = ("0.0.0.0", "127.0.0.1", "::1", "::")
DOM_FIX = re.compile(r"^(domain-suffix|domain|host|domain-wildcard)\s*,\s*")
_ALLOWED = "abcdefghijklmnopqrstuvwxyz0123456789.-"
_SPECIAL_RE = re.compile(r"[|^$/*+@]")
OK_DOM = re.compile(r"[a-z0-9.-]+$")


def normalize(line):
    h = line.strip()
    if not h or h[0] in "#![" or h.startswith("//"):
        return None
    h = h.lower()
    # hosts 格式快速路径（支持空格或 Tab 分隔）
    if " " in h or "\t" in h:
        toks = h.split(None, 1)
        if toks[0] in HOST_PREFIXES:
            if len(toks) == 2:
                h = toks[1].strip()
                if not h or h[0] == "#":
                    return None
            else:
                return None
    # Surge/Clash 写法：DOMAIN,xxx / DOMAIN-SUFFIX,xxx
    if h.startswith("domain"):
        m = DOM_FIX.match(h)
        if m:
            h = h[m.end():].lstrip(".")
    # 绝大多数行是纯域名或已去掉前缀的域名：无特殊字符直接走字符集校验
    if not _SPECIAL_RE.search(h):
        h = h.strip(". ")
        if "." in h and len(h) <= 79 and not h.strip(_ALLOWED) and h.strip("0123456789."):
            return h
        return None
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
    if h.strip(_ALLOWED) or not h.strip("0123456789."):
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
_SRC_URLS = {}
SRC_COUNTS = {}
HEALTH_FILE = os.path.join(ROOT, "src_health.json")
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
            p = _download(url, idx)
            if p is None:
                mir = _mirror(url)
                if mir:
                    print("[兜底] 源%02d 换镜像重试 %s" % (idx, mir.split("/")[2]))
                    p = _download(mir, idx)
            return p
    finally:
        _TIMING[idx] = time.time() - t_start


def _mirror(url):
    """raw 与 jsDelivr 互为兜底镜像"""
    m = re.match(r"https://raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+)/([^/]+)/(.*)", url)
    if m:
        return "https://cdn.jsdelivr.net/gh/%s/%s@%s/%s" % (m.group(1), m.group(2), m.group(3), m.group(4))
    m = re.match(r"https://cdn\.jsdelivr\.net/gh/([\w.-]+)/([\w.-]+)@([^/]+)/(.*)", url)
    if m:
        return "https://raw.githubusercontent.com/%s/%s/%s/%s" % (m.group(1), m.group(2), m.group(3), m.group(4))
    return None


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
    _SRC_URLS.clear()
    for i, u in enumerate(urls):
        _SRC_URLS[i] = u
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



def _parse_one(args):
    """单文件解析，返回 (idx, 计数器, 行数)；给多进程用"""
    idx, f = args
    c = collections.Counter()
    n = 0
    with open(f, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            d = normalize(line)
            if d:
                # 保护域不在这里过滤：keep 阶段本来就会剔除，省掉 200 万次正则
                c[d] += 1
                n += 1
    return idx, c, n


def collect(files):
    doms = collections.Counter()
    files = sorted(files)
    # 单进程解析：Counter 序列化开销比多进程收益大，实测多进程反而更慢
    res = [_parse_one(x) for x in files]
    seen_hash, dup = {}, 0
    for idx, c, n in res:
        _SRC_STATUS[idx] = "缓存" if _TIMING.get(idx, 0) < 0.05 else "在线"
        SRC_COUNTS[idx] = n
        h = _file_hash(_cpath(_SRC_URLS.get(idx, ""))) if idx in _SRC_URLS else ""
        if h and h in seen_hash:
            dup += 1
            print("[解析] 源%02d 内容与源%02d 相同，跳过 %d 条" % (idx, seen_hash[h], n))
            continue
        if h:
            seen_hash[h] = idx
        doms.update(c)
        print("[解析] 源%02d %d 条" % (idx, n))
    if dup:
        print("[解析] 内容重复源 %d 个，已跳过" % dup)
    return doms


def _file_hash(path):
    if not path or not os.path.exists(path):
        return ""
    h = hashlib.sha1()
    with open(path, "rb") as f:
        h.update(f.read(1 << 20))
    h.update(str(os.path.getsize(path)).encode())
    return h.hexdigest()


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


def _atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def write(blocked, white):
    ver = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d %H:%M")
    p = lambda n: os.path.join(OUT, n)
    sd = sorted(blocked)
    body = "".join("0.0.0.0 %s\n" % d for d in sd)
    _atomic_write(p("hosts.txt"), "# AD-QGG Filter\n# Update: %s\n# Count: %d\n%s" % (ver, len(sd), body))
    _atomic_write(p("adguard.txt"), "! AD-QGG Filter\n! Update: %s\n! Count: %d\n%s" % (
        ver, len(sd), "".join("||%s^\n" % d for d in sd)))
    _atomic_write(p("domains.txt"), "".join(d + "\n" for d in sd))
    _atomic_write(p("all.txt"), body)
    _atomic_write(p("dnsmasq.conf"), "".join("address=/%s/#\n" % d for d in sd))
    _atomic_write(p("clash.yaml"), "payload:\n" + "".join("  - DOMAIN-SUFFIX,%s\n" % d for d in sd))
    _atomic_write(p("surge.list"), "".join("DOMAIN,%s\n" % d for d in sd))
    sw = sorted(white)
    _atomic_write(p("whitelist.txt"), "# AD-QGG 白名单\n# Count: %d\n%s" % (
        len(sw), "".join("0.0.0.0 %s\n" % d for d in sw)))
    _atomic_write(p("whitelist_adguard.txt"), "! AD-QGG 白名单\n" + "".join("@@||%s^\n" % d for d in sw))

    # 产物一致性自检：hosts / adguard / domains 三者必须等条数
    nh = sum(1 for l in open(p("hosts.txt"), encoding="utf-8") if l.startswith("0.0.0.0"))
    na = sum(1 for l in open(p("adguard.txt"), encoding="utf-8") if l.startswith("||"))
    nd = sum(1 for l in open(p("domains.txt"), encoding="utf-8") if l.strip())
    if not (nh == na == nd):
        raise RuntimeError("[自检] 产物条数不一致 hosts=%d adguard=%d domains=%d" % (nh, na, nd))
    print("[自检] 产物一致：hosts=%d adguard=%d domains=%d whitelist=%d" % (nh, na, nd, len(white)))

    # 格式语法自检（参考 AGLint 思路）：每行必须符合对应格式，防止写出畸形规则
    bad = []
    for fname, rx, skip in FORMAT_CHECKS:
        with open(p(fname), encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                s = line.rstrip("\n")
                if not s or s[0] in skip:
                    continue
                if not rx.match(s):
                    bad.append("%s:%d %s" % (fname, i, s[:60]))
                    if len(bad) > 5:
                        break
    if bad:
        for b in bad[:5]:
            print("[格式] 异常行：%s" % b)
        raise RuntimeError("[格式] 产物格式自检失败 %d 处" % len(bad))
    print("[格式] 6 个格式逐行校验通过")


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


def dns_alive(d, tries=3):
    """只有明确“域名不存在”(NXDOMAIN) 才判失效；超时/网络错误一律按存活处理，避免误删"""
    socket.setdefaulttimeout(2.0)
    for _ in range(tries):
        try:
            socket.getaddrinfo(d, None, socket.AF_INET)
            return True
        except socket.gaierror as e:
            if e.errno == socket.EAI_NONAME:   # -2 域名不存在
                continue                        # 再确认一次
            return True                         # EAI_AGAIN/EAI_FAIL 等：网络问题，不算失效
        except Exception:
            return True
    return False


def load_alive():
    """存活缓存：域名 + 最后确认日期，7 天内不重复探测"""
    p = os.path.join(ROOT, "alive.txt")
    if not os.path.exists(p):
        return {}
    out = {}
    for l in open(p, encoding="utf-8"):
        s = l.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split("\t")
        try:
            out[parts[0]] = datetime.date.fromisoformat(parts[1])
        except Exception:
            out[parts[0]] = datetime.date(2000, 1, 1)
    return out


def save_alive(items):
    p = os.path.join(ROOT, "alive.txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write("# 已验证存活的域名（域名 + 确认日期），7 天内不再重复解析\n")
        f.write("".join("%s\t%s\n" % (d, dt.isoformat()) for d, dt in sorted(items.items())))
    print("[巡检] alive.txt 记录 %d 条存活域名" % len(items))


def check_dead(blocked, workers=60, total=None, reused=0):
    """DNS 巡检：解析不出来的域名判为失效，直接从结果里删掉"""
    t = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(dns_alive, blocked))
    dead = {d for d, ok in zip(blocked, res) if not ok}
    cost = time.time() - t
    if not dead:
        print("[死域] DNS 巡检 %.1fs，无失效域名" % cost)
        return dead
    ratio_max = float(os.environ.get("DEAD_RATIO_MAX", "0.2"))
    if len(dead) > len(blocked) * ratio_max:
        print("[死域] 警告：失效 %d/%d 超过 %.0f%%，疑似 DNS 异常，本轮不删除" % (len(dead), len(blocked), ratio_max * 100))
        return set()
    alive_n = (total or len(blocked)) - len(dead)
    print("[存活率] 总数 %d / 存活 %d / 失效 %d / 存活率 %.1f%% | 实探 %d 复用 %d 耗时 %.1fs" % (
        total or len(blocked), alive_n, len(dead), alive_n * 100.0 / max(1, total or len(blocked)),
        len(blocked), reused, cost))
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



# ============ 国内域名过滤（CN_ONLY=1 时生效）============
CN_ROOTS = set("""
byteimg.com zijieapi.com snssdk.com toutiao.com douyin.com douyincdn.com douyinliving.com
bytedance.com bytecdn.com pstatp.com ixigua.com zhangyue.com fqnovel.com qznovel.com
qznovelvod.com pkoplink.com comfylink.com ugdtimg.com gromore.com pangolin-sdk-toutiao.com
pglstatp-toutiao.com byteoversea.com byteintlapi.com bytednsdoc.com bytednsdoc.cn
bytegoofy.com chenzhongtech.com zuoyebang.com feishu.cn larkoffice.com huoshan.com
volcengine.com douban.com doubanio.com
qq.com gtimg.com gtimg.cn myapp.com tencent.com tmgr.com qpic.cn weiyun.com kugou.com
tencent-cloud.com idqqimg.com weixin.com qzone.com
alicdn.com aliyun.com taobao.com tmall.com tanx.com alipay.com mmstat.com umeng.com
cnzz.com alibaba.com 1688.com tbcdn.cn taobao.net aliapp.org uc.cn ucweb.com sm.cn
alipan.com dingtalk.com alimama.com
baidu.com bdstatic.com bcebos.com baidustatic.com baiducontent.com bdurl.net iqiyi.com qiyi.com 71.am
kuaishou.com gifshow.com kwai.com yximgs.com kwcdn.com ksyun.com
huawei.com hicloud.com dbankcdn.com hwclouds.com
mi.com xiaomi.com miui.com mi-img.com xiaomi.net
163.com netease.com 126.com ydstatic.com 127.net lofter.com 163yun.com
jd.com 360buyimg.com jdcloud.com jdpay.com
meituan.com meituan.net dianping.com sankuai.com mtyapp.com
pinduoduo.com yangkeduo.com pddpic.com pdd.cn duoduoyou.com
sina.com sinaimg.cn weibo.com weibo.cn sinajs.cn
sohu.com sohu.cn itc.cn
360.com qhimg.com qhstatic.com 360safe.com qhres.com
bilibili.com hdslb.com biliapi.net bilibili.tv
vivo.com.cn vivoglobal.com vivo.com
heytapmobi.com oppomobile.com oppo.com coloros.com
honor.com hihonor.com
zhihu.com zhimg.com ximalaya.com ctrip.com 12306.cn xunlei.com 115.com
lenovo.com meizu.com hexun.com eastmoney.com ifeng.com
youku.com tudou.com pptv.com mgtv.com hunantv.com
58.com 58cdn.com.cn kuaikanmanhua.com
anythinktech.com mintegral.com tradplusad.com sigmob.com tobid.cn beizi.com
adview.cn shenshiads.com qinlinad.com bridgeoos.com zxrtb.com
juliangcili.com 4kya.com 4hnovel.com ttassfgz.com u4gdp3.com s3432pr.com
llqtv.com lysl2020.com xhsdns.cn
""".split())

# 公共后缀（PSL 精简版）：含 .cn 省级后缀，避免把 xxx.bj.cn 误当整域
SLD2 = ("com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
        "bj.cn", "sh.cn", "tj.cn", "cq.cn", "he.cn", "sx.cn", "nm.cn", "ln.cn",
        "jl.cn", "hl.cn", "js.cn", "zj.cn", "ah.cn", "fj.cn", "jx.cn", "sd.cn",
        "ha.cn", "hb.cn", "hn.cn", "gd.cn", "gx.cn", "hi.cn", "sc.cn", "gz.cn",
        "yn.cn", "xz.cn", "sn.cn", "gs.cn", "qh.cn", "nx.cn", "xj.cn", "tw.cn",
        "hk.cn", "mo.cn", "com.hk", "org.hk", "net.hk")


def root_of2(h):
    p = h.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in SLD2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def is_cn_strict(d, doms):
    """厂商主域直接留；其余 .cn 必须带广告特征或在源里出现≥2次"""
    if root_of2(d) in CN_ROOTS:
        return True
    if not d.endswith(".cn"):
        return False
    return bool(ad_like(d)) or doms.get(d, 0) >= 2



VENDORS = {
    "byteimg.com": "字节跳动 ByteDance", "zijieapi.com": "字节跳动 ByteDance",
    "snssdk.com": "字节跳动 ByteDance", "toutiao.com": "字节跳动 ByteDance",
    "douyin.com": "字节跳动 ByteDance", "bytedance.com": "字节跳动 ByteDance",
    "pstatp.com": "字节跳动 ByteDance", "pglstatp-toutiao.com": "字节跳动 ByteDance",
    "pangolin-sdk-toutiao.com": "字节跳动 ByteDance", "gromore.com": "字节跳动 ByteDance",
    "ugdtimg.com": "字节跳动 ByteDance", "qznovelvod.com": "字节跳动 ByteDance",
    "qznovel.com": "字节跳动 ByteDance", "fqnovel.com": "字节跳动 ByteDance",
    "bytecdn.com": "字节跳动 ByteDance", "bytegoofy.com": "字节跳动 ByteDance",
    "qq.com": "腾讯 Tencent", "gtimg.com": "腾讯 Tencent", "gtimg.cn": "腾讯 Tencent",
    "kugou.com": "腾讯 Tencent", "tencent.com": "腾讯 Tencent", "qpic.cn": "腾讯 Tencent",
    "alicdn.com": "阿里 Alibaba", "aliyun.com": "阿里 Alibaba", "umeng.com": "阿里 Alibaba",
    "tanx.com": "阿里 Alibaba", "taobao.com": "阿里 Alibaba", "alibaba.com": "阿里 Alibaba",
    "uc.cn": "阿里 Alibaba", "sm.cn": "阿里 Alibaba",
    "baidu.com": "百度 Baidu", "bdstatic.com": "百度 Baidu", "iqiyi.com": "百度 Baidu",
    "kuaishou.com": "快手 Kuaishou", "yximgs.com": "快手 Kuaishou", "gifshow.com": "快手 Kuaishou",
    "huawei.com": "华为 Huawei", "hicloud.com": "华为 Huawei",
    "mi.com": "小米 Xiaomi", "miui.com": "小米 Xiaomi", "xiaomi.com": "小米 Xiaomi",
    "163.com": "网易 NetEase", "126.com": "网易 NetEase", "ydstatic.com": "网易 NetEase",
    "jd.com": "京东 JD", "360buyimg.com": "京东 JD",
    "meituan.com": "美团 Meituan", "dianping.com": "美团 Meituan", "sankuai.com": "美团 Meituan",
    "pinduoduo.com": "拼多多 Pinduoduo", "pddpic.com": "拼多多 Pinduoduo",
    "sina.com": "新浪 Sina", "sinaimg.cn": "新浪 Sina", "weibo.com": "新浪 Sina",
    "sohu.com": "搜狐 Sohu", "360.com": "奇虎360", "qhimg.com": "奇虎360",
    "bilibili.com": "哔哩哔哩 Bilibili", "hdslb.com": "哔哩哔哩 Bilibili",
    "vivo.com.cn": "vivo", "vivoglobal.com": "vivo",
    "heytapmobi.com": "OPPO欢太", "oppomobile.com": "OPPO欢太", "coloros.com": "OPPO欢太",
    "honor.com": "荣耀 Honor", "ximalaya.com": "喜马拉雅",
    "anythinktech.com": "TopOn聚合", "mintegral.com": "Mintegral", "sigmob.com": "Sigmob",
    "tradplusad.com": "TradPlus", "beizi.com": "倍孜", "tobid.cn": "ToBid",
    "applovin.com": "AppLovin", "unity3d.com": "Unity Ads", "pangle.io": "Pangle海外",
}


def vendor_of(d):
    r = root_of2(d)
    return VENDORS.get(r, "其他 Other")


def vendor_summary(blocked, subs_per_root=10, roots_per_vendor=5):
    groups = collections.defaultdict(lambda: collections.defaultdict(list))
    for d in blocked:
        groups[vendor_of(d)][root_of2(d)].append(d)
    for v in sorted(groups, key=lambda x: -sum(len(y) for y in groups[x].values())):
        roots = groups[v]
        print("[厂商] %-20s 主域 %d / 规则 %d" % (v, len(roots), sum(len(x) for x in roots.values())))
        for r, subs in sorted(roots.items(), key=lambda kv: -len(kv[1]))[:roots_per_vendor]:
            sample = " ".join(sorted(subs)[:3])
            tail = " ..." if len(subs) > 3 else ""
            print("[厂商]   %-36s (%d) %s%s" % (r, len(subs), sample, tail))


def source_health():
    """记录每个源最近 5 轮条数；连续 3 轮 0 条 → 疑似失效源"""
    data = {}
    if os.path.exists(HEALTH_FILE):
        try:
            data = json.load(open(HEALTH_FILE, encoding="utf-8"))
        except Exception:
            data = {}
    bad = []
    for idx, url in _SRC_URLS.items():
        n = SRC_COUNTS.get(idx, 0)
        rec = data.get(url) or {}
        hist = (rec.get("hist") or [])[-4:] + [n]
        rec["hist"] = hist
        rec["last"] = n
        data[url] = rec
        if len(hist) >= 3 and all(x == 0 for x in hist[-3:]):
            bad.append(url)
    try:
        with open(HEALTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
    except Exception as e:
        print("[源质量] 记录失败 %s" % e)
    empty = [u for i, u in _SRC_URLS.items() if SRC_COUNTS.get(i, 0) == 0]
    print("[源质量] 本轮空结果 %d / 共 %d 个源" % (len(empty), len(_SRC_URLS)))
    if bad:
        print("[源质量] 警告：%d 个源连续 3 轮 0 条，疑似失效" % len(bad))
        for u in bad[:10]:
            print("[源质量]   %s" % u)
    return bad


def prev_rule_count():
    p = os.path.join(OUT, "hosts.txt")
    if not os.path.exists(p):
        return 0
    with open(p, encoding="utf-8") as f:
        return sum(1 for l in f if l.startswith("0.0.0.0"))


def white_conflicts(blocked, white, extra):
    out = []
    for d in blocked:
        if d in extra:
            continue
        parts = d.split(".")
        if any(".".join(parts[i:]) in white for i in range(1, len(parts) - 1)):
            out.append(d)
    if out:
        print("[冲突] %d 条被白名单父域放行，前 5 条：%s" % (len(out), ", ".join(sorted(out)[:5])))
    else:
        print("[冲突] 无白名单冲突")
    return out


STEPS_OK = []


def run_step(no, name, fn, *args, **kw):
    """每个功能独立跑：单步失败只影响这一步，核心步骤失败才中止整轮"""
    critical = kw.get("critical", True)
    t = time.time()
    try:
        r = fn(*args)
        print("[%02d] %-10s 完成 %.1fs" % (no, name, time.time() - t))
        STEPS_OK.append(name)
        return r
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("[%02d] %-10s 失败 %.1fs：%s" % (no, name, time.time() - t, e))
        if critical:
            raise
        print("[%02d] %s 跳过，后续步骤继续" % (no, name))
        return None


# ---------------------------------------------------------------- 各步骤实现
def load_lists():
    """读取 whitelist.txt 与 custom.txt"""
    white, extra = set(), set()
    if os.path.exists(WHITE):
        for l in open(WHITE, encoding="utf-8"):
            d = normalize(l)
            if d:
                white.add(d)
    if os.path.exists(CUSTOM):
        for l in open(CUSTOM, encoding="utf-8"):
            d = normalize(l)
            if d:
                extra.add(d)
    print("[白名单] whitelist %d 条 / custom %d 条" % (len(white), len(extra)))
    return white, extra


def build_candidates(doms, white, extra):
    """四道排除 + 国内过滤 + 限额 + 扣死域 + 白名单父域修复 + eTLD+1 归并"""
    keep = set()
    for d, c in doms.items():
        if d in white or is_protected(d):
            continue
        if SAFE_WORDS.search(d) and not ad_like(d):
            continue   # 业务接口，非广告特征
        if SHARED_INFRA.search(d) and d not in extra:
            continue   # 共享基建（对象存储/CDN 父域）整域拦截会连坐正常业务
        if c >= 2 or (ad_like(d) and not SHARED_INFRA.search(d)):
            keep.add(d)
    if os.environ.get("CN_ONLY", "0") == "1":
        before = len(keep)
        keep = {d for d in keep if is_cn_strict(d, doms)}
        cn_dom = [d for d in keep if not (root_of2(d) in CN_ROOTS)]
        n_ad = sum(1 for d in cn_dom if ad_like(d))
        n_cnt2 = sum(1 for d in cn_dom if doms.get(d, 0) >= 2)
        n_cnt3 = sum(1 for d in cn_dom if doms.get(d, 0) >= 3)
        print("[国内] 上游 %d 条 → 保留国内 %d 条（剔除非国内 %d 条）" % (before, len(keep), before - len(keep)))
        print("[国内] 其中 .cn 非厂商 %d 条：广告特征 %d / 出现≥2次 %d / ≥3次 %d" % (
            len(cn_dom), n_ad, n_cnt2, n_cnt3))
    cap = CN_TARGET if os.environ.get("CN_ONLY", "0") == "1" else TARGET
    if len(keep) > cap:
        ranked = sorted(keep, key=lambda d: (ad_like(d), doms[d], -len(d)), reverse=True)
        keep = set(ranked[:cap])
        print("[限额] 截断到 %d 条" % cap)
    dead = set(load_dead().keys())
    blocked = (keep | extra) - dead
    if dead:
        print("[死域] 跳过 %d 条已确认无效的域名" % len(dead & (keep | extra)))

    def covered_by_white(d):
        parts = d.split(".")
        return any(".".join(parts[i:]) in white for i in range(len(parts) - 1))

    fixed = {d for d in (blocked - extra) if covered_by_white(d)}   # custom 优先，不被白名单父域吃掉
    if fixed:
        print("[修复] 剔除 %d 个被白名单父域覆盖的域名" % len(fixed))
        blocked -= fixed
    blocked, dropped = collapse(blocked, white)
    if dropped:
        print("[归并] 去掉 %d 个冗余子域" % dropped)
    print("[候选] 待定 %d 条" % len(blocked))
    return blocked


BASELINE = os.path.join(ROOT, "baseline.txt")


def load_baseline():
    if not os.path.exists(BASELINE):
        return set()
    return {l.strip() for l in open(BASELINE, encoding="utf-8") if l.strip() and not l.startswith("#")}


def save_baseline(blocked):
    with open(BASELINE, "w", encoding="utf-8") as f:
        f.write("# 增量基线：上一轮实际发布的规则，下一轮在此基础上增删\n")
        f.write("".join("%s\n" % d for d in sorted(blocked)))


def merge_incremental(fresh, extra, white):
    """增量合并：上游新出现的加入；上游消失但仍存活的旧规则保留，由死域探测自然剔除"""
    old = load_baseline()
    if not old:
        print("[增量] 无基线，首轮全量写入")
        return fresh
    dead = set(load_dead().keys())
    def covered_by_white(d):
        parts = d.split(".")
        return any(".".join(parts[i:]) in white for i in range(len(parts) - 1))
    new = fresh - old
    gone = old - fresh
    gone -= extra                       # custom 永不删
    gone = {d for d in gone if not covered_by_white(d)}
    merged = (old | fresh) - dead - gone
    print("[增量] 上游新增 %d 条 / 沿用旧规则 %d 条 / 剔除上游消失 %d 条（custom、白名单、存活保护）→ 本轮 %d 条" % (
        len(new), len(old & fresh), len(gone - merged), len(merged)))
    return merged


PENDING = os.path.join(ROOT, "pending.txt")


def load_pending():
    out = {}
    if not os.path.exists(PENDING):
        return out
    for l in open(PENDING, encoding="utf-8"):
        s = l.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split("\t")
        try:
            out[parts[0]] = datetime.date.fromisoformat(parts[1])
        except Exception:
            pass
    return out


def save_pending(items):
    with open(PENDING, "w", encoding="utf-8") as f:
        f.write("# 首轮只出现一次的域名（域名 + 首次出现日期），第二轮仍出现即放行\n")
        f.write("".join("%s\t%s\n" % (d, dt.isoformat()) for d, dt in sorted(items.items())))
    print("[观察期] pending.txt 记录 %d 条" % len(items))


def apply_pending(blocked, doms, extra):
    """新域观察期：只出现 1 次且无广告特征词的域名，首轮先不上线，下轮仍出现才发布"""
    today = datetime.date.today()
    pend = load_pending()
    hold = set()
    for d in blocked:
        if d in extra or doms.get(d, 0) >= 2 or ad_like(d):
            continue
        if d not in pend:
            hold.add(d)
    kept = {d: dt for d, dt in pend.items() if (today - dt).days < 30}
    for d in hold:
        kept[d] = today
    save_pending(kept)
    if hold:
        print("[观察期] 首轮观察 %d 条单源无特征域，本轮暂不发布" % len(hold))
        for d in sorted(hold)[:5]:
            print("[观察期]   %s" % d)
    else:
        print("[观察期] 无新增待观察域名")
    return blocked - hold


def probe_blocked(blocked):
    """分批 DNS 存活探测；返回 (存活集合, 失效集合)"""
    if os.environ.get("DNS_CHECK", "1") != "1":
        print("[巡检] DNS_CHECK=0，跳过探测")
        return blocked, set()
    today = datetime.date.today()
    old_alive = load_alive()
    cands = sorted(blocked)
    fresh = [d for d in cands if d not in old_alive or (today - old_alive[d]).days >= 7]
    limit = max(200, len(cands) // 4)
    if len(fresh) > limit:
        print("[巡检] 到期 %d 条，本轮只重验 %d 条（分批轮转）" % (len(fresh), limit))
        fresh = fresh[:limit]
    reused = len(cands) - len(fresh)
    if reused:
        print("[巡检] 沿用缓存 %d 条，实际探测 %d 条" % (reused, len(fresh)))
    dead = set()
    if fresh:
        dead = check_dead(fresh, total=len(cands), reused=reused)
        blocked = blocked - dead
    else:
        print("[存活率] 总数 %d / 全部 7 天内已验证存活，跳过探测" % len(cands))
    now_alive = {d: old_alive[d] for d in blocked if d in old_alive}
    for d in fresh:
        if d not in dead:
            now_alive[d] = today
    save_alive(now_alive)
    return blocked, dead


FORMAT_CHECKS = (
    ("hosts.txt", re.compile(r"^0\.0\.0\.0 [a-z0-9.-]+$"), "#"),
    ("adguard.txt", re.compile(r"^\|\|[a-z0-9.-]+\^$"), "!"),
    ("dnsmasq.conf", re.compile(r"^address=/[a-z0-9.-]+/#$"), "#"),
    ("clash.yaml", re.compile(r"^  - DOMAIN-SUFFIX,[a-z0-9.-]+$"), "#py"),
    ("surge.list", re.compile(r"^DOMAIN,[a-z0-9.-]+$"), "#"),
    ("whitelist_adguard.txt", re.compile(r"^@@\|\|[a-z0-9.-]+\^$"), "!"),
)

SRC_STATE = os.path.join(ROOT, "src_state.json")


def source_staleness(stale_days=7):
    """跟踪每个源的内容指纹：同一份内容超过 7 天没变 → 疑似停更/被缓存钉住"""
    today = datetime.date.today()
    state = {}
    if os.path.exists(SRC_STATE):
        try:
            state = json.load(open(SRC_STATE, encoding="utf-8"))
        except Exception:
            state = {}
    stale = []
    for idx, url in _SRC_URLS.items():
        h = _file_hash(_cpath(url))
        if not h:
            continue
        rec = state.get(url) or {}
        if rec.get("sha1") == h:
            since = rec.get("since") or today.isoformat()
            age = (today - datetime.date.fromisoformat(since)).days
            rec["age"] = age
            if age >= stale_days:
                stale.append((url, age))
        else:
            rec = {"sha1": h, "since": today.isoformat(), "age": 0}
        state[url] = rec
    try:
        with open(SRC_STATE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=1)
    except Exception as e:
        print("[停更] 记录失败 %s" % e)
    if stale:
        print("[停更] 警告：%d 个源内容超过 %d 天未更新" % (len(stale), stale_days))
        for u, a in stale[:8]:
            print("[停更]   %s（%d 天）" % (u, a))
    else:
        print("[停更] 无长期未更新的源（阈值 %d 天）" % stale_days)
    return stale


MUST_KEEP = ("qq.com", "weixin.qq.com", "alipay.com", "taobao.com", "tmall.com",
             "jd.com", "12306.cn", "gov.cn", "passport.jd.com", "pay.qq.com",
             "baidu.com", "weibo.com", "m.taobao.com")


def regression_check(blocked, white, extra=()):
    """产物上线前的回归断言：关键业务域不能被拦、规则里不能有 IP/非法域"""
    bad = []
    for d in MUST_KEEP:
        if d in blocked:
            bad.append("关键业务域被拦：%s" % d)
    hit_white = [d for d in blocked if d in white]
    if hit_white:
        bad.append("白名单域名出现在规则里：%s" % ", ".join(hit_white[:3]))
    ip_like = [d for d in blocked if not d.strip("0123456789.")]
    if ip_like:
        bad.append("规则里混入 IP：%s" % ", ".join(ip_like[:3]))
    label = [d for d in blocked if "." not in d or len(d) > 79]
    if label:
        bad.append("非法域名：%s" % ", ".join(label[:3]))
    parents = {d: 1 for d in blocked}
    nested = []
    for d in blocked:
        if d in extra or SHARED_INFRA.search(d):   # custom 显式规则 / 共享基建允许与父域并存
            continue
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in parents and ".".join(parts[i:]) != d:
                nested.append(d)
                break
    if nested:
        bad.append("父子域同时存在：%s" % ", ".join(nested[:3]))
    if bad:
        for b in bad:
            print("[断言] 失败：%s" % b)
        raise RuntimeError("回归断言未通过（%d 项）" % len(bad))
    print("[断言] 通过：关键域 %d 个未被拦 / 无 IP / 无非法域 / 无父子并存" % len(MUST_KEEP))
    return True


def check_rollback(blocked):
    """条数波动超过 ±40% → 本轮不写产物"""
    prev = prev_rule_count()
    cand = len(blocked)
    if prev >= 500 and abs(cand - prev) / float(prev) > 0.4:
        print("[回滚] 条数 %d → %d（波动 %.0f%%，超出 ±40%%），本轮不写产物，保留上一版" % (
            prev, cand, abs(cand - prev) * 100.0 / prev))
        return False
    print("[回滚] 条数 %d → %d，波动正常" % (prev, cand))
    return True


def main():
    t0 = time.time()
    files = run_step(1, "读取源", read_sources)
    print("[计时] 下载+准备 %.1fs" % (time.time() - t0))
    t1 = time.time()
    doms = run_step(2, "解析规则", collect, files)
    print("[计时] 解析 %.1fs" % (time.time() - t1))
    white, extra = run_step(3, "加载清单", load_lists)
    blocked = run_step(4, "生成候选", build_candidates, doms, white, extra)

    blocked = run_step(5, "观察期", apply_pending, blocked, doms, extra, critical=False) or blocked
    blocked = merge_incremental(blocked, extra, white)
    run_step(6, "源质量", source_health, critical=False)
    run_step(7, "源停更", source_staleness, critical=False)
    probed = run_step(8, "存活探测", probe_blocked, blocked, critical=False)
    dead = set()
    if probed:
        blocked, dead = probed

    if not run_step(9, "异常回滚", check_rollback, blocked, critical=False):
        print("[完成] 用时 %.1f 秒（已回滚，产物保持上一版）" % (time.time() - t0))
        return 1

    run_step(10, "死域入库", save_dead, dead, critical=False)
    run_step(11, "冲突检测", white_conflicts, blocked, white, extra, critical=False)
    run_step(12, "厂商归类", vendor_summary, blocked, critical=False)
    run_step(13, "回归断言", regression_check, blocked, white, extra)
    run_step(14, "写出产物", write, blocked, white)
    save_baseline(blocked)
    print("[增量] baseline.txt 已更新 %d 条" % len(blocked))
    print("[完成] 用时 %.1f 秒，%d 个步骤全通过" % (time.time() - t0, len(STEPS_OK)))
    return 0


if __name__ == "__main__":
    main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)
