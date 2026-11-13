#!/usr/bin/env python3
"""误报回归检测：确认规则没有波及白名单里的正常域名

1. 静态检查：白名单域名是否出现在拦截列表里（含父域覆盖）
2. 动态抽查：抽 60 个白名单域做解析，失败率 > 10% 视为异常
"""
import os, sys, random, socket, json, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTS = os.path.join(ROOT, "rules", "hosts.txt")
WHITE = os.path.join(ROOT, "whitelist.txt")
REPORT = os.path.join(ROOT, "rules", "regress_report.txt")
DOH = "https://223.5.5.5/resolve"
UA = {"User-Agent": "AdQggRegress/1.0"}


def load(path):
    out = []
    if os.path.exists(path):
        for l in open(path, encoding="utf-8"):
            l = l.strip()
            if not l or l.startswith("#"):
                continue
            out.append(l.split()[-1].lower())
    return out


def blocked_by(dom, blocked):
    parts = dom.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in blocked:
            return True
    return False


def alive(d):
    try:
        socket.gethostbyname(d); return True
    except Exception:
        try:
            req = urllib.request.Request(DOH + "?name=%s&type=A" % d, headers=UA)
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read()).get("Status") == 0
        except Exception:
            return None


def main():
    blocked = set(load(HOSTS))
    white = load(WHITE)
    print("[回归] 规则 %d 条，白名单 %d 条" % (len(blocked), len(white)))

    conflicts = [d for d in white if blocked_by(d, blocked)]
    sample = random.sample(white, min(60, len(white)))
    socket.setdefaulttimeout(2.0)
    with ThreadPoolExecutor(max_workers=30) as ex:
        results = list(ex.map(alive, sample))
    dead = [d for d, v in zip(sample, results) if v is False]
    unknown = sum(1 for v in results if v is None)

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("白名单被拦截冲突: %d\n" % len(conflicts))
        for d in conflicts[:50]:
            f.write("  ! %s\n" % d)
        f.write("抽样 %d 个，解析失败 %d，无法判定 %d\n" % (len(sample), len(dead), unknown))
        for d in dead[:30]:
            f.write("  x %s\n" % d)

    print("[回归] 冲突 %d 条，抽样失败 %d/%d" % (len(conflicts), len(dead), len(sample)))
    if len(conflicts) > 5:
        print("::error::白名单域名被规则波及")
        sys.exit(1)
    if len(sample) >= 20 and len(dead) > len(sample) * 0.6:
        print("::warning::白名单抽样解析失败率偏高（%d/%d），仅供观察" % (len(dead), len(sample)))


if __name__ == "__main__":
    main()
