#!/usr/bin/env python3
"""事后修剪：拿刚发布的全量规则做 DNS 校验，剔掉死域后重新生成各格式

不重新合并上游，所以只花校验的时间（约 50 秒）。
"""
import os, sys, json, socket, importlib.util, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASE = "https://github.com/o0001e/ad-rules/releases/download/rule/hosts.txt"
DEAD = os.path.join(ROOT, "dead.txt")
DOH = "https://223.5.5.5/resolve"
UA = {"User-Agent": "AdQggTrim/1.0"}

spec = importlib.util.spec_from_file_location("adblock", os.path.join(ROOT, "adblock.py"))
adblock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adblock)


def fetch_domains():
    req = urllib.request.Request(RELEASE, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read().decode("utf-8", "ignore")
    return [l.split()[1] for l in data.splitlines() if l.startswith("0.0.0.0")]


def sys_alive(d):
    try:
        socket.gethostbyname(d); return True
    except socket.gaierror as e:
        return False if getattr(e, "errno", None) == -2 else None
    except Exception:
        return None


def doh_alive(d):
    try:
        req = urllib.request.Request(DOH + "?name=%s&type=A" % d, headers=UA)
        with urllib.request.urlopen(req, timeout=5) as r:
            st = json.loads(r.read()).get("Status")
        return False if st == 3 else (True if st == 0 else None)
    except Exception:
        return None


def check(d):
    v = sys_alive(d)
    return d, v if v is not None else doh_alive(d)


def main():
    doms = fetch_domains()
    print("[修剪] 取到 %d 条待校验域名" % len(doms), flush=True)
    socket.setdefaulttimeout(2.0)
    dead, alive, unknown = [], 0, 0
    with ThreadPoolExecutor(max_workers=200) as ex:
        for d, v in ex.map(check, doms):
            if v is False: dead.append(d)
            elif v is True: alive += 1
            else: unknown += 1
    print("[修剪] 存活 %d / 死亡 %d / 无法判定 %d（存活率 %.1f%%）"
          % (alive, len(dead), unknown, alive * 100.0 / max(len(doms), 1)))
    if len(dead) < 50:
        print("[修剪] 死亡数异常偏少，放弃修剪")
        return
    with open(DEAD, "w", encoding="utf-8") as f:
        f.write("# 已确认 NXDOMAIN 的域名\n")
        f.write("".join(d + "\n" for d in sorted(dead)))
    blocked = {d for d in doms if d not in set(dead)}
    white = set()
    if os.path.exists(os.path.join(ROOT, "whitelist.txt")):
        for l in open(os.path.join(ROOT, "whitelist.txt"), encoding="utf-8"):
            d = adblock.normalize(l)
            if d: white.add(d)
    apps = json.load(open(os.path.join(ROOT, "app_list.json"), encoding="utf-8"))
    adblock.write(blocked, white, apps)
    print("[修剪] 重新生成产物完成，%d 条" % len(blocked))


if __name__ == "__main__":
    main()
