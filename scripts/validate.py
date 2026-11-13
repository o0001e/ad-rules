#!/usr/bin/env python3
"""DNS 校验：每周跑一次，把确认不存在的域名写进 dead.txt

判定规则（保守，避免误杀）：
  - 系统解析 NXDOMAIN（errno -2）→ 确定死亡
  - 系统解析超时/无网络 → 用阿里 DoH 复核一次
  - DoH 明确 NXDOMAIN（Status 3）→ 死亡
  - 其余（超时、限流、SERVFAIL）→ 一律当存活，不清除
"""
import os, sys, socket, json, errno, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAINS = os.path.join(ROOT, "rules", "domains.txt")
DEAD = os.path.join(ROOT, "dead.txt")
DOH = "https://223.5.5.5/resolve"
UA = {"User-Agent": "AdQggValidator/1.0"}


def sys_alive(d):
    """返回 True/False/None（None=无法判定）"""
    try:
        socket.gethostbyname(d)
        return True
    except socket.gaierror as e:
        if getattr(e, "errno", None) == -2:
            return False
        return None
    except Exception:
        return None


def doh_alive(d):
    try:
        req = urllib.request.Request(DOH + "?name=%s&type=A" % d, headers=UA)
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        st = data.get("Status")
        if st == 3:
            return False
        if st == 0:
            return True
        return None
    except Exception:
        return None


def check(d):
    v = sys_alive(d)
    if v is not None:
        return d, v
    return d, doh_alive(d)


def main():
    if not os.path.exists(DOMAINS):
        sys.exit("[校验] 没有 rules/domains.txt，先跑 adblock.py")
    doms = [l.strip() for l in open(DOMAINS, encoding="utf-8") if l.strip()]
    print("[校验] 待检 %d 条…" % len(doms), flush=True)
    socket.setdefaulttimeout(2.0)
    dead, alive, unknown = [], 0, 0
    with ThreadPoolExecutor(max_workers=200) as ex:
        for d, v in ex.map(check, doms):
            if v is False:
                dead.append(d)
            elif v is True:
                alive += 1
            else:
                unknown += 1
    print("[校验] 存活 %d / 死亡 %d / 无法判定 %d（存活率 %.1f%%）"
          % (alive, len(dead), unknown, alive * 100.0 / max(len(doms), 1)))
    with open(DEAD, "w", encoding="utf-8") as f:
        f.write("# 已确认 NXDOMAIN 的域名，合并时跳过\n")
        f.write("".join(d + "\n" for d in sorted(dead)))
    print("[校验] 已写入 dead.txt（%d 条）" % len(dead))


if __name__ == "__main__":
    main()
