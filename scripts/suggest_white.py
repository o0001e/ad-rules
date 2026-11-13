#!/usr/bin/env python3
"""白名单建议：从真机 DNS 日志里挖高频、真实在用的域名

输出 rules/whitelist_suggested.txt，只做建议，不自动写入 whitelist.txt。
"""
import os, csv, collections, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    "/home/user/.doubao/agent_mode/workspace/.sessions/17540679856130/attachments",
    "blockads_dns_logs_20261113_175037.csv")
HOSTS = os.path.join(ROOT, "rules", "hosts.txt")
WHITE = os.path.join(ROOT, "whitelist.txt")
OUT = os.path.join(ROOT, "rules", "whitelist_suggested.txt")


def load_domains(path):
    out = set()
    if os.path.exists(path):
        for l in open(path, encoding="utf-8"):
            l = l.strip()
            if l and not l.startswith("#"):
                out.add(l.split()[-1].lower())
    return out


def main():
    if not os.path.exists(LOG):
        print("找不到 DNS 日志：%s" % LOG)
        return
    blocked = load_domains(HOSTS)
    white = load_domains(WHITE)
    cnt = collections.Counter()
    with open(LOG, encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            d = (row.get("Domain") or "").strip().lower().rstrip(".")
            if d and "." in d:
                cnt[d] += 1
    cand = []
    for d, c in cnt.most_common():
        if d in blocked or d in white:
            continue
        parts = d.split(".")
        # 父域已被拦截 → 说明是广告域的子域，不建议
        if any(".".join(parts[i:]) in blocked for i in range(1, len(parts) - 1)):
            continue
        if c < 5:
            break
        cand.append((d, c))
        if len(cand) >= 300:
            break
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# 白名单建议：真实 DNS 日志中出现、且当前未被拦截的高频域名\n")
        f.write("# 域名\t请求次数\n")
        for d, c in cand:
            f.write("%s\t%d\n" % (d, c))
    print("[建议] 输出 %d 条到 %s" % (len(cand), OUT))


if __name__ == "__main__":
    main()
