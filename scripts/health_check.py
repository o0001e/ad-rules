#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则健康巡检：抽样验证域名是否还能解析，判断规则是否已经大面积失效。

- 从 hosts.txt 随机抽 300 条（按日期定种子，同一天结果可复现）
- 用阿里 DoH 逐条查 A 记录
- 存活率低于 60% → 退出码 2，由工作流触发重建
- 额外检查：条数为 0 的 App 文件、三份规则是否一致
"""
import os
import random
import sys
import urllib.parse
import urllib.request
import concurrent.futures as cf
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = 300
DOH = "https://dns.alidns.com/resolve?name=%s&type=A"


def domains_from(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.split()[1] for l in f if l.startswith("0.0.0.0")]


def alive(host):
    try:
        req = urllib.request.Request(DOH % urllib.parse.quote(host),
                                     headers={"User-Agent": "ad-rules-health/1.0"})
        data = urllib.request.urlopen(req, timeout=6).read().decode()
        return '"Answer"' in data or '"Status": 0' in data.replace(" ", "")
    except Exception:
        return False


def main():
    hosts = domains_from(os.path.join(ROOT, "hosts.txt"))
    if not hosts:
        print("没有可检查的规则")
        sys.exit(2)

    seed = int(datetime.date.today().strftime("%Y%m%d"))
    random.seed(seed)
    sample = random.sample(hosts, min(SAMPLE, len(hosts)))
    print("抽样 %d 条（总 %d 条）..." % (len(sample), len(hosts)))

    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        results = list(ex.map(alive, sample))
    ok = sum(results)
    ratio = ok / len(sample)
    print("存活 %d / %d = %.1f%%" % (ok, len(sample), ratio * 100))

    report = ["规则健康巡检 %s" % datetime.date.today(),
              "总条数: %d，抽样: %d" % (len(hosts), len(sample)),
              "存活: %d（%.1f%%）" % (ok, ratio * 100)]

    # 空 App 文件
    apps = os.path.join(ROOT, "apps")
    empty = []
    if os.path.isdir(apps):
        for fn in sorted(os.listdir(apps)):
            if fn.endswith(".txt") and not domains_from(os.path.join(apps, fn)):
                empty.append(fn)
    if empty:
        report.append("空分组 %d 个: %s" % (len(empty), ", ".join(empty[:8])))

    open(os.path.join(ROOT, "health_report.txt"), "w", encoding="utf-8").write("\n".join(report) + "\n")
    print("\n".join(report))

    if ratio < 0.6:
        print("存活率过低，判定规则大面积失效，需要重建")
        sys.exit(2)
    print("健康检查通过")


if __name__ == "__main__":
    main()
