#!/usr/bin/env python3
"""Gitee 体检：逐个 GET 产物，报告哪些被内容风控 451"""
import sys, urllib.request
BASE = "https://gitee.com/ADS9/ad/raw/m/"
FILES = ["rules/hosts.txt", "rules/whitelist.txt", "rules/all.txt",
         "rules/adguard.txt", "rules/domains.txt", "rules/dnsmasq.conf", "all.txt"]
UA = {"User-Agent": "Mozilla/5.0 AdQgg"}
bad = []
for f in FILES:
    try:
        req = urllib.request.Request(BASE + f, headers=UA)
        with urllib.request.urlopen(req, timeout=20) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        code = "ERR"
    print("%-24s %s" % (f, code))
    if code != 200:
        bad.append(f)
if bad:
    print("::warning::Gitee 以下文件不可用（内容风控）：%s" % ", ".join(bad))
