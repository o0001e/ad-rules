#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
按 App 重建 apps/ 分组规则文件。
读取爬虫输出 .publish/d 与 app_list.json，按根域名归属把拦截域名分组写出。
可独立运行，不依赖重新爬取，用于爬虫中断后抢救结果。

用法：
    python3 scripts/gen_apps.py
"""
import json
import os, time
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUB_D = os.path.join(ROOT, ".cache", "crawl", "d")
APP_LIST = os.path.join(ROOT, "app_list.json")
APPS_DIR = os.path.join(ROOT, "rules", "apps")


HOSTS_TXT = os.path.join(ROOT, "hosts.txt")


def load_blocked():
    """合并后的 hosts.txt 是完整规则集，.publish/d 只是爬虫那部分。
    两者取并集，避免上游源贡献的域名不参与分组。"""
    doms = set()
    if os.path.exists(HOSTS_TXT):
        with open(HOSTS_TXT, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("0.0.0.0"):
                    doms.add(line.split()[1].strip())
    if os.path.exists(PUB_D):
        with open(PUB_D, encoding="utf-8") as f:
            doms |= {line.strip() for line in f if line.strip()}
    if not doms:
        sys.exit("[失败] hosts.txt 与 .publish/d 都不存在，请先跑合并或爬虫")
    print("[分组] 可用域名来源: hosts.txt + .publish/d，合计 %d 条" % len(doms))
    return doms


AUTO_LIST = os.path.join(ROOT, "app_list_auto.json")


def load_apps():
    data = {}
    for pth in (APP_LIST, AUTO_LIST):
        if os.path.exists(pth):
            try:
                data.update(json.load(open(pth, encoding="utf-8")))
            except Exception:
                pass
    result = {}
    for name, hosts in data.items():
        if isinstance(hosts, str):
            hosts = [hosts]
        result[name] = [h.strip() for h in hosts if h.strip()]
    return result


def safe_name(name):
    return name.replace("/", "_").replace(" ", "_")


def main():
    blocked = load_blocked()
    apps = load_apps()
    os.makedirs(APPS_DIR, exist_ok=True)

    # 先统计现有产物的规模，用于防止"爬虫只抓到一点点就覆盖"的灾难
    old_total = 0
    old_files = 0
    for fn in os.listdir(APPS_DIR):
        if not fn.endswith(".txt"):
            continue
        old_files += 1
        try:
            with open(os.path.join(APPS_DIR, fn), encoding="utf-8") as f:
                old_total += sum(1 for l in f if l.startswith("0.0.0.0"))
        except Exception:
            pass

    # 先把分组全部算出来，再决定要不要落盘
    groups = {}
    for company, hosts in apps.items():
        keep = sorted(
            h for h in blocked
            if any(h == d or h.endswith("." + d) for d in hosts)
        )
        if keep:
            groups[company] = keep

    # 上游全量域名按注册根域归组，补足到 1000 个分组（对上 app_list 的优先）
    MAX_GROUPS = 5000   # 每个厂商一组，不人为截断
    MULTI = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw"}

    def root_of(host):
        parts = host.split(".")
        if len(parts) < 2:
            return host
        if ".".join(parts[-2:]) in MULTI and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    matched = set()
    for keep in groups.values():
        matched |= set(keep)

    leftover = {}
    for h in blocked - matched:
        leftover.setdefault(root_of(h), []).append(h)

    auto_names = {}
    for root, doms in leftover.items():
        cand = apps.get(root) or apps.get(root.split(".")[0])
        name = root if not cand else None
        if cand:
            # 根域能对上某个 App 的域名列表，就并进那个已有分组
            for company, hosts in apps.items():
                if root in hosts:
                    auto_names[root] = company
                    groups.setdefault(company, [])
                    groups[company] = sorted(set(groups[company]) | set(doms))
                    break
            continue
        auto_names[root] = root

    for root, doms in leftover.items():
        nm = auto_names.get(root)
        if nm is None:
            continue
        groups.setdefault(nm, [])
        groups[nm] = sorted(set(groups[nm]) | set(doms))

    # 分组太多时按域名数排序截断，保证每组至少 2 条
    if len(groups) > MAX_GROUPS:
        ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))[:MAX_GROUPS]
        groups = dict(ordered)

    total = sum(len(v) for v in groups.values())
    generated = len(groups)

    # 安全阀：新产出比旧产出少一半以上，说明本次爬取异常（超时/断网），宁可不动旧文件
    if old_total > 200 and total < old_total * 0.3:
        print("[分组][警告] 新产出仅 %d 条，旧产物 %d 条（%d 个文件），疑似抓取不完整，跳过覆盖"
              % (total, old_total, old_files))
        return

    expected = set()
    written = skipped = 0
    for company, keep in groups.items():
        fn = safe_name(company) + ".txt"
        expected.add(fn)
        content = "# %s 广告拦截 %d条\n" % (company, len(keep)) + \
                  "\n".join("0.0.0.0 " + h for h in keep) + "\n"
        path = os.path.join(APPS_DIR, fn)
        # 内容未变就不落盘，避免每次构建都把几千个文件全改一遍（省时间、免冲突）
        try:
            if open(path, encoding="utf-8").read() == content:
                skipped += 1
                continue
        except OSError:
            pass
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        written += 1
    print("[分组] 实际写入 %d 个文件，未变化跳过 %d 个" % (written, skipped))

    # 清理不在 app_list.json 里的旧分组文件
    removed = 0
    for fn in os.listdir(APPS_DIR):
        if not fn.endswith(".txt") or fn in expected:
            continue
        os.remove(os.path.join(APPS_DIR, fn))
        removed += 1

    # 统一订阅：全局规则 + 所有 App 分组，合并去重后写 all.txt
    unified = set()
    for h in blocked:
        unified.add(h)
    for company, doms in groups.items():
        unified |= set(doms)
    with open(os.path.join(ROOT, "all.txt"), "w", encoding="utf-8") as f:
        f.write("# AD-QGG 统一订阅（全局 + 全部 App 分组，去重合并）\n")
        f.write("# Version: %s\n" % time.strftime("%Y%m%d"))
        for h in sorted(unified):
            f.write("0.0.0.0 %s\n" % h)
    print("[统一] all.txt 共 %d 条（全局 %d + 分组补充）" % (len(unified), len(blocked)))

    # 厂商根域覆盖清单
    lines = ["# 厂商根域覆盖清单", "# 厂商\t根域\t拦截子域数"]
    for company in sorted(groups):
        roots = apps.get(company, [])
        if not roots and "." in company:
            continue   # 自动生成的根域组不列入厂商清单
        cnt = len(groups[company])
        lines.append("%s\t%s\t%d" % (company, " ".join(roots[:6]) or "-", cnt))
    with open(os.path.join(ROOT, "厂商根域清单.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("[分组] 拦截域名 %d 条，生成 %d 个 App 文件，清理陈旧 %d 个"
          % (len(blocked), generated, removed))
    print("[分组] 各 App 命中合计 %d 条（同一域名可归属多个 App）" % total)


if __name__ == "__main__":
    main()
