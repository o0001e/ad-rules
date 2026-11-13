#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自愈检查：每次构建产物落盘后、提交前运行。
只做"发现问题就修"的确定性动作，不联网、不改上游，所有修复写进 自愈报告.txt。

修什么：
1. 主规则条数异常（<1000 或比上一版跌 >30%）→ 回滚到上一版
2. hosts/adguard/domains 三份不一致 → 以 hosts 为唯一真源重建另两份
3. 重复行、非法域名 → 去重剔除
4. 拦截与白名单重叠 → 从拦截里剔除
5. apps/ 总条数腰斩、或上一版存在的 App 文件消失 → 整目录回滚
6. 单个 App 文件变成 0 条但上一版有内容 → 单独回滚该文件
7. Gitee/镜像文件缺失 → 不处理（由工作流负责）

退出码始终 0（修复失败也算"已记录"），只有完全无法自愈时才返回 1。
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPS = os.path.join(ROOT, "apps")
REPORT = os.path.join(ROOT, "自愈报告.txt")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

actions = []
errors = []


def log(msg):
    actions.append(msg)
    print("[自愈] " + msg)


def _best_ref():
    """优先用最近一次成功快照标签 ok-latest 作为回滚源，没有则退回 HEAD。"""
    try:
        r = subprocess.run(["git", "rev-parse", "--verify", "ok-latest"],
                           cwd=ROOT, capture_output=True, timeout=10)
        if r.returncode == 0:
            return "ok-latest"
    except Exception:
        pass
    return "HEAD"


RESTORE_REF = _best_ref()


def git_show(path):
    """取回滚源里的文件内容，失败返回 None。"""
    for ref in (RESTORE_REF, "HEAD"):
        try:
            out = subprocess.run(["git", "show", ref + ":" + path], cwd=ROOT,
                                 capture_output=True, timeout=20)
            if out.returncode == 0:
                return out.stdout.decode("utf-8", "ignore")
        except Exception:
            pass
    return None


def read_domains(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.split()[1] for l in f if l.startswith("0.0.0.0")]


def write_hosts(domains):
    with open(os.path.join(ROOT, "hosts.txt"), "w", encoding="utf-8") as f:
        f.write("# 国内App广告拦截 hosts\n")
        f.write("\n".join("0.0.0.0 " + h for h in sorted(domains)) + "\n")


def write_adguard(domains, ver):
    with open(os.path.join(ROOT, "adguard.txt"), "w", encoding="utf-8") as f:
        f.write("! Title: 国内热门App广告拦截（多源合并 + 配套白名单）\n")
        f.write("! Version: %s\n" % ver)
        f.write("! Expires: 1 day\n")
        f.write("! Homepage: https://github.com/o0001e/ad-rules\n")
        f.write("! 拦截条数: %d\n" % len(domains))
        f.write("! 配套白名单: whitelist.txt / whitelist_adguard.txt\n\n")
        f.write("\n".join("||" + h + "^" for h in sorted(domains)) + "\n")


def write_domains(domains):
    with open(os.path.join(ROOT, "domains.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domains)) + "\n")


def read_whitelist():
    p = os.path.join(ROOT, "whitelist.txt")
    if not os.path.exists(p):
        return set()
    with open(p, encoding="utf-8", errors="ignore") as f:
        return {l.strip() for l in f if l.strip() and not l.startswith("#")}


def count_apps():
    total, files = 0, {}
    if not os.path.isdir(APPS):
        return 0, files
    for fn in os.listdir(APPS):
        if not fn.endswith(".txt"):
            continue
        n = len(read_domains(os.path.join(APPS, fn)))
        files[fn] = n
        total += n
    return total, files


def run(ver):
    cur = read_domains(os.path.join(ROOT, "hosts.txt"))
    n = len(cur)
    prev_text = git_show("hosts.txt")
    prev = [l.split()[1] for l in prev_text.splitlines() if l.startswith("0.0.0.0")] if prev_text else []
    pn = len(prev)

    # 1. 条数异常 → 回滚
    if n < 1000:
        log("主规则仅 %d 条（<1000），判定构建失败" % n)
        if prev_text and pn >= 1000:
            for f in ("hosts.txt", "adguard.txt", "domains.txt"):
                t = git_show(f)
                if t:
                    open(os.path.join(ROOT, f), "w", encoding="utf-8").write(t)
            log("已从上一版回滚 hosts/adguard/domains（%d 条）" % pn)
            return 0
        errors.append("主规则异常且无可回滚版本")
        return 1
    if pn and n < pn * 0.7:
        log("主规则从 %d 条跌到 %d 条（-%.0f%%），判为上游异常，回滚" % (pn, n, 100 * (1 - n / pn)))
        for f in ("hosts.txt", "adguard.txt", "domains.txt"):
            t = git_show(f)
            if t:
                open(os.path.join(ROOT, f), "w", encoding="utf-8").write(t)
        log("已回滚到上一版 %d 条" % pn)
        return 0
    if pn and n > pn * 1.6:
        log("主规则从 %d 条增长到 %d 条（放宽收录后的正常变化）" % (pn, n))

    # 2. 清洗：格式 + 去重
    bad = [h for h in cur if not DOMAIN_RE.match(h)]
    doms = sorted({h for h in cur if DOMAIN_RE.match(h)})
    if bad:
        log("剔除格式非法 %d 条（示例 %s）" % (len(bad), bad[:3]))
    if len(doms) != n or bad:
        write_hosts(doms)

    # 3. 三份一致性：以 hosts 为真源
    adg = os.path.join(ROOT, "adguard.txt")
    dm = os.path.join(ROOT, "domains.txt")
    a_set, d_set = set(), set()
    if os.path.exists(adg):
        with open(adg, encoding="utf-8", errors="ignore") as f:
            a_set = {l.strip()[2:-1] for l in f if l.startswith("||") and l.strip().endswith("^")}
    if os.path.exists(dm):
        with open(dm, encoding="utf-8", errors="ignore") as f:
            d_set = {l.strip() for l in f if l.strip() and not l.startswith("#")}
    if a_set != set(doms):
        log("adguard.txt 与 hosts 不一致（%d vs %d），按 hosts 重建" % (len(a_set), len(doms)))
        write_adguard(doms, ver)
    if d_set != set(doms):
        log("domains.txt 与 hosts 不一致（%d vs %d），按 hosts 重建" % (len(d_set), len(doms)))
        write_domains(doms)

    # 4. 白名单冲突
    wl = read_whitelist()
    overlap = wl & set(doms)
    if overlap:
        log("拦截与白名单重叠 %d 条，从拦截剔除（示例 %s）" % (len(overlap), sorted(overlap)[:3]))
        doms = [h for h in doms if h not in overlap]
        write_hosts(doms)
        write_adguard(doms, ver)
        write_domains(doms)

    # 5/6. apps 目录自愈
    total, files = count_apps()
    prev_files = {}
    prev_listing = subprocess.run(["git", "-c", "core.quotepath=false", "ls-tree", "--name-only", "HEAD", "apps/"],
                                  cwd=ROOT, capture_output=True, timeout=20)
    if prev_listing.returncode == 0:
        for line in prev_listing.stdout.decode().splitlines():
            fn = line.split("apps/", 1)[-1]
            if fn.endswith(".txt"):
                prev_files[fn] = 0
    for fn in list(prev_files):
        # 历史条数必须读上一版提交的内容，不能读当前文件（当前可能已被清空）
        prev_text_app = git_show("apps/" + fn)
        if prev_text_app is None:
            prev_files[fn] = -1          # 上一版没有 → 本版新增，不算丢失
        else:
            prev_files[fn] = len([l for l in prev_text_app.splitlines() if l.startswith("0.0.0.0")])

    missing = [fn for fn in prev_files if not os.path.exists(os.path.join(APPS, fn))]
    emptied = [fn for fn, v in prev_files.items() if v > 0 and files.get(fn, 0) == 0]
    prev_total = sum(v for v in prev_files.values() if v > 0)

    if prev_total > 200 and total < prev_total * 0.5:
        log("apps 总条数从 %d 跌到 %d（腰斩），整体回滚 apps 目录" % (prev_total, total))
        r = subprocess.run(["git", "checkout", "HEAD", "--", "apps/"], cwd=ROOT,
                           capture_output=True, timeout=60)
        if r.returncode == 0:
            log("apps 目录已回滚")
        else:
            errors.append("apps 回滚失败: " + r.stderr.decode()[:80])
        return 1 if errors else 0

    # 只有 app_list 里人工配置过的厂商才算"必须存在"，
    # 自动按根域生成的组随域名变化自然增删属于正常，不能回滚复活过期文件
    curated = set()
    try:
        import json
        al = json.load(open(os.path.join(ROOT, "app_list.json"), encoding="utf-8"))
        curated = set(al.keys())
    except Exception:
        pass

    def is_curated(fn):
        return fn[:-4] in curated

    real_missing = [fn for fn in missing if is_curated(fn)]
    auto_gone = [fn for fn in missing if not is_curated(fn)]
    if auto_gone:
        log("自动分组自然移除 %d 个（%s），无需恢复" % (len(auto_gone), auto_gone[:3]))
    if real_missing:
        log("厂商分组丢失 %d 个（%s），从上一版恢复" % (len(real_missing), real_missing[:3]))
        for fn in real_missing:
            t = git_show("apps/" + fn)
            if t:
                open(os.path.join(APPS, fn), "w", encoding="utf-8").write(t)

    real_emptied = [fn for fn in emptied if is_curated(fn)]
    if real_emptied:
        log("厂商分组被清空 %d 个（%s），从上一版恢复" % (len(real_emptied), real_emptied[:3]))
        for fn in real_emptied:
            t = git_show("apps/" + fn)
            if t:
                open(os.path.join(APPS, fn), "w", encoding="utf-8").write(t)

    return 1 if errors else 0


def main():
    import datetime
    ver = datetime.datetime.now().strftime("%Y%m%d")
    code = run(ver)
    lines = ["自愈报告 %s（回滚源: %s）" % (ver, RESTORE_REF), "执行时间: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""]
    lines += ["- " + a for a in actions] or ["- 未发现异常，无需修复"]
    if errors:
        lines += ["", "错误:"] + ["- " + e for e in errors]
    open(REPORT, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    sys.exit(code)


if __name__ == "__main__":
    main()
