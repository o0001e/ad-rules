import re
p = 'adblock.py'
lines = open(p, encoding='utf-8').read().split('\n')
# 找到 source_stats 起始行到 build_report 结束行，整体替换
start = next(i for i, l in enumerate(lines) if 'source_stats.txt' in l and 'open(' in l)
# 往前退到缩进起点（该 with 行本身是起始）
end = next(i for i, l in enumerate(lines) if 'build_report.txt' in l and 'open(' in l)
new_block = [
    '    # 来源统计：每个域名被几个独立源收录',
    '    with open(os.path.join(OUT, "source_report.txt"), "w", encoding="utf-8") as f:',
    '        f.write("# 域名\\t收录源数\\t来源编号\\n")',
    '        for d in sorted(blocked):',
    '            ids = ",".join(str(x) for x in sorted(srcs.get(d, ())))',
    '            f.write("%s\\t%d\\t%s\\n" % (d, len(srcs.get(d, ())), ids))',
    '',
    '    # 白名单产物',
    '    with open(os.path.join(OUT, "whitelist.txt"), "w", encoding="utf-8") as f:',
    '        f.write("# AD-QGG 白名单（一行一个域名）\\n# Update: %s\\n# Count: %d\\n" % (ver, len(white)))',
    '        f.write("".join(d + "\\n" for d in sorted(white)))',
    '    with open(os.path.join(OUT, "whitelist_adguard.txt"), "w", encoding="utf-8") as f:',
    '        f.write("! AD-QGG 白名单\\n# Update: %s\\n" % ver)',
    '        f.write("".join("@@||%s^\\n" % d for d in sorted(white)))',
    '',
    '    with open(os.path.join(OUT, "build_report.txt"), "w", encoding="utf-8") as f:',
    '        f.write("构建时间: %s\\n总规则: %d\\n白名单: %d\\nApp 分组: %d\\n"',
    '                % (ver, n, len(white), len(groups)))',
]
lines = lines[:start] + new_block + lines[end + 3:]
open(p, 'w', encoding='utf-8').write('\n'.join(lines))
print("重写完成")
