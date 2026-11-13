#!/bin/bash
# 每周自动更新：重新拉源 -> 合并 -> 按 App 归类 -> 推送到最短订阅仓库 zhao-8023/ad（分支 m）
set -euo pipefail
cd "$(dirname "$0")/.."
TOKEN_FILE="$HOME/.config/adqgg/gitee_token"
[ -s "$TOKEN_FILE" ] || { echo "缺少 Gitee 令牌文件: $TOKEN_FILE"; exit 1; }
TOKEN=$(tr -d '\n\r ' < "$TOKEN_FILE")

python3 scripts/merge_rules.py
python3 scripts/categorize_apps.py
cp dist/adguard.txt dist/domains.txt dist/hosts.txt dist/whitelist.txt \
   dist/whitelist_adguard.txt dist/whitelist_suffix.txt .

mkdir -p .publish
cp dist/domains.txt dist/adguard.txt dist/hosts.txt dist/whitelist.txt .publish/
cd .publish
git init -q -b m 2>/dev/null || true
git add -A
git -c user.name="AD-QGG Bot" -c user.email="ad-qgg@local" \
    commit -qm "自动更新 $(date +%F)" 2>/dev/null || true
git -c credential.helper= push --force \
    "https://oauth2:${TOKEN}@gitee.com/ADS9/ad.git" HEAD:m 2>&1 | tail -3
cd ..

STATUS_DIR="$HOME/.config/adqgg"
[ -f "$STATUS_DIR/last_update.json" ] && cp "$STATUS_DIR/last_update.json" "$STATUS_DIR/prev_update.json"
python3 - <<'PY'
import json,os,datetime
root=os.getcwd(); d=os.path.join(os.path.expanduser("~"),".config/adqgg")
def n(f): return sum(1 for l in open(os.path.join(root,f),encoding="utf-8") if l.strip() and not l.startswith("#"))
json.dump({"time":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
 "version":datetime.datetime.now().strftime("%Y%m%d"),
 "blocked":n("domains.txt"),"whitelist":n("whitelist.txt"),
 "hongguo_short":n("apps/红果免费短剧.txt"),"hongguo_comic":n("apps/红果免费漫剧.txt")},
 open(os.path.join(d,"last_update.json"),"w",encoding="utf-8"),ensure_ascii=False,indent=2)
PY
echo "== 完成 =="
cat dist/build_report.txt
