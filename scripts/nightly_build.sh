#!/usr/bin/env bash
# 广告规则夜间构建：爬虫抓取 → 规则合并 → 安全检查 → 同步产物 → 提交推送
# 用法：bash scripts/nightly_build.sh
# 跳过爬虫（快速测试）：SKIP_CRAWL=1 bash scripts/nightly_build.sh
# 只构建不推送（本地测试）：NO_PUSH=1 bash scripts/nightly_build.sh

set -uo pipefail

REPO="/home/user/Doubao/chats/17540679856130/ad-repo"
TOKEN_FILE="$HOME/.config/adqgg/gitee_token"
REMOTE="https://gitee.com/ADS9/ad.git"
BRANCH="m"
LOG="$REPO/nightly_build.log"
STATUS="$HOME/.config/adqgg/last_update.json"

cd "$REPO" || { echo "仓库目录不存在: $REPO"; exit 1; }

exec >> "$LOG" 2>&1
echo "========================================"
echo "[$(date '+%F %T')] 开始夜间构建"

# ---------- 1. 拉取最新 ----------
if git pull origin "$BRANCH" --rebase --autostash; then
  echo "[OK] 拉取最新代码"
else
  echo "[WARN] pull 失败，基于本地版本继续"
fi

# ---------- 2. 爬虫抓取 ----------
if [ "${SKIP_CRAWL:-0}" = "1" ]; then
  echo "[SKIP] 按参数跳过爬虫"
else
  echo "[..] 爬虫开始（限时 30 分钟）"
  timeout 1800 python3 -u scripts/crawl_rules.py
  RC=$?
  if [ $RC -eq 124 ]; then
    echo "[WARN] 爬虫超时（30分钟），继续后续流程"
  elif [ $RC -ne 0 ]; then
    echo "[WARN] 爬虫返回码 $RC，继续后续流程"
  else
    echo "[OK] 爬虫完成"
  fi
fi

# ---------- 3. 规则合并 ----------
echo "[..] 重建 apps/ 分组"
python3 scripts/gen_apps.py || echo "[WARN] 分组重建失败，跳过"

echo "[..] 规则合并"
if ! python3 scripts/merge_rules.py; then
  echo "[FAIL] 合并脚本失败，终止"
  exit 1
fi
echo "[OK] 合并完成"

# ---------- 4. 安全检查 ----------
COUNT=$(grep -c '^0.0.0.0' dist/hosts.txt 2>/dev/null || echo 0)
echo "本次规则数: $COUNT"
if [ "$COUNT" -lt 1000 ]; then
  echo "[FAIL] 规则数低于 1000，判定上游异常，拒绝提交"
  exit 1
fi
if [ "$COUNT" -gt 100000 ]; then
  echo "[WARN] 规则数异常膨胀: $COUNT"
fi

WL=$(grep -cv '^[[:space:]]*$' dist/whitelist.txt 2>/dev/null || echo 0)
GITEE_HIT=$(grep -c 'gitee' dist/domains.txt 2>/dev/null || echo 0)
echo "白名单条数: $WL / gitee 误拦: $GITEE_HIT"
if [ "$GITEE_HIT" -gt 0 ]; then
  echo "[WARN] 检测到 gitee 相关域名被拦截，需检查"
fi

# ---------- 5. 同步产物 ----------
cp dist/adguard.txt dist/domains.txt dist/hosts.txt \
   dist/whitelist.txt dist/whitelist_adguard.txt dist/whitelist_suffix.txt . || {
  echo "[FAIL] 同步产物失败，终止"; exit 1; }
cp dist/build_report.txt 构建报告.txt 2>/dev/null || true
echo "[OK] 产物已同步到根目录"

# ---------- 6. 提交推送 ----------
git add -A
if git diff --quiet && git diff --staged --quiet; then
  echo "[OK] 无变更，无需提交"
else
  git -c user.name=XWDNS -c user.email=x@x.io \
      commit -m "自动构建规则 $(date '+%F %H:%M')" || true

  if [ "${NO_PUSH:-0}" = "1" ]; then
    echo "[SKIP] 按参数不推送，变更保留在本地"
  else
    TOKEN=$(tr -d '\n\r ' < "$TOKEN_FILE")
    if git push "https://oauth2:${TOKEN}@gitee.com/ADS9/ad.git" HEAD:"$BRANCH"; then
      echo "[OK] 推送成功"
    else
      echo "[WARN] 首次推送失败，rebase 后重试"
      git pull origin "$BRANCH" --rebase --autostash
      if git push "https://oauth2:${TOKEN}@gitee.com/ADS9/ad.git" HEAD:"$BRANCH"; then
        echo "[OK] 重试推送成功"
      else
        echo "[FAIL] 推送失败，变更已保留在本地，未强推远端"
      fi
    fi
  fi
fi

# ---------- 7. 写状态文件 ----------
mkdir -p "$(dirname "$STATUS")"
python3 - "$STATUS" "$COUNT" "$WL" <<'PY' || true
import json, sys, datetime
path, count, wl = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
data = {
    "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "rules": count,
    "whitelist": wl,
}
json.dump(data, open(path, "w"), ensure_ascii=False, indent=2)
PY

echo "[DONE] 拦截 $COUNT 条 / 白名单 $WL 条"
echo "========================================"
