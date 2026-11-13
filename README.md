# 广告域名黑名单订阅

国内热门 App 广告域名拦截规则，GitHub Actions 每日自动抓取、构建、提交。

## 订阅地址

### 一条地址搞定（推荐）

只需要这一条，全局规则 + 全部分组已合并去重：

```
# 国内加速（jsDelivr）
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/all.txt

# GitHub 源（备用）
https://raw.githubusercontent.com/o0001e/ad-rules/main/all.txt
```

配对白名单（避免误拦登录/支付）：

```
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/whitelist.txt
```

### 分格式订阅（需要特定格式时用）

### 国内加速（jsDelivr CDN，推荐）

```
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/hosts.txt
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/domains.txt
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/adguard.txt
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/whitelist.txt
```

### GKD 规则

```
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/gkd.json          # ADST持续更新
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/gkd-custom.json   # x随缘更新
```

### GitHub 源（raw，备用）

```
https://raw.githubusercontent.com/o0001e/ad-rules/main/hosts.txt
https://raw.githubusercontent.com/o0001e/ad-rules/main/domains.txt
https://raw.githubusercontent.com/o0001e/ad-rules/main/adguard.txt
https://raw.githubusercontent.com/o0001e/ad-rules/main/whitelist.txt
```

### 按 App 单独订阅

`apps/` 目录下每个 App 一个文件，只拦这个 App 的广告域。

```
https://raw.githubusercontent.com/o0001e/ad-rules/main/apps/抖音.txt
```

注意：**CDN 版遇到中文文件名必须转编码**，否则返回 400。

```
抖音 → %E6%8A%96%E9%9F%B3
https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/apps/%E6%8A%96%E9%9F%B3.txt
```

### Gitee 镜像（自动同步）

```
https://gitee.com/ADS9/ad/raw/m/hosts.txt
```

## 规则来源

两层合计：

1. **15 个上游规则源**：anti-AD、217heidai、045200、zimoadmin、AWAvenue、ADgk、Adblock-Plus-Rule、1024_hosts、Ad-set-hosts、FuLing-AdRules、EasyAds、TutuBetterRules、AdGuard 224/224_optimized、easylistchina
2. **自建爬虫**：516 个国内 App / 595 个根域名，证书透明日志（crt.sh + certspotter）+ 广告前缀字典爆破，DoH 存活校验后入库

## 自动更新

| 工作流 | 北京时间 | 内容 |
|---|---|---|
| `ad-rule-build` | 每天 02:00 | 爬虫抓取 → 合并上游 → 安全检查 → 提交 GitHub → 同步 Gitee |
| `gkd-rule-update` | 每天 03:30 | 拉取 GKD 双上游 → 改 name/version → 提交 → 同步 Gitee |

手动触发：Actions → 选工作流 → Run workflow。`ad-rule-build` 带 `skip_crawl` 开关，勾上只跑合并（约 3 分钟），不勾跑全量（约 40~60 分钟）。

## 目录

```
hosts.txt / domains.txt / adguard.txt     主规则（上游合并）
whitelist.txt / whitelist_*.txt           配套白名单
apps/<App>.txt                            按 App 分组的自建抓取结果
gkd.json / gkd-custom.json                GKD 规则
scripts/crawl_rules.py                    全量爬虫
scripts/crawl_app.py                      单 App 定向重抓
scripts/merge_rules.py                    上游合并
scripts/gen_apps.py                       apps 分组重建
scripts/update_gkd.py                     GKD 双上游更新
```

## 安全机制

- 规则数低于 1000 条拒绝提交，防止上游断源导致空文件覆盖
- 推送前 `git pull --rebase`，3 次重试
- Gitee 同步以现有分支为父提交快进推送，不做强推
- 关键词白名单（baidu / bdstatic / gitee 等）硬放行，避免误杀
