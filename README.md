# AD-QGG Filters

纯合并型广告规则订阅：多源并行下载 → 统一解析 → eTLD+1 归并 → 多格式输出。每 8 小时更新一次。

## 订阅地址

| 用途 | 地址 |
|---|---|
| **hosts（推荐）** | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/hosts.txt` |
| hosts（国内 CDN） | `https://gitee.com/ADS9/ad/raw/m/rules/hosts.txt` |
| AdGuard | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/adguard.txt` |
| 纯域名 | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/domains.txt` |
| Lite（仅国内） | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/lite.txt` |
| Clash | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/clash.yaml` |
| dnsmasq | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/dnsmasq.conf` |
| 全量（含单 App 分组） | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/all.txt` |

Release 镜像：`https://github.com/o0001e/ad-rules/releases/download/rule/hosts.txt`

## 结构

- `sources.txt` — 上游规则源，一行一个直链
- `whitelist.txt` — 白名单（整域放行）
- `custom.txt` — 人工补充规则
- `app_list.json` — 厂商根域 → App 名称映射，用来拆单 App 分组
- `adblock.py` — 合并脚本
- `rules/` — 构建产物（不入库，由 Actions 发布到 Release）

## 本地运行

```bash
python3 adblock.py
```
