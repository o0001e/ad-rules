# AD-QGG 国内 App 广告域名过滤

多源订阅合并，无爬虫。每 8 小时自动更新，产物发布到 Release，GitHub 与 Gitee 双写。

## 订阅地址（优先 jsDelivr）

| 用途 | 地址 |
|---|---|
| 主规则（jsDelivr，国内快） | `https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/rules/hosts.txt` |
| 主规则（GitHub raw） | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/hosts.txt` |
| 主规则（Gitee，备用） | `https://gitee.com/ADS9/ad/raw/m/rules/hosts.txt` |
| 白名单（jsDelivr） | `https://cdn.jsdelivr.net/gh/o0001e/ad-rules@main/rules/whitelist.txt` |
| 白名单（GitHub raw） | `https://raw.githubusercontent.com/o0001e/ad-rules/main/rules/whitelist.txt` |
| 白名单（Gitee） | `https://gitee.com/ADS9/ad/raw/m/rules/whitelist.txt` |

其他格式把文件名换掉即可：`adguard.txt`、`domains.txt`、`dnsmasq.conf`、`clash.yaml`、`surge.list`、`all.txt`。

## 流水线

| 流水线 | 频率 | 作用 |
|---|---|---|
| Update Filters | 每 8 小时 | 拉 45 个源 → 解析 → eTLD+1 归并 → 11 种产物 → 发 Release → 双写 |
| Trim Dead Domains | 主流水线成功后 | 取产物做 DNS 校验，剔死域后重发 |
| Weekly App Groups | 每周日 04:00 | 爬虫补 App 分组 |

## 规则口径

- 保护名单：qq / weixin / alipay / taobao / gov.cn / 12306 / gitee / github / jsdelivr 等整域放行
- 云厂商共享域（amazonaws、azurewebsites、appspot、edgesuite 等）只拦具体子域，绝不上溯父域
- 业务接口词（api / login / pay / static / vod 等）默认不算广告
- DNS 校验确认失效的域名写进 dead.txt，合并时跳过
- 产物少于 1000 条时拒绝覆盖

## 报告

- `rules/source_report.txt`：每个域名被几个源收录
- `rules/source_score.txt`：每个源的贡献量和存活率
- `rules/regress_report.txt`：白名单误伤检测
- `rules/whitelist_suggested.txt`：从真机 DNS 日志挖出的白名单建议（需人工确认）
