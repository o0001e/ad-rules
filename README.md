# AD-QGG 国内 App 广告域名过滤

多源订阅合并，无爬虫。每天凌晨自动构建（北京时间 01:00 / 03:00 / 05:00），产物直接提交到本仓库。

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

单文件智能体 `ad_agent.py`（纯标准库，无第三方依赖），14 个步骤，各自独立执行；非核心步骤失败只跳过、不中断整轮。

```
01 读取源      48 个上游，缓存 + 镜像兜底
02 解析规则    六种格式归一 + 内容哈希去重
03 加载清单    白名单 + custom
04 生成候选    保护域/噪音词/业务词/共享基建 排除 → 国内过滤 → eTLD+1 归并
05 观察期      单源无特征新域首轮不发布（pending.txt）
06 源质量      连续 3 轮 0 条告警（src_health.json）
07 源停更      内容 7 天不变告警（src_state.json）
08 存活探测    分批 DNS 校验，只认 NXDOMAIN（alive.txt / dead.txt）
09 异常回滚    条数与上轮波动 > 40% 时整轮不写
10 死域入库    30 天后复验，复活则移出
11 冲突检测    被拦又被白名单放行的域名
12 厂商归类    按广告平台分组统计
13 回归断言    关键业务域不被拦 / 无 IP / 无非法域 / 无父子并存
14 写出产物    九种格式 + 原子替换 + 条数自检 + 逐行格式校验
```

定时：`.github/workflows/update.yml`，cron `0 17,19,21 * * *`（UTC）= 北京时间 01 / 03 / 05 点。

## 规则口径

- 保护名单：qq / weixin / alipay / taobao / gov.cn / 12306 / gitee / github / cnb / jsdelivr 等整域放行
- 共享基建（amazonaws、azurewebsites、appspot、edgesuite、bcebos 等）一律不进规则，只保留 custom 例外
- 业务接口词（api / login / pay / static / vod 等）默认不算广告
- DNS 校验确认失效的域名写进 `dead.txt`，合并时跳过
- 产物条数环比波动超过 ±40% 时拒绝写入，防止误把基线改坏

## 状态文件

| 文件 | 作用 |
|---|---|
| `alive.txt` | 已确认存活的域名 + 校验日期，7 天内不重复探测 |
| `dead.txt` | 已确认失效（NXDOMAIN），30 天后复验 |
| `src_health.json` | 每个源最近 5 轮的产出量，连续 3 轮 0 条告警 |
| `src_state.json` | 每个源的内容指纹 + 起始日期，用于识别停更 |
| `pending.txt` | 观察期内的新域，下轮仍出现才发布 |
| `.build_hash` | 产物哈希，与上轮一致时跳过提交 |
