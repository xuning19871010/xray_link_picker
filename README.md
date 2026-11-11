# xray_link_picker

自动拉取公开订阅源并探测可用的 `xray` / `sing-box` 分享链接，同时按**出口 IP（测量端点作用域）× 自然日（Asia/Shanghai）**记录与统计每日对应的 DISTINCT `xray_link`。

## 输出文件说明（`data/` 目录及 Release `latest` 附件）

| 文件 | 内容说明 | 含敏感链接凭据 |
|---|---|---|
| `data/good_links.txt` | 当前状态为 `good` 的代表链接（每个出口 IP 选 1 条代表，出口 IP 互不重复） | 是 |
| `data/failed_links.txt` | 当前状态为 `failed` 的链接 | 是 |
| `data/stable_links.txt` | 连续可用天数达标（`ok_days >= 门槛`）的代表链接（出口 IP 互不重复） | 是 |
| `data/stable_links_by_ip.txt` | 与 `stable_links.txt` 同集，每行 `出口IP 空格 xray_link`，按出口 IP 数值排序 | 是 |
| `data/ip_day_counts.csv` | **去重前真实映射**：每个 `(day, exit_ip, ip_source, ip_version)` 当天成功测通的 `distinct_link_count`、成功探测次数与覆盖轮次 | 否（仅 IP 与计数） |
| `data/ip_summary.csv` | 每个 `(exit_ip, ip_source, ip_version)` 的跨天汇总：首见日、末见日、观测天数、最大连续天数、当前已完成日连续天数、累计不同链接数等 | 否（仅 IP 与计数） |
| `data/collection_days.csv` | 每个上海自然日的采集轮次（总轮次/完成/中断）与探测覆盖计数 | 否 |
| `data/ip_report.html` | 单文件零依赖静态交互报表，支持按 IP/测量源搜索、按观测天数/连续天数排序与分页查看近 30 天每日计数 | 否 |
| `data/state.sqlite` | SQLite 状态与观测历史库（含 `.sha256` 校验） | 是 |

## 核心命令行查询（只读模式，不修改数据库）

对本地或从 Release 下载的 `state.sqlite` 执行查询时，`export.py` 默认使用 SQLite `mode=ro` 只读打开，不会修改数据库文件。

### 1. 查询今天（或指定日期）成功工作的 DISTINCT `xray_link` 数量及对应出口 IP

```bash
# 默认查询今天（Asia/Shanghai），仅输出统计与每个出口 IP 的链接计数（不打印敏感链接明文）
python3 export.py --db data/state.sqlite today

# 指定日期并按需打印每个出口 IP 对应的具体 xray_link 明文
python3 export.py --db data/state.sqlite today --day 2026-11-11 --show-links

# 按观测源/协议栈过滤，或输出 JSON
python3 export.py --db data/state.sqlite today --ip-source checkip.amazonaws.com --ip-version ipv4 --json
```

口径区分：
- **当日至少成功过 1 次的 DISTINCT 链接数（`ever_good_link_count`）**：当天内至少有 1 次探测连通且成功取到合法公网出口 IP。
- **当日测过且最新一次仍为成功的 DISTINCT 链接数（`latest_good_on_day_link_count`）**：排除当天先成功、后续复测失败的链接（注：属于最近一次探测结果，不构成实时在线保证）。
- 若同一条链接在同一天内不同轮次测出不同出口 IP，两个出口 IP 当天均会保留并各自计入。

### 2. 查询连续 X 天每天都存在的出口 IP 及每日 DISTINCT `xray_link` 数量

```bash
# 查询截至昨天（已完成日）连续 7 天每天都至少有 1 次成功观测的出口 IP
python3 export.py --db data/state.sqlite continuous --days 7

# 将今天（进行中/incomplete）纳入连续窗口结束日，并输出每个 IP 每天对应的具体 xray_link 明文
python3 export.py --db data/state.sqlite continuous --days 3 --include-today --show-links

# 指定窗口结束日期与观测源过滤
python3 export.py --db data/state.sqlite continuous --days 5 --end-day 2026-11-10 --ip-source checkip.amazonaws.com
```

连续性与完整性语义：
- **每日存在定义**：某 `(exit_ip, ip_source, ip_version)` 在该上海自然日内至少有 1 次成功观测。连续 X 天存在允许每天由不同的 `xray_link` 接力提供该出口 IP。
- **未采集/缺失日 ≠ 0**：若数据库历史采集天数不足 X 天，或窗口内存在未采集日，命令会明确输出告警，绝不将“未采集/未知”伪造为 0，也不会用旧版 `ok_days` 计数器伪造历史。

## 出口 IP 测量口径说明（Destination-Scoped Observation）

1. **为什么默认使用 `https://checkip.amazonaws.com` 且不做跨源静默回退**：
   - 根据 [Cloudflare Workers TCP Sockets 官方文档](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)，Workers 出站 TCP socket 禁止直连 Cloudflare 自身 IP 段；而常见基于 Workers 的 VLESS 实现（如 [`zizifn/edgetunnel`](https://github.com/zizifn/edgetunnel/blob/main/src/worker-vless.js)）在直连目标无响应时会回退连接配置的 `proxyIP` 中继并转发原始 TLS 流量。
   - 因此，当测量端点位于 Cloudflare 前置（如 `api.ipify.org`）时，这类节点会触发 `proxyIP` 回退并返回中继服务器（甚至轮换中继池）的出口 IP；而当访问非 Cloudflare 前置目标（如 AWS `checkip.amazonaws.com`，以及日常访问的 GitHub / YouTube / X 等非 CF 目标）时，节点走直连出站路径，观测到的出口 IP 与访问 CF 目标时不同。
   - 本项目默认采用非 Cloudflare 前置的权威 IPv4 端点 `https://checkip.amazonaws.com`（可通过环境变量 `IP_CHECK_URL` 配置），默认关闭跨源回退（`IP_FALLBACK_URLS=""`），并在数据库与报表中显式记录 `ip_source` 与 `ip_version`（`ipv4`/`ipv6`），确保同一连续性序列不会静默混入不同测量源或不同协议栈的结果。
2. **严格响应校验与失败分类**：
   - 使用标准库 `ipaddress.ip_address` 校验返回内容必须为单个合法公网 IP（`is_global=True`），拒绝多 IP/多行（如伪造或未过滤的 `X-Forwarded-For` 列表）、HTML 错误页及不匹配的地址族。
   - 严格区分“连通性探针失败（`reason=917`）”与“代理已连通但出口 IP 获取失败（`reason=ip_http`/`ip_invalid`/`ip_family`）”；失败观测绝不绑定陈旧的 `exit_ip`。
