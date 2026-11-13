# xray_link_picker

自动拉取公开订阅源并探测可用的 `xray` / `sing-box` 分享链接，按出口 IP 和上海日历日统计每天有多少条不同链接。

当前采集纪元是 `checkip-amazonaws-ipv4-1`。这个纪元从空库开始，不导入旧链接、旧出口 IP、旧计数或旧按日记录。旧 Release 和 Artifact 留着当档案，恢复时会跳过。

## 第一次运行

在新代码已经在默认分支上、并且没有正在跑的旧任务之后，手动触发一次并打开 bootstrap：

```bash
gh workflow run select_xray_links -R <owner>/<repo> --ref master -f bootstrap=true
```

这次会建空库，拉取全部订阅源并去重，能解析的链接先记为 `pending`，再在约 5 小时预算内探测。没测到的保持 `pending`，不会记成失败。跑完并校验通过后，会新建一个 `run-<UTC时间>-<run_id>-<attempt>` Release，然后才把它标成 Latest。

恢复时先看有没有本纪元的 `epoch.txt`。没有纪元标记的旧 Release 直接跳过，不去对校验和。有本纪元标记但 `state.sqlite` 对不上时，任务失败，不会 bootstrap 成空库。`ops-<run_id>-<attempt>` 只放隧道地址，没有 `epoch.txt`，不能当数据库恢复。

探测开始后，协调者可以用下面这条命令拿到登录地址（文件里没有密码）：

```bash
gh release download "ops-<run_id>-<attempt>" -R <owner>/<repo> -p ssh-access.txt -O -
```

登录账号是 root，只接受公钥。本地私钥路径按你自己的文件填写，命令形如 `ssh -i /path/to/action-sshd-cloudflared ... root@github-actions`。密码登录已关闭，不再使用 `RUNNER_SSH_PASSWORD`。

之后的定时运行不要再打开 bootstrap。它们只恢复校验通过的本纪元快照。一份都没有就失败退出，不会自动空库，也不会读 Artifact。

定时表达式是每小时的 0 分。这和每小时一次的含义相同，不保证 GitHub 调度器一定会投递。

## 输出文件说明（每个成功运行自己的 Release，不覆盖旧附件）

| 文件 | 内容说明 | 含敏感链接凭据 |
|---|---|---|
| `data/good_links.txt` | 当前状态为 `good` 的代表链接（每个出口 IP 选 1 条代表，出口 IP 互不重复） | 是 |
| `data/good_links_by_ip.tsv` | 当前全部 `status=good`，不按出口 IP 去重。列是 `exit_ip`、`link`。`exit_ip` 只用库里这次 checkip 测到并写入的值，按 IPv4、IPv6 分族后用地址整数排序；同一地址再按解码后的 link 排序。link 会做一次 HTML 实体解码。空的、多个地址或解析不了的出口留空，链接仍保留，排在合法地址后面。不拿链接里的 host 填空，也不表示别的网站看到的是同一个 IP | 是 |
| `data/failed_links.txt` | 当前状态为 `failed` 的链接 | 是 |
| `data/stable_links.txt` | 连续可用天数达标（`ok_days >= 门槛`）的代表链接（出口 IP 互不重复） | 是 |
| `data/stable_links_by_ip.txt` | 与 `stable_links.txt` 同集，每行 `出口IP 空格 xray_link`，按出口 IP 数值排序 | 是 |
| `data/ip_day_counts.csv` | **去重前真实映射**：每个 `(day, exit_ip, ip_source, ip_version)` 当天成功测通的 `distinct_link_count`、成功探测次数与覆盖轮次 | 否（仅 IP 与计数） |
| `data/ip_summary.csv` | 每个 `(exit_ip, ip_source, ip_version)` 的跨天汇总：首见日、末见日、观测天数、最大连续天数、当前已完成日连续天数、累计不同链接数等 | 否（仅 IP 与计数） |
| `data/collection_days.csv` | 每个上海自然日的采集轮次（总轮次/完成/中断）与探测覆盖计数 | 否 |
| `data/ip_report.html` | 单文件零依赖静态报表，支持按 IP/测量源搜索与排序查看每日计数 | 否 |
| `data/state.sqlite` | SQLite 状态与观测历史库（含 `.sha256` 校验） | 是 |

## 核心命令行查询（只读模式，不修改数据库）

`export.py` 查询时使用 SQLite `mode=ro` 只读打开，不会修改数据库文件。

### 1. 查询今天（或指定日期）成功工作的 DISTINCT `xray_link` 数量及对应出口 IP

```bash
# 默认查询今天（Asia/Shanghai），仅输出统计与每个出口 IP 的链接计数（不打印敏感链接明文）
python3 export.py --db data/state.sqlite today

# 指定日期并按需打印每个出口 IP 对应的具体 xray_link 明文
python3 export.py --db data/state.sqlite today --day 2026-11-11 --show-links

# 按观测源 URI / 协议栈过滤，或输出 JSON
python3 export.py --db data/state.sqlite today --ip-source https://checkip.amazonaws.com --ip-version ipv4 --json
```

口径区分：
- **当日至少成功过 1 次的 DISTINCT 链接数（`ever_good_link_count`）**：当天内至少有 1 次探测连通且成功取到合法公网出口 IP。
- **当日测过且最新一次仍为成功的 DISTINCT 链接数（`latest_good_on_day_link_count`）**：排除当天先成功、后续复测失败的链接（属于最近一次探测结果，不构成实时在线承诺）。
- 若同一条链接在同一天内不同轮次测出不同出口 IP，两个出口 IP 当天均会保留并各自计入。

### 2. 查询连续 X 天每天都存在的出口 IP 及每日 DISTINCT `xray_link` 数量

```bash
# 查询截至昨天（已完成日）连续 7 天每天都至少有 1 次成功观测的出口 IP
python3 export.py --db data/state.sqlite continuous --days 7

# 将今天（进行中/incomplete）纳入连续窗口结束日，并输出每个 IP 每天对应的具体 xray_link 明文
python3 export.py --db data/state.sqlite continuous --days 3 --include-today --show-links

# 指定窗口结束日期与观测源过滤
python3 export.py --db data/state.sqlite continuous --days 5 --end-day 2026-11-10 --ip-source https://checkip.amazonaws.com
```

连续性与完整性语义：
- **每日存在定义**：某 `(exit_ip, ip_source, ip_version)` 在该上海自然日内至少有 1 次成功观测。连续 X 天存在允许每天由不同的 `xray_link` 接力提供该出口 IP。
- **未采集/缺失日 ≠ 0**：若数据库历史采集天数不足 X 天，或窗口内存在未采集日，命令会明确输出告警，绝不将“未采集/未知”伪造为 0，也不会用旧版 `ok_days` 计数器伪造历史。

## 出口 IP 测量口径说明（Destination-Scoped Observation）

1. **为什么默认固定单一测量端点 `https://checkip.amazonaws.com` 且不做跨源静默回退**：
   - 代理节点返回的出口 IP 是**对特定目标测量端点观测到的出口 IP**，并非全网所有目标恒定不变的唯一物理 IP。
   - 例如，根据 [Cloudflare Workers TCP Sockets 官方文档](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)，Workers 出站 TCP socket 限制直连 Cloudflare IP 段；常见基于 Workers 的 VLESS 实现（如 [`zizifn/edgetunnel`](https://github.com/zizifn/edgetunnel/blob/main/src/worker-vless.js)）在直连目标无数据时通常会回退走配置的 `proxyIP` 中继。在这类节点配置下，请求 Cloudflare 前置端点（如 `api.ipify.org`）可能走 `proxyIP` 中继，而请求非 Cloudflare 前置目标（如 `https://checkip.amazonaws.com`）时则可能走不同的出站路径（但这取决于节点具体后端实现，不代表所有请求或访问 GitHub / YouTube / X 时必然固定走某一条路径）。
   - 本项目只使用一个测量端点，默认 `https://checkip.amazonaws.com`（`IP_CHECK_URL`），地址族默认 IPv4（`IP_FAMILY=4`）。观测结果记的是「这个端点看到的出口地址」，不表示访问 GitHub、YouTube、X 或其他网站时一定是同一个 IP。数据库里的 `ip_source` 是去掉账号密码后的完整端点 URI，不同端点或 IPv4/IPv6 不会混进同一条连续统计。
2. **严格响应校验与失败分类**：
   - 使用标准库 `ipaddress.ip_address` 校验返回内容必须为单个合法公网 IP（`is_global=True`），拒绝多 IP/多行（如未过滤的 `X-Forwarded-For` 列表）、内网/保留地址、HTML 错误页及不匹配的地址族。
   - 严格区分“连通性探针失败（`reason=917`）”与“代理已连通但出口 IP 获取失败（`reason=ip_http`/`ip_invalid`/`ip_family`）”；失败观测绝不绑定陈旧的 `exit_ip`。
