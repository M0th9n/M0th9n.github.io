---
title: "恶意样本分析：OSA Stealer（other · zsh · cd86aee4）"
published: 2026-11-09
draft: false
description: "恶意（置信度中）：OSA Stealer · stealer/downloader/implant · 难度 easy · 纯静态分析"
tags: ["OSA", "stealer", "downloader", "implant", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **OSA Stealer**（存疑） · 置信度 **中**
> 
> 别名：AppleScript-based macOS stealer、osascript downloader/loader
> 
> 外层 zsh 为明文，可直接读出完整恶意链：base64+gzip 内嵌 stage2 并 eval；stage2 定时向硬编码域名请求内容并通过管道交给 osascript 执行（远程 AppleScript 代码执行）；随后把 /tmp/osalogging.zip 分块 HTTP PUT 上传并删除本地文件。所有环节均有字符串/偏移证据。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **OSA Stealer** · 别名 AppleScript-based macOS stealer、osascript downloader/loader · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · downloader · implant |
| 难度 | easy |
| 首次出现 | 2026-11-06 18:24:31 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/cd86aee4882b93ccd3e993b9d8f12bd372640ed765893fcab27c5919d2f154d1/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解码内嵌载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">回调C2取远程脚本</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">osascript远程执行</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">口令参数外传</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">分块外传归档</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `cd86aee4882b93ccd3e993b9d8f12bd372640ed765893fcab27c5919d2f154d1` |
| MD5 | _未记录_ |
| 大小 | 1,442 字节（1.4 KB） |
| 类型 | other · `zsh` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解码内嵌载荷

`T1140` · 置信度 **高** · 静态

外层脚本用 base64 -D 解码 heredoc 中的 PAYLOAD_m296222728618692，再 gunzip 得到 2641 字节 zsh 脚本，最后 eval 执行，规避明文可见。

> **证据**：外层脚本 off 11: d2229=$(base64 -D <<'PAYLOAD_m296222728618692' | gunzip；末尾 eval "$d2229"；gzip 头 1f8b08
> 
> **来源**：`ev-000001` · `ev-000003`

### 2. 回调C2取远程脚本

`T1071.001` · 置信度 **高** · 静态

向 hxxp://seohumanoid[.]com/dynamic?txd=<硬编码token> 发起 GET，把响应体当作可执行脚本内容；token 在脚本中固定。

> **证据**：stage2 off 496/742: "hxxp://$domain/dynamic?txd=$token"；off 127 token=42403afd...；off 92 domain=seohumanoid[.]com
> 
> **来源**：`ev-000002` · `ev-000003`

### 3. osascript远程执行

`T1059.002` · 置信度 **高** · 静态

curl 的输出不落盘、直接通过管道交给 osascript 解释执行，等价于由 C2 下发并运行任意 AppleScript，构成远程代码执行通道。

> **证据**：stage2 off 496 与 off 742 均以 " | osascript" 结尾
> 
> **来源**：`ev-000002` · `ev-000003`

### 4. 口令参数外传

`T1041` · 置信度 **中** · 静态

若启动时带参数，将第一个参数以 pwd=$1 追加到 /dynamic 请求中，与 token 一并发送，疑似接收/回传口令。

> **证据**：stage2 off 496: ".../dynamic?txd=$token&pwd=$1"；off 300 if [ $# -gt 0 ]
> 
> **来源**：`ev-000002`

### 5. 分块外传归档

`T1041` · 置信度 **高** · 静态

检测 /tmp/osalogging.zip 存在且非空后，按 10MB 分块以 HTTP PUT 上传到 /gate，参数含 buildtxd、upload_id、chunk_index、total_chunks。

> **证据**：stage2 off 929 CHUNK_SIZE=$((10*1024*1024))；off 1750 curl -X PUT；off 2064 /gate?buildtxd=$token&upload_id=...
> 
> **来源**：`ev-000002` · `ev-000003`

### 6. 伪装浏览器UA

`T1036.005` · 置信度 **高** · 静态

所有 HTTP 请求固定使用 macOS Safari 的 Mozilla/5.0 User-Agent，并附加 api-key 请求头，混入正常浏览器流量。

> **证据**：stage2 off 361/1821: User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36；off 459/1923 api-key
> 
> **来源**：`ev-000002`

### 7. 静默后台运行

`T1564` · 置信度 **高** · 静态

入口把 stdin/stdout/stderr 全部重定向到 /dev/null，并以 & 后台方式调用 daemon_function，使运行过程无终端输出。

> **证据**：stage2 off 31/51/71: exec </dev/null / exec >/dev/null / exec 2>/dev/null；off 2581: daemon_function "$@" &
> 
> **来源**：`ev-000002`

### 8. 上传后删除暂存包

`T1070.004` · 置信度 **高** · 静态

全部分块上传成功后执行 rm -f /tmp/osalogging.zip，删除本地窃取归档以清理痕迹。

> **证据**：stage2 off 2548: rm -f "$file"；file 定义于 off 263
> 
> **来源**：`ev-000002`

### 9. 失败重试退避

`T1041` · 置信度 **高** · 静态

单块上传最多重试 8 次，并按 3+attempt*2 秒递增等待，提高受干扰网络下的外传成功率。

> **证据**：stage2 off 972 MAX_RETRIES=8；off 1597 重试循环；off 2384 sleep $((3 + attempt * 2))
> 
> **来源**：`ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://seohumanoid[.]com/dynamic?txd=42403afd2906a8f3062e3ddb19b28572d88db9ae74b147319383bd280c6bec0a` | 80 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxp://seohumanoid[.]com/gate?buildtxd=42403afd2906a8f3062e3ddb19b28572d88db9ae74b147319383bd280c6bec0a` | 80 | exfil | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/osalogging.zip`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `seohumanoid[.]com` | 是 | 静态 |
| `c2_port` | `80` | 是 | 静态 |
| `c2_uri` | `/dynamic (任务下发) ; /gate (分块上传)` | 是 | 静态 |
| `campaign_id` | `42403afd2906a8f3062e3ddb19b28572d88db9ae74b147319383bd280c6bec0a (txd/buildtxd)` | 是 | 静态 |
| `api_key` | `5190ef1733183a0dc63fb623357f56d6` | 是 | 静态 |
| `exfil_path` | `/tmp/osalogging.zip` | 是 | 静态 |
| `encoding_algo` | `base64 + gzip (内嵌 stage2)` | 是 | 静态 |
| `chunk_size` | `10485760` | 否 | 静态 |
| `user_agent` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要把本脚本描述为完整的键盘记录器或银行木马：它只负责取回并执行远程 AppleScript，并上传既定的 /tmp/osalogging.zip，采集动作不在本文件中。
- 不要断言存在持久化（LaunchAgent/LaunchDaemon/登录项）：脚本未创建任何持久化项，仅后台运行一次。
- 不要断言 C2 已成功上线或数据已外传：本次为纯静态分析，未进行任何网络回连，也未观测到真实会话。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次仅做静态分析，未在动态沙箱或真实 macOS 环境执行，C2 会话与外传结果均未观测。
2. 实际窃取/采集逻辑由 C2 下发的 AppleScript 完成，该远程脚本内容未知，无法确认具体收集的数据类型（浏览器凭据、Keychain、钱包等）。
3. 家族归属依据行为与命名推断，未获得厂商命名、YARA 规则或多引擎结果佐证。
4. 所有 C2 条目标记为 static 且 pending_dynamic_verify=true，需真实网络会话才能升级为 dynamic。
5. gzip 内嵌数据的修改时间为 2026-11-02，仅作构建时间参考，不作为结论。

## 证据索引

<details>
<summary>展开 3 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 外层 .zsh 字符串抽取：22 条 ASCII，含 heredoc 标记 PAYLOAD_m296222728618692 与 eval "$d2229" |
| `ev-000002` | 字符串提取 | stage2 字符串抽取：71 条 ASCII，含 domain/token/api_key、curl\|osascript、/tmp/osalogging.zip、/gate 分块上传与 rm -f |
| `ev-000003` | evidence.record | 静态解码脚本：heredoc→base64→gzip→2641 字节 stage2，sha256 206c96b...82acd；提取域名、token、api-key、暂存路径 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
