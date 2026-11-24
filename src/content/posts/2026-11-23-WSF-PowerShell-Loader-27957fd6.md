---
title: "恶意样本分析：WSF PowerShell Loader（other · wsf · 27957fd6）"
published: 2026-11-23
draft: false
description: "恶意（置信度中）：WSF PowerShell Loader · downloader/loader · 难度 easy · 纯静态分析"
tags: ["WSF", "downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **WSF PowerShell Loader**（存疑） · 置信度 **中**
> 
> 别名：JScript WSF downloader、PowerShell stager
> 
> 样本为明文 JScript 的 Windows Script File，源码可直接阅读：它通过 MSXML2.XMLHTTP 从 hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/KMK.ps1 下载 PowerShell 脚本，写入 C:\Temp\ 下随机命名的 .ps1，并以隐藏窗口执行 powershell.exe -nop -ep bypass -file，构成典型的下载器/加载器链。下载与执行逻辑由源码直接证实，无需依赖启发式判断。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **WSF PowerShell Loader** · 别名 JScript WSF downloader、PowerShell stager · _存疑_ |
| 置信度 | **中** |
| 行为类 | downloader · loader |
| 难度 | easy |
| 首次出现 | 2026-11-23 06:53:26 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">创建 Temp 暂存目录</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">HTTPS 拉取远程脚本</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">失败自动重试两次</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">随机名写入脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口执行载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c` |
| MD5 | _未记录_ |
| 大小 | 4,161 字节（4.1 KB） |
| 类型 | other · `wsf` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 创建 Temp 暂存目录

`T1074` · 置信度 **高** · 静态

调用 Scripting.FileSystemObject 的 FolderExists/CreateFolder，确保 C:\Temp\ 目录存在，作为下载载荷的落地位置。

> **证据**：scan.strings off 0x1A6 'fs.FolderExists' / off 0x1FD 'fs.CreateFolder'; 默认配置 off 0x722 "directory: 'C:\Temp\'"
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. HTTPS 拉取远程脚本

`T1105` · 置信度 **高** · 静态

使用 MSXML2.XMLHTTP 对固定 URL 发起同步 GET，期望返回 200 后取得响应正文作为待执行脚本。

> **证据**：off 0x169 new ActiveXObject('MSXML2.XMLHTTP'); off 0x427 http.open('GET', url, false); off 0x456 http.send; URL off 0x6D0
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 失败自动重试两次

`T1071.001` · 置信度 **高** · 静态

下载封装在 retry 中，按 maxAttempts=2 对同一 URL 最多尝试 3 次，仅在返回非空时跳出，提升弱网/单点故障下的投递成功率。

> **证据**：off 0x903 retry 循环 'for (i=0;i<=attempts;i++)'; off 0x747 maxAttempts: 2
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 随机名写入脚本

`T1036` · 置信度 **高** · 静态

把下载到的响应正文写入 C:\Temp\ 下由 Math.random 生成的 8 位大写字母数字文件名，扩展名固定为 .ps1；下载为空则终止。

> **证据**：off 0x8A9 randomName: 'Math.random.toString(36).slice(2, 10).toUpperCase + .ps1'; off 0xBDC fs.CreateTextFile / writeText
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 隐藏窗口执行载荷

`T1059.001` · 置信度 **高** · 静态

通过 WScript.Shell.Run 以窗口参数 0、等待模式 true 启动 powershell.exe，执行刚写入的 .ps1，父进程为 WSH 宿主。

> **证据**：off 0x535 shell.Run(cmd, 0, true); off 0xC1C 命令行 'powershell.exe -nop -ep bypass -file "<path>"'; off 0xC6A execHidden
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 绕过 PowerShell 策略

`T1562.001` · 置信度 **高** · 静态

命令行携带 -nop（不加载配置文件）与 -ep bypass（绕过执行策略），以便在默认受限策略的主机上直接运行远程脚本。

> **证据**：off 0xC1C 命令行字符串 'powershell.exe -nop -ep bypass -file'
> 
> **来源**：`ev-000001` · `ev-000002`

### 7. 对外暴露脚本接口

`T1059.001` · 置信度 **中** · 静态

执行后把内部 Api 对象挂到 WSH 的 this.ScriptAPI，保留 run/config/reset 方法，使同一宿主上下文中的后续脚本可复用下载与执行能力。

> **证据**：off 0xFC7 makeApi; off 0xFFB this.ScriptAPI = Api; off 0xE1A run/config/reset 方法
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/KMK[.]ps1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\<8位大写随机字母数字>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `whispragency[.]com` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `/cnokulg/nlcayps/knarics/KMK.ps1` | 是 | 静态 |
| `download_dir` | `C:\Temp\` | 是 | 静态 |
| `download_filename` | `Math.random.toString(36).slice(2,10).toUpperCase + '.ps1'（8 位大写字母数字）` | 是 | 静态 |
| `exec_command` | `powershell.exe -nop -ep bypass -file "<downloaded .ps1>"` | 是 | 静态 |
| `max_attempts` | `2` | 否 | 静态 |
| `encryption_algo` | `none（明文 HTTP 响应直接落盘，无解密环节）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不应认定为勒索软件或窃密程序：源码只做下载与 PowerShell 执行，未见文件加密、凭据收集或数据外传代码。
- 不应断言存在持久化：未发现注册表 Run 键、计划任务、服务安装或启动目录写入逻辑。
- 不应断言样本已成功外联、落盘或执行：本次为纯静态分析，未运行样本，C2 可达性与 KMK.ps1 的真实内容均未验证。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态分析，样本未运行，未取得网络响应、落地文件或子进程等运行时证据。
2. 远程 KMK.ps1 的内容与最终行为未知；其后可能包含持久化、信息窃取或其他载荷，不能据本样本推断。
3. 域名 whispragency[.]com 当前是否解析、URL 是否仍分发载荷未验证。
4. 无可用的引擎/YARA 命中，家族命名为基于代码结构的通用描述，不代表已确认的厂商命名。
5. 该样本为文本脚本，PE/ELF 结构解析类工具不适用；行为结论来自源码字符串与逻辑审阅。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | ASCII 字符串 123 条，逐条给出偏移；包含 ActiveXObject/XMLHTTP/shell.Run/远程 URL/C:\Temp/powershell 命令等关键常量。 |
| `ev-000002` | evidence.record | 静态解析与哈希核验：sha256 与样本名一致，确认明文无混淆，并复原下载→落地→隐藏执行的完整链路。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
