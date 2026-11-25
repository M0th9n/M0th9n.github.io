---
title: "恶意样本分析：WSF PowerShell Downloader（other · wsf · 55ea024e）"
published: 2026-11-24
draft: false
description: "恶意（置信度低）：WSF PowerShell Downloader · downloader/dropper · 难度 easy · 纯静态分析"
tags: ["WSF", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **WSF PowerShell Downloader**（存疑） · 置信度 **低**
> 
> 别名：JScript/Wsf.Downloader、PowerShell stager、WSF downloader dropper
> 
> 该文件是明文 Windows Script File（JScript），启动即调用 ScriptAPI.run，通过 MSXML2.XMLHTTP 以 HTTPS GET 下载 hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/PWKMK.ps1，用 Scripting.FileSystemObject 将响应写入 C:\Temp\ 下随机 8 字符命名的 .ps1，再以 WScript.Shell.Run(...,0,true) 隐藏窗口执行 powershell.exe -nop -ep bypass -file。脚本没有其他业务功能，行为链完整且可直接从源码确认，属于下载并投递后续 PowerShell 载荷的恶意引导脚本。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **WSF PowerShell Downloader** · 别名 JScript/Wsf.Downloader、PowerShell stager、WSF downloader dropper · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · dropper |
| 难度 | easy |
| 首次出现 | 2026-11-23 06:48:35 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">脚本加载即自动执行</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.007</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">创建临时暂存目录</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">HTTPS 下载远程脚本</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">随机命名落盘 PowerShell</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口执行 PowerShell</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b` |
| MD5 | _未记录_ |
| 大小 | 5,430 字节（5.3 KB） |
| 类型 | other · `wsf` |

## 行为分析

共 **6** 条行为，每条都挂了证据，且全部静态可得。

### 1. 脚本加载即自动执行

`T1059.007` · 置信度 **高** · 静态

文件为 <job> 形式的 WSF，JScript 主体定义完成后在 off 5298 直接调用 ScriptAPI.run，无需用户参数或交互即进入下载流程，并将 ScriptAPI 挂到全局对象以便再次调用。

> **证据**：off 5298: ScriptAPI.run; off 5369: global.ScriptAPI = ScriptAPI;
> 
> **来源**：`ev-000001`

### 2. 创建临时暂存目录

`T1074` · 置信度 **高** · 静态

通过 ActiveXObject('Scripting.FileSystemObject') 检查并创建 C:\Temp\，作为后续载荷落盘位置。

> **证据**：off 385: directory: 'C:\\Temp\\'; off 1293 ActiveXObject('Scripting.FileSystemObject'); off 1424 fso.FolderExists/CreateFolder
> 
> **来源**：`ev-000001`

### 3. HTTPS 下载远程脚本

`T1105` · 置信度 **高** · 静态

使用 MSXML2.XMLHTTP 同步 GET 请求 hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/PWKMK.ps1，仅当状态码为 200 时取响应正文，失败时按 maxAttempts=2 吞异常重试。

> **证据**：off 1973 ActiveXObject('MSXML2.XMLHTTP'); off 2082 xhr.open('GET', url, false); off 2128 xhr.send; off 2157 status === 200
> 
> **来源**：`ev-000001`

### 4. 随机命名落盘 PowerShell

`T1105` · 置信度 **高** · 静态

把下载内容通过 FileSystemObject.CreateTextFile 写入 C:\Temp\ 下由 Math.random 生成的 8 位大写字母数字文件名加 .ps1 后缀，避免固定文件名。

> **证据**：off 2453 randomToken(length); off 2733 return dir + randomToken(8) + '.ps1'; off 1558 fso.CreateTextFile(path, true)
> 
> **来源**：`ev-000001`

### 5. 隐藏窗口执行 PowerShell

`T1059.001` · 置信度 **高** · 静态

构造 powershell.exe -nop -ep bypass -file "<落盘路径>" 命令，并通过 WScript.Shell.Run(cmd, 0, true) 以隐藏窗口、等待结束的方式执行，绕过执行策略且不显示控制台。

> **证据**：off 2840 powershell.exe -nop -ep bypass -file; off 1860 shell.Run(cmd, 0, true)
> 
> **来源**：`ev-000001`

### 6. 静默运行不弹窗

`T1564.003` · 置信度 **高** · 静态

WScript.Shell.Run 的第二个参数为 0（隐藏窗口），第三个参数为 true（等待进程结束），使下载与执行过程对用户不可见。

> **证据**：off 1860: shell.Run(cmd, 0, true)
> 
> **来源**：`ev-000001`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/PWKMK[.]ps1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\<8位随机大写字母数字>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `whispragency[.]com` | 是 | 静态 |
| `payload_url` | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/PWKMK[.]ps1` | 是 | 静态 |
| `install_path` | `C:\Temp\` | 是 | 静态 |
| `staged_filename_pattern` | `%RANDOM8%.ps1（大写字母数字）` | 是 | 静态 |
| `launch_command` | `powershell.exe -nop -ep bypass -file "<staged_path>"` | 是 | 静态 |
| `download_retry` | `maxAttempts=2` | 否 | 静态 |
| `encryption_algo` | `none（脚本与通信均未加密）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得断言其为勒索软件、窃密程序或挖矿程序：源码只包含下载、落盘与执行，未出现加密文件、凭据读取或矿池相关逻辑。
- 不得断言具备持久化能力：源码未发现注册表 Run 键、计划任务、服务或启动目录写入。
- 不得断言最终载荷家族或具体 C2 基础设施归属：远程 PWKMK.ps1 未在本次静态分析中获取，其内容与后续行为未知。
- 不得把 whispragency[.]com 描述为已确认的长期 C2 面板：当前仅能证明该 URL 被用于一次性下载 PowerShell 脚本。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态档位，该格式没有可用的隔离动态通道，未取得任何运行时网络、进程或文件事件。
2. 样本不是 PE/ELF，结构化解析与仿真工具不适用，结论完全基于脚本源码与字符串。
3. 远程 PowerShell 载荷未下载，无法确认其功能、最终家族、后续 C2 与持久化方式；相关字段均待动态或外网复核。
4. 无法确认真实环境中 whispragency[.]com 的解析地址、证书与可用性；网络 IOC 仅来自源码常量。

## 证据索引

<details>
<summary>展开 1 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 静态字符串提取（ASCII 152 条），完整还原 WSF 源码，包含下载 URL、C:\Temp\ 路径、ActiveX 对象、随机文件名与 PowerShell 启动命令等关键证据。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
