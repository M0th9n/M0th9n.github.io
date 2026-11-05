---
title: "恶意样本分析：VBScript PowerShell Downloader（other · vbe · 206cfbab）"
published: 2026-11-05
draft: false
description: "恶意（置信度中）：VBScript PowerShell Downloader · downloader/loader · 难度 easy · 纯静态分析"
tags: ["VBScript", "downloader", "loader"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **VBScript PowerShell Downloader**（存疑） · 置信度 **中**
> 
> 别名：VBS/PS1 Downloader、Twejamaica Loader
> 
> 样本为可直接阅读的明文 VBScript（3131 字节，无 VBE 编码头）。其 PayloadPipeline 类完整实现了一条下载-落盘-执行链：硬编码 HTTPS 地址，以 MSXML2.XMLHTTP 发起 GET 下载 21.ps1，将响应体写入 C:\Temp\ 下的随机名 .ps1，再通过 WScript.Shell.Run 以隐藏窗口和 -nop -ep bypass 启动 powershell.exe 执行。下载并执行远程脚本的行为由源码直接可见，判定为恶意下载器/加载器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **VBScript PowerShell Downloader** · 别名 VBS/PS1 Downloader、Twejamaica Loader · _存疑_ |
| 置信度 | **中** |
| 行为类 | downloader · loader |
| 难度 | easy |
| 首次出现 | 2026-11-04 15:57:51 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/206cfbabb6175852a80ccfff9884e6019a39d712de6c198a3ac43e4e4e9f9c45/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">硬编码下载地址</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">创建暂存目录</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">HTTP拉取PS1载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">落盘随机名脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">静默启动PowerShell</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `206cfbabb6175852a80ccfff9884e6019a39d712de6c198a3ac43e4e4e9f9c45` |
| MD5 | _未记录_ |
| 大小 | 3,131 字节（3.1 KB） |
| 类型 | other · `vbe` |

## 行为分析

共 **6** 条行为，每条都挂了证据，且全部静态可得。

### 1. 硬编码下载地址

`T1071.001` · 置信度 **高** · 静态

在 Class_Initialize 中将远程载荷地址固定为 hxxps://twejamaica[.]org/aSUqKxqx/21[.]ps1，使用 HTTPS 443 端口。

> **证据**：源码偏移 192：m_url = "hxxps://twejamaica[.]org/aSUqKxqx/21.ps1"
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. 创建暂存目录

`T1074.001` · 置信度 **高** · 静态

通过 Scripting.FileSystemObject 检查并创建 C:\Temp\，作为下载脚本的暂存位置。

> **证据**：源码偏移 984：m_fs.CreateFolder m_stageDir（m_stageDir="C:\Temp\"）
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. HTTP拉取PS1载荷

`T1105` · 置信度 **高** · 静态

使用 MSXML2.XMLHTTP 对硬编码 URL 发起同步 GET 请求，仅在返回 Status=200 时继续。

> **证据**：源码偏移 1566：m_http.Open "GET", m_url, False；偏移 1803：If m_http.Status = 200
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 落盘随机名脚本

`T1105` · 置信度 **高** · 静态

将 HTTP 响应体 ResponseText 写入 C:\Temp\<8位大写随机字母>.ps1，文件名由 Randomize/Rnd 动态生成以规避固定名称检测。

> **证据**：源码偏移 1273 拼接触发路径；偏移 1861 CreateTextFile；偏移 1925 out.Write m_http.ResponseText
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 静默启动PowerShell

`T1059.001` · 置信度 **高** · 静态

通过 WScript.Shell.Run 以窗口样式 0（隐藏窗口）执行 powershell.exe -nop -ep bypass -file <payload>，并等待进程结束。

> **证据**：源码偏移 1331 构造命令行；偏移 2244：m_shell.Run m_launchCmd, 0, True
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 绕过执行策略

`T1562.001` · 置信度 **高** · 静态

命令行使用 -nop（NoProfile）与 -ep bypass（ExecutionPolicy Bypass），关闭配置文件加载并绕过 PowerShell 执行策略限制。

> **证据**：源码偏移 1331："powershell.exe -nop -ep bypass -file """ & m_payloadPath
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://twejamaica[.]org/aSUqKxqx/21[.]ps1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\<8位大写字母>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `twejamaica[.]org` | 是 | 静态 |
| `download_url` | `hxxps://twejamaica[.]org/aSUqKxqx/21[.]ps1` | 是 | 静态 |
| `stage_dir` | `C:\Temp\` | 是 | 静态 |
| `payload_filename_pattern` | `8 位大写随机字母 + .ps1（Randomize/Rnd 生成）` | 是 | 静态 |
| `launch_command` | `powershell.exe -nop -ep bypass -file "<payload>"，窗口样式 0` | 是 | 静态 |
| `encryption_algo` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要因扩展名 .vbe 判定其为编码或加密的 VBE 文件：文件内容为明文 VBScript，开头为 Option Explicit，不含 #@~^ 编码头。
- 不要断言最终载荷是勒索软件、窃密程序、RAT 或挖矿程序：远程 21.ps1 未被获取或执行，后续功能未知。
- 不要声称存在注册表、服务、计划任务、互斥体或自启动持久化：源码的 Finish 为空，未见任何持久化或自删除调用。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 纯静态分析，未在沙箱中执行样本，未观测到实际网络请求、文件落盘或 PowerShell 子进程。
2. 第二阶段 hxxps://twejamaica[.]org/aSUqKxqx/21[.]ps1 未下载，无法判定其真实功能、最终家族或后续 C2。
3. 配置文件与 C2 均由源码静态提取，尚未经动态网络流量验证；若域名/路径已失效，实际行为可能无法复现。
4. 样本无持久化代码，是否为一次性下载器取决于未获取的第二阶段载荷。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 101 条 ASCII 字符串，包含硬编码 URL、C:\Temp\ 暂存路径、MSXML2.XMLHTTP/WScript.Shell/FileSystemObject 对象名及 powershell.exe -nop -ep bypass 命令行。 |
| `ev-000002` | evidence.record | 逐行审阅明文 VBScript 源码，记录 PayloadPipeline 的下载、落盘、隐藏启动流程及无持久化/无清理结论。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
