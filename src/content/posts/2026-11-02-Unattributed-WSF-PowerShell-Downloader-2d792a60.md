---
title: "恶意样本分析：Unattributed WSF PowerShell Downloader（other · wsf · 2d792a60）"
published: 2026-11-02
draft: false
description: "恶意（置信度低）：Unattributed WSF PowerShell Downloader · downloader/loader/dropper · 难度 easy · 纯静态分析"
tags: ["downloader", "loader", "dropper", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed WSF PowerShell Downloader**（存疑） · 置信度 **低**
> 
> 别名：WSF/PS1 downloader、JScript staged PowerShell loader
> 
> WSF 内嵌 JScript 逻辑完整可见：从固定 HTTPS 地址下载 PowerShell 脚本，写入 C:\Temp\ 下的随机名 .ps1，并以隐藏窗口、禁用配置加载、绕过执行策略的方式启动 powershell.exe 执行。下载并执行远端代码的意图明确，无需依赖外部情报即可判定为恶意下载器/加载器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed WSF PowerShell Downloader** · 别名 WSF/PS1 downloader、JScript staged PowerShell loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader · dropper |
| 难度 | easy |
| 首次出现 | 2026-11-02 08:03:27 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/2d792a60273e0b756e5efe2ef9275df360eb55faa365fdb2dffeb4a6ba431846/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">经MSXML请求远端载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">创建临时目录</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">随机名落盘PS1</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口启动PowerShell</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">绕过执行策略与配置</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `2d792a60273e0b756e5efe2ef9275df360eb55faa365fdb2dffeb4a6ba431846` |
| MD5 | _未记录_ |
| 大小 | 3,583 字节（3.5 KB） |
| 类型 | other · `wsf` |

## 行为分析

共 **6** 条行为，每条都挂了证据，且全部静态可得。

### 1. 经MSXML请求远端载荷

`T1071.001` · 置信度 **高** · 静态

通过 ActiveXObject('MSXML2.XMLHTTP') 以同步 GET 请求 hxxps://kronemedia[.]de/wp-content/plugins/wpqlxeq/KMSKMK[.]PS1，仅在 HTTP 200 时取 responseText 作为下一阶段脚本，并最多重试 2 次。

> **证据**：字符串偏移 0xE4 的 URL；偏移 0x578 的 'MSXML2.XMLHTTP'；偏移 0x5A3 的 http.open('GET', State.url, false) / http.send
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. 创建临时目录

`T1074.001` · 置信度 **高** · 静态

使用 Scripting.FileSystemObject 检查 C:\Temp\ 是否存在，不存在则 CreateFolder 创建，作为下载载荷的暂存目录。

> **证据**：偏移 0x400 的 FolderExists(State.dir) / 0x430 的 fs.CreateFolder(State.dir)；State.dir 位于偏移 0x131 的 'C:\\Temp\\'
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 随机名落盘PS1

`T1105` · 置信度 **高** · 静态

以 8 位 [A-Z0-9] 随机串为文件名，将下载到的脚本文本写入 C:\Temp\<token>.ps1，覆盖同名文件。

> **证据**：偏移 0x835 的 pool='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'；0x8EF 的 target=State.dir+token+'.ps1'；0x932 的 fs.CreateTextFile(target,true) / handle.Write
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 隐藏窗口启动PowerShell

`T1059.001` · 置信度 **高** · 静态

调用 WScript.Shell.Run 以窗口模式 0（隐藏）并等待返回的方式执行 powershell.exe 运行落盘的 .ps1。

> **证据**：偏移 0x9AF 的 sh.Run('powershell.exe -nop -ep bypass -file "'+target+'"', 0, true)
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 绕过执行策略与配置

`T1562.001` · 置信度 **高** · 静态

PowerShell 命令行显式使用 -nop（不加载用户配置）与 -ep bypass（绕过执行策略），降低脚本被拦截的概率。

> **证据**：偏移 0x9AF 起的命令行字符串 '-nop -ep bypass -file'
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 借WSF解析执行脚本

`T1059.007` · 置信度 **高** · 静态

样本以 Windows Script File（XML + <script language="JScript"> CDATA）形式交付，由 Windows Script Host 解析执行内嵌 JScript，入口为 IIFE 末尾的 Api.run。

> **证据**：文件头 '<?xml version="1.0"?>'、偏移 0x1E 的 '<script language="JScript">'、偏移 0xDA9 的 'Api.run;'
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://kronemedia[.]de/wp-content/plugins/wpqlxeq/KMSKMK[.]PS1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\%RANDOM8%.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://kronemedia[.]de/wp-content/plugins/wpqlxeq/KMSKMK[.]PS1` | 是 | 静态 |
| `download_path` | `C:\Temp\` | 是 | 静态 |
| `dropped_filename` | `[A-Z0-9]{8}.ps1` | 是 | 静态 |
| `exec_command` | `powershell.exe -nop -ep bypass -file "C:\Temp\<token>.ps1"` | 是 | 静态 |
| `retries` | `2` | 否 | 静态 |
| `encryption_algo` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 未发现任何加密、文件加密或破坏逻辑，不应将其归为 ransomware / wiper。
- 本文件未访问浏览器数据、凭据库或键盘输入，不应仅凭下载器行为称其为 stealer。
- 未发现注册表 Run 键、计划任务、服务或启动目录写入，就本 WSF 而言不具备持久化能力。
- 远端 PS1 内容未获取，不能断言最终载荷的家族、真实 C2 或具体功能。
- 不能因使用 PowerShell 就断言存在无文件执行或进程注入；本脚本是把文件落盘后调用 powershell.exe。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 纯静态分析：样本未在沙箱中引爆，reproduced=false，所有行为结论均来自对脚本源码的直接审阅。
2. 远端 PS1（KMSKMK.PS1）未下载，其内容、后续 C2、持久化方式与最终家族均未知，相关字段标记为待动态验证。
3. 域名 kronemedia[.]de 可能在分析时已失效，或按来源 IP / User-Agent 差异化下发，静态阶段无法确认其当前状态。
4. 未观察到实际网络流量，C2 条目为静态恢复（recoverability=static, pending_dynamic_verify=true）。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | ASCII 字符串抽取 105 条：包含下载 URL、C:\Temp\ 路径、三个 COM 类名、PowerShell 命令行与随机文件名生成常量，覆盖全部关键逻辑。 |
| `ev-000002` | evidence.record | 逐行审阅内嵌 JScript 得到的执行链与配置（URL、投放目录、随机名规则、powershell 命令、重试次数），为人工推导登记。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
