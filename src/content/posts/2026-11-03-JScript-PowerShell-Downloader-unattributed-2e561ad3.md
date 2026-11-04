---
title: "恶意样本分析：JScript/PowerShell Downloader (unattributed)（other · jse · 2e561ad3）"
published: 2026-11-03
draft: false
description: "恶意（置信度低）：JScript/PowerShell Downloader (unattributed) · downloader/dropper · 难度 easy · 纯静态分析"
tags: ["downloader", "dropper"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **JScript/PowerShell Downloader (unattributed)**（存疑） · 置信度 **低**
> 
> 样本为可直接阅读的明文 JScript：从硬编码 HTTP 地址下载 PowerShell 脚本，写入 C:\Temp\ 后以隐藏窗口执行，并同时通过计划任务、启动目录快捷方式和注册表 Run 键建立三重持久化。代码中不存在任何正常软件功能，下载、执行、持久化链路完整且自证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **JScript/PowerShell Downloader (unattributed)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · dropper |
| 难度 | easy |
| 首次出现 | 2026-11-03 06:44:16 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">下载远程PowerShell脚本</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">写入临时目录随机脚本</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口执行载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册计划任务持久化</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">投放启动目录快捷方式</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32` |
| MD5 | _未记录_ |
| 大小 | 5,948 字节（5.8 KB） |
| 类型 | other · `jse` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 下载远程PowerShell脚本

`T1105` · 置信度 **高** · 静态

通过 MSXML2.XMLHTTP 同步 GET 硬编码地址 hxxp://clw-trucks[.]top/xcd/246[.]ps1，状态码 200 时把 responseText 作为下一阶段脚本内容。

> **证据**：off 112 REMOTE_URL；off 1656 fetchPayload；off 1690 createCOM('MSXML2.XMLHTTP')；off 1753 xhr.open('GET', url, false)
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. 写入临时目录随机脚本

`T1105` · 置信度 **高** · 静态

创建 C:\Temp\ 目录，并以 10 位随机大写字母加 .ps1 后缀命名落地文件，把下载内容写入该文件。

> **证据**：off 170 TEMP_DIR: 'C:\\Temp\\'；off 1000 writeFile/CreateTextFile；off 5440 CONFIG.TEMP_DIR + randomName('.ps1')
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 隐藏窗口执行载荷

`T1059.001` · 置信度 **高** · 静态

调用 WScript.Shell.Run 以 powershell.exe -nop -ep bypass -windowstyle hidden -file 执行刚写入的 .ps1，绕过执行策略并隐藏窗口。

> **证据**：off 1990 psCommand；off 2034 '-nop -ep bypass'；off 2154 拼装 powershell.exe；off 5656 shell.Run(..., 0, true)
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 注册计划任务持久化

`T1053.005` · 置信度 **高** · 静态

经 Schedule.Service COM 在任务根目录注册名为 sys 的计划任务，动作是隐藏窗口运行落地脚本，登录触发延迟 5 分钟，失败每 5 分钟重试最多 3 次。

> **证据**：off 203 TASK_NAME: 'sys'；off 2265 Schedule.Service；off 2677 register；off 3976 RegisterTaskDefinition；off 3076 Delay=PT5M；off 3876 RestartCount=3
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 投放启动目录快捷方式

`T1547.001` · 置信度 **高** · 静态

在用户 Startup 目录创建随机名 .lnk，目标为 powershell.exe，参数为隐藏窗口执行落地脚本，窗口样式 7（最小化）后保存。

> **证据**：off 4207 makeStartupLink；off 4315 SpecialFolders('Startup')；off 4504 TargetPath='powershell.exe'；off 4681 lnk.Save
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 写入注册表Run键

`T1547.001` · 置信度 **高** · 静态

通过 WScript.Shell.RegWrite 向 HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealthMonitor 写入 REG_SZ，值为隐藏窗口执行落地脚本的 PowerShell 命令。

> **证据**：off 334 REG_PATH；off 414 REG_VALUE: 'SystemHealthMonitor'；off 4831 addRunKey；off 5044 RegWrite(key, val, 'REG_SZ')
> 
> **来源**：`ev-000001` · `ev-000002`

### 7. 伪装微软维护任务

`T1036.004` · 置信度 **高** · 静态

把新建计划任务的描述设为 Windows System Maintenance Utility、作者设为 Microsoft Corporation，冒充合法系统维护组件以降低可见性。

> **证据**：off 2857 RegistrationInfo.Description='Windows System Maintenance Utility'；off 2947 RegistrationInfo.Author='Microsoft Corporation'
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://clw-trucks[.]top/xcd/246[.]ps1` | 80 | download | 静态 | — |

### 主机

**落地路径**

- `C:\Temp\<RANDOM10>.ps1`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<RANDOM10>.lnk`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealthMonitor`

**计划任务**

- `\sys`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `clw-trucks[.]top (hxxp://clw-trucks[.]top/xcd/246[.]ps1)` | 是 | 静态 |
| `download_url` | `hxxp://clw-trucks[.]top/xcd/246[.]ps1` | 是 | 静态 |
| `install_path` | `C:\Temp\<RANDOM10>.ps1` | 是 | 静态 |
| `task_name` | `sys` | 是 | 静态 |
| `task_delay_minutes` | `5` | 否 | 静态 |
| `task_restart` | `RestartInterval=PT5M, RestartCount=3` | 否 | 静态 |
| `registry_run_value` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealthMonitor` | 是 | 静态 |
| `powershell_flags` | `-nop -ep bypass -windowstyle hidden -file` | 是 | 静态 |
| `encryption_algo` | `none` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能判定为勒索软件或信息窃取程序：代码中没有文件加密、凭据读取、浏览器数据收集或外传逻辑，行为仅限下载、执行与持久化。
- 不能把远程 246.ps1 的具体能力归到本文件：该阶段载荷未被获取，其最终功能、哈希与 C2 均未观测。
- 不能仅凭任务名 sys 与伪造的 Microsoft 元数据将其归入某一具名家族：缺少家族特征串、配置结构或多引擎佐证。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 纯静态档位无 JSE 隔离动态通道，下载、落盘、计划任务注册、快捷方式与注册表写入均未在真实主机观测，属代码级推断。
2. 远程 hxxp://clw-trucks[.]top/xcd/246[.]ps1 未获取，第二阶段载荷内容与最终能力未知。
3. 未验证域名当前解析与存活状态，未进行任何真实外联。
4. 家族归属不明确，仅按行为归类为 JScript/PowerShell 下载器。
5. 运行时可能因 COM 组件可用性、权限或网络条件而提前 return，实际落地成功率未验证。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取样本全部 169 条 ASCII 字符串，命中 REMOTE_URL、TEMP_DIR、TASK_NAME、REG_PATH、REG_VALUE 及 MSXML2.XMLHTTP、Schedule.Service、RegWrite 等关键 API 字符串。 |
| `ev-000002` | evidence.record | 对明文源码逐段静态审计，记录各功能块文件偏移、配置项与行为映射（自述证据）。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
