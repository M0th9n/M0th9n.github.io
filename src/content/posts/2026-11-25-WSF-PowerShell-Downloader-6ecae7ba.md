---
title: "恶意样本分析：WSF PowerShell Downloader（other · wsf · 6ecae7ba）"
published: 2026-11-25
draft: false
description: "恶意（置信度中）：WSF PowerShell Downloader · downloader/dropper · 难度 easy · 纯静态分析"
tags: ["WSF", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **WSF PowerShell Downloader**（存疑） · 置信度 **中**
> 
> 别名：JScript/WSF downloader、PowerShell stager
> 
> 样本是一段明文可读的 Windows Script File（JScript），完整实现了『创建临时目录 → 通过 MSXML2.XMLHTTP 从远程 HTTPS 地址拉取 PowerShell 脚本 → 随机文件名落盘到 C:\Temp → 以 powershell.exe -nop -ep bypass 隐藏执行』的下载-投放链；无任何正常业务功能，也无用户交互或授权说明，属于典型的脚本下载器/投放器。结论直接来自脚本源码，未做真实引爆，故不给动态级证据。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **WSF PowerShell Downloader** · 别名 JScript/WSF downloader、PowerShell stager · _存疑_ |
| 置信度 | **中** |
| 行为类 | downloader · dropper |
| 难度 | easy |
| 首次出现 | 2026-11-25 10:23:52 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/6ecae7bae50c5865b7c37a867fac8d8b8a5650cfd534ed3e2e5cd9304f7932bb/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">建立临时落地目录</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">HTTPS 拉取远程脚本</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">下载失败重试三次</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">随机名写入临时脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">无策略启动 PowerShell</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `6ecae7bae50c5865b7c37a867fac8d8b8a5650cfd534ed3e2e5cd9304f7932bb` |
| MD5 | _未记录_ |
| 大小 | 3,813 字节（3.7 KB） |
| 类型 | other · `wsf` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 建立临时落地目录

`T1074.001` · 置信度 **高** · 静态

调用 FileSystemObject.FolderExists 检查 C:\Temp，不存在则 CreateFolder 创建，作为后续载荷的落地目录。

> **证据**：偏移 844-900：FolderExists / CreateFolder('C:\Temp\')
> 
> **来源**：`ev-000001`

### 2. HTTPS 拉取远程脚本

`T1105` · 置信度 **高** · 静态

通过 MSXML2.XMLHTTP 以同步 GET 请求 hxxps://whispragency[.]com/.../111KMK.ps1，仅当 HTTP 状态码为 200 时读取 responseText 作为载荷内容。

> **证据**：偏移 1307 open('GET',ctx.address,false)；1366 send；1400 status===200；1448 responseText
> 
> **来源**：`ev-000001`

### 3. 下载失败重试三次

`T1105` · 置信度 **高** · 静态

下载循环从 attempt=0 跑到 maxAttempts=2，异常或非 200 时最多重试 3 次，提高在弱网/拦截环境下的投递成功率。

> **证据**：偏移 1220 for(attempt=0;attempt<=ctx.maxAttempts;attempt++)；偏移 1573 attempt===ctx.maxAttempts
> 
> **来源**：`ev-000001`

### 4. 随机名写入临时脚本

`T1074.001` · 置信度 **高** · 静态

用 Math.random.toString(36).substring(2,10).toUpperCase 生成 8 位大写随机名，经 CreateTextFile 写入 C:\Temp\<随机名>.ps1 并关机文件句柄。

> **证据**：偏移 1933 随机后缀；2014 targetPath=directory+suffix+'.ps1'；2088 CreateTextFile；2155 Write；2195 Close
> 
> **来源**：`ev-000001`

### 5. 无策略启动 PowerShell

`T1059.001` · 置信度 **高** · 静态

调用 WScript.Shell.Run 执行 powershell.exe -nop -ep bypass -file "<targetPath>"，以隐藏窗口（参数 0）并等待其结束（bWaitOnReturn=true）。

> **证据**：偏移 2224 shell.Run；2252 命令行 '-nop -ep bypass -file'；2330 窗口样式 0
> 
> **来源**：`ev-000001`

### 6. 隐藏窗口执行载荷

`T1564.003` · 置信度 **高** · 静态

Run 的窗口样式参数为 0 且等待返回，使 PowerShell 第二阶段在无可见窗口的情况下运行，降低用户察觉。

> **证据**：偏移 2330-2350 Run(...,0,true)
> 
> **来源**：`ev-000001`

### 7. 借用 443 端口混淆流量

`T1071.001` · 置信度 **高** · 静态

下载地址使用 https 协议与 443 端口，将恶意拉取混入常规 Web 加密流量，规避基于端口的粗粒度检测。

> **证据**：偏移 600 初始地址 'hxxps://whispragency[.]com/.../111KMK.ps1'
> 
> **来源**：`ev-000001`

### 8. 暴露可改写配置接口

`T1059.001` · 置信度 **中** · 静态

脚本把 run/config/reset 封装为 window.ScriptAPI，其中 config(key,value) 可直接改写远程地址、工作目录与重试次数，便于投放者复用到不同载荷与基础设施。

> **证据**：偏移 3374 config:function(key,value)；3524 currentContext[key]=value；3743 this.ScriptAPI=api
> 
> **来源**：`ev-000001`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/111KMK.ps1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\%RANDOM%8UPPER%.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `whispragency[.]com` | 是 | 静态 |
| `download_url` | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/111KMK.ps1` | 是 | 静态 |
| `install_path` | `C:\Temp\` | 是 | 静态 |
| `payload_filename_pattern` | `<8 位大写随机串>.ps1` | 是 | 静态 |
| `execution_command` | `powershell.exe -nop -ep bypass -file "<targetPath>"` | 是 | 静态 |
| `retry_policy` | `maxAttempts=2（循环 0..2，共最多 3 次尝试）` | 否 | 静态 |
| `encryption_algo` | `none（脚本明文，载荷以 responseText 原样写盘）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能据本文件断言最终 PowerShell 载荷的功能、家族或危害类型——远程 111KMK.ps1 未取得、未分析。
- 不能声称样本使用了加密、混淆或编码容器——CDATA 内为明文可读 JScript，载荷以 responseText 原样写盘。
- 不能声称存在持久化行为（注册表 Run 键、计划任务、服务）——源码中没有任何持久化 API 调用。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态分析，未执行样本、未进行沙箱引爆，reproduced=false；实际网络回连与 PowerShell 行为未观测。
2. 远程载荷 hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/111KMK.ps1 在默认无网环境中未取得，其内容、最终 C2 与家族归属均未知，相关 C2 标记为 static 且 pending_dynamic_verify=true。
3. .wsf 既非 PE 也非 ELF，pe.*/elf.* 与 scan.hashes/scan.triage 的结构解析不适用；文件哈希与类型由静态读取脚本计算（ev-000002）。
4. ScriptAPI.config 具备运行时改写远程地址的能力，但未观测到任何外部调用方或配置下发行为，仅按代码能力描述。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | ASCII 字符串 118 条，完整还原脚本逻辑与 hxxps://whispragency[.]com/.../111KMK.ps1 下载地址、C:\Temp 落地路径、powershell.exe -nop -ep bypass 命令行 |
| `ev-000002` | evidence.record | 静态读取与哈希：3813 字节 XML/JScript，sha256=6ecae7...32bb、md5=0c0cef99...，无隐藏/加密二进制块 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
