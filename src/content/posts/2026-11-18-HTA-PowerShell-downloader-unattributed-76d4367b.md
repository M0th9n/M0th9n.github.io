---
title: "恶意样本分析：HTA PowerShell downloader (unattributed)（other · hta · 76d4367b）"
published: 2026-11-18
draft: false
description: "恶意（置信度低）：HTA PowerShell downloader (unattributed) · downloader/loader · 难度 medium · 纯静态分析"
tags: ["HTA", "downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **HTA PowerShell downloader (unattributed)**（存疑） · 置信度 **低**
> 
> HTA 内嵌 VBScript 经去噪声后拼出隐藏执行的 PowerShell 命令，PowerShell 先用自定义字母表+Base64+异或解出第二阶段脚本，再从三个硬编码 IP 以 JPG 名义下载数据、截取 <<STT>> 与 <<D>> 之间的 Base64 并反射加载 .NET 程序集，最后以 Msbuild/x86 参数调用其方法。整条链路是明确的下载-加载器行为，代码本身即为恶意意图的直接证据；但全程为静态解码，未在真实主机执行。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **HTA PowerShell downloader (unattributed)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | medium |
| 首次出现 | 2026-11-16 15:44:11 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/76d4367b1fbcdb020ea7f94e9aea1ac40dcbca536b21f8053574e1a9ab166afa/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口运行 HTA</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">去除噪声还原命令</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">以隐藏方式拉起 PowerShell</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">自定义字母表解码脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">轮询多个 IP 下载载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `76d4367b1fbcdb020ea7f94e9aea1ac40dcbca536b21f8053574e1a9ab166afa` |
| MD5 | _未记录_ |
| 大小 | 21,887 字节（21.4 KB） |
| 类型 | other · `hta` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 隐藏窗口运行 HTA

`T1564.003` · 置信度 **高** · 静态

HTA:APPLICATION 设置 BORDER=none、SHOWINTASKBAR=no、WINDOWSTATE=minimize，脚本结束调用 window.close，使整个执行过程无可见界面。

> **证据**：HTA:APPLICATION 属性 off 0x30-0x2E0；结尾 window.close
> 
> **来源**：`ev-000001`

### 2. 去除噪声还原命令

`T1027` · 置信度 **高** · 静态

VBScript 用 393 次字符串拼接构造命令，再以 Replace 删除 548 处固定噪声 token "jkkbjnjm"，还原出完整 PowerShell 命令行。

> **证据**：a9JsrcpKj = a9JsrcpKj & "..."; Replace(a9JsrcpKj, "jkkbjnjm", "")
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 以隐藏方式拉起 PowerShell

`T1059.001` · 置信度 **高** · 静态

通过 CreateObject("WScript.Shell").Run 隐藏执行 cmd /c %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe，并传入内嵌的混淆脚本；使用 SysNative 绕过 WOW64 重定向以调用 64 位 PowerShell。

> **证据**：CreateObject("WScript.Shell").Run a9JsrcpKj, 0, False；命令行含 cmd /c %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 自定义字母表解码脚本

`T1140` · 置信度 **高** · 静态

PowerShell 把自定义字母表字符串映射回标准 Base64，FromBase64String 解码后逐字节减去 21 字节密钥，得到第二阶段脚本并 iex 执行。

> **证据**：$friMPmCR 自定义字母表；$dCxgl5M 21 字节密钥；[Convert]::FromBase64String；iex $vq3Ues
> 
> **来源**：`ev-000002`

### 5. 轮询多个 IP 下载载荷

`T1105` · 置信度 **高** · 静态

第二阶段使用 System.Net.WebClient 对三个硬编码 IP 的 JPG 路径随机排序后依次 DownloadData，任一成功即返回数据。

> **证据**：DownloadDataFromLinks：$a1.DownloadData($a3)；URL hxxp://64.224.17[.]115/img/1.jpg、hxxp://129.121.148[.]240/img/pics/1.jpg、hxxp://155.103.71[.]164/1.jpg
> 
> **来源**：`ev-000002`

### 6. 截取标记并反射加载 .NET

`T1620` · 置信度 **高** · 静态

在下载内容中定位 <<STT>> 与 <<D>> 两个标记，取两者之间的子串做 Base64 解码，再用 [Reflection.Assembly]::Load 在内存中加载 .NET 程序集。

> **证据**：$a9='<<STT>>'；$b0='<<D>>'；[System.Convert]::FromBase64String($b4)；[System.Reflection.Assembly]::Load($b5)
> 
> **来源**：`ev-000002`

### 7. 调用加载器并指定目标进程

`T1055` · 置信度 **中** · 静态

反射加载后取类型 myprogram.Homees 的方法 runss 并调用，参数依次为反转的 IPFS 地址、'0'、空串、'Msbuild'、'0'、'x86'，把注入目标进程名与架构交给下游加载器。

> **证据**：$b7.GetMethod('run'+'ss').Invoke($null, [object[]]($b9,'0','','Msbuild','0','x86'))
> 
> **来源**：`ev-000002`

### 8. IPFS 网关作备用载荷源

`T1105` · 置信度 **中** · 静态

脚本把反转存储的 myfilebase[.]com IPFS 网关地址作为参数传给 .NET 加载器，用于主 IP 下载失败时的二次获取；存储串缺少 http 前缀，由加载器补齐。

> **证据**：反转后 s://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmWnAEko87xHCkk88NUJGxMeDYCszeBjURHeYiBM4j2ccr（原串经 Substring(0, Length-15) 截断）
> 
> **来源**：`ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://64[.]224[.]17[.]115/img/1.jpg` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://129[.]121[.]148[.]240/img/pics/1.jpg` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://155[.]103[.]71[.]164/1.jpg` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmWnAEko87xHCkk88NUJGxMeDYCszeBjURHeYiBM4j2ccr` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `64.224.17[.]115, 129.121.148[.]240, 155.103.71[.]164` | 是 | 静态 |
| `fallback_url` | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmWnAEko87xHCkk88NUJGxMeDYCszeBjURHeYiBM4j2ccr` | 否 | 静态 |
| `payload_markers` | `<<STT>> ... <<D>>` | 是 | 静态 |
| `encryption_algo` | `stage1: custom base64 alphabet + 21-byte subtract key (0xAD,0x7A,0x14,0x0A,0x71,0xE3,0xC2,0x50,0x2B,0x1D,0xC6,0x8A,0x9F,0x3C,0xB4,0xEA,0x2E,0xED,0xF7,0x10,0x1D); stage2 strings: LUT '2fiEqFLy3VCsl6o7' + XOR 0x49` | 是 | 静态 |
| `injection_target` | `Msbuild` | 否 | 静态 |
| `architecture` | `x86` | 否 | 静态 |
| `install_path` | `-` | 否 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能声称已在真实主机或沙箱中引爆并观测到下载、注入或持久化；本报告全部结论来自对 HTA/脚本的静态解码。
- 不能断言最终载荷的家族与功能（窃密、勒索、RAT 等）；远端 .NET 程序集与 IPFS 载荷均未获取。
- 不能声称样本创建了持久化项（注册表/计划任务/服务）；脚本中未见此类代码。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 未执行样本，无沙箱网络与内存观测；所有 C2 与行为均为静态还原，recoverability=static 且 pending_dynamic_verify=true。
2. 三个下载 IP 与 IPFS 网关在分析时未访问，无法确认其当前存活状态与返回内容。
3. 未能获取 <<STT>>..<<D>> 之间的 .NET 程序集及 IPFS 二次载荷，因此无法确认注入实现、最终家族与后续行为。
4. IPFS 地址在原脚本中以反转形式保存且截去 http 前缀，报告中的 scheme 为按上下文补全。
5. 未获得任何 AV/YARA 命中，家族命名为候选且标记 uncertain。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 HTA 的 ASCII/UTF-16 字符串，确认 HTA:APPLICATION 属性、a9JsrcpKj 拼接片段与 CreateObject(WScript.Shell) 等结构。 |
| `ev-000002` | evidence.record | 自写 Python 静态解混淆：去噪声还原 VBScript 命令、解出第二阶段 PowerShell、解码下载 URL/IPFS 地址与 .NET 调用参数（未执行样本）。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
