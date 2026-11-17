---
title: "恶意样本分析：myprogram.Homees loader（other · hta · 7c57b600）"
published: 2026-11-17
draft: false
description: "恶意（置信度低）：myprogram.Homees loader · downloader/loader · 难度 medium · 纯静态分析"
tags: ["downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **myprogram.Homees loader**（存疑） · 置信度 **低**
> 
> 别名：Homees loader、HTA PowerShell downloader
> 
> 样本是伪装成系统页面的 HTA，脚本把真实命令拆成上百段并插入垃圾串 dIpdbcpc，运行时删除垃圾串后拼出 %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe 命令；第二阶 PowerShell 用自定义字母表与 16 字节密钥解出下载逻辑，从三个硬编码 IP 的 JPEG 中截取 Base64 .NET 程序集并反射加载，再以 IPFS 地址等参数调用载荷入口。整条链已从文件字节完整还原，无任何正常软件用途。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **myprogram.Homees loader** · 别名 Homees loader、HTA PowerShell downloader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | medium |
| 首次出现 | 2026-11-16 08:02:06 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/7c57b600932d784aab952029de50fbe6ff376422e4540d8e555c79d9b94ba763/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口启动</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">垃圾字符混淆命令</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027;T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">经 WScript.Shell 拉起 PowerShell</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001;T1059.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">自定义字母表加 XOR 解密</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140;T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">休眠后从三台主机取图</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105;T1071.001;T1497.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `7c57b600932d784aab952029de50fbe6ff376422e4540d8e555c79d9b94ba763` |
| MD5 | _未记录_ |
| 大小 | 21,979 字节（21.5 KB） |
| 类型 | other · `hta` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 隐藏窗口启动

`T1564.003` · 置信度 **高** · 静态

HTA:APPLICATION 将窗口状态设为最小化，隐藏任务栏按钮与系统菜单；脚本执行完毕后立即调用 window.close 关闭宿主窗口。

> **证据**：HTA 偏移 0x118 WINDOWSTATE="minimize"、0x102 SYSMENU="no"、0x559d window.close
> 
> **来源**：`ev-000001`

### 2. 垃圾字符混淆命令

`T1027;T1140` · 置信度 **高** · 静态

把完整命令拆成数百个字符串片段，每段插入固定垃圾串 dIpdbcpc，运行末尾用 Replace 一次性删除全部垃圾串再拼接。

> **证据**：HTA 偏移 0x170 起为第一段 aFI1ocJxF 拼接，0x536c Replace(aFI1ocJxF, "dIpdbcpc", "")
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 经 WScript.Shell 拉起 PowerShell

`T1059.001;T1059.005` · 置信度 **高** · 静态

以 CreateObject("WScript.Shell") 获得执行对象后调用 Run，用隐藏窗口、异步方式启动 %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe 并传入长参数串。

> **证据**：HTA 偏移 0x5554 CreateObject、0x5576 shell.Run；还原命令前缀 cmd /c %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 自定义字母表加 XOR 解密

`T1140;T1027` · 置信度 **高** · 静态

第二阶脚本用 _mfh 函数（字母表 6QYMqaSIoED7ztw2，两字符组合成字节后 XOR 0x36）还原所有字符串；对内嵌数据先按自定义字母表重映射回标准 Base64，再逐字节减去 16 字节密钥并对结果执行 iex。

> **证据**：第二阶 PowerShell 的 _mfh 函数、$pHuCTgF 数据块、$cH5urrG 密钥与末尾 iex
> 
> **来源**：`ev-000002`

### 5. 休眠后从三台主机取图

`T1105;T1071.001;T1497.003` · 置信度 **高** · 静态

强制启用 TLS1.2 并 Start-Sleep 3 秒，然后用 WebClient 以随机顺序请求三个硬编码 IP 上的 .jpg 地址，任一请求成功即返回其内容。

> **证据**：第二阶脚本 SecurityProtocol=Tls12、Start-Sleep -Seconds 3、DownloadDataFromLinks 与三个 URL 字面量
> 
> **来源**：`ev-000003`

### 6. 图内提取并加载 .NET

`T1620;T1027.009` · 置信度 **高** · 静态

以 <<STT>> 与 <<D>> 为边界从 HTTP 响应文本中截取 Base64 数据，Convert.FromBase64String 解码后通过 Assembly.Load 在 PowerShell 进程内反射加载 .NET 程序集。

> **证据**：第二阶脚本 $a9=<<STT>>、$b0=<<D>>、IndexOf/Substring 截取、Reflection.Assembly::Load
> 
> **来源**：`ev-000003`

### 7. 反射调用载荷入口

`T1620` · 置信度 **高** · 静态

取类型 myprogram.Homees 的 runs 方法并反射调用，传入六个参数：IPFS 地址、"0"、空串、"Msbuild"、"0"、"x86"。

> **证据**：第二阶脚本 $b6.GetType("mypr"+"ogram.Homees") 与 GetMethod("run"+"ss").Invoke(...)
> 
> **来源**：`ev-000003`

### 8. IPFS 网关下发下一阶段

`T1105;T1071.001` · 置信度 **高** · 静态

作为参数交给载荷的 URL 以反转方式存放，还原后指向 myfilebase[.]com 的 IPFS 网关，路径为 QmREcHA2N7FKb3Hzegws5wPajK5wRY4qQt9FNEeLyi7kJr，用于取回后续载荷。

> **证据**：第二阶脚本 $b9 反转并截尾 15 字符后得到 misleading-lime-termite[.]myfilebase[.]com/ipfs/QmREc…
> 
> **来源**：`ev-000003`

### 9. 混入无关代码干扰分析

`T1027` · 置信度 **高** · 静态

脚本中混入与载荷无关的 CheckNumber 奇偶判断函数，并在加载前后两次输出 CPU 占用前五的进程表，用于干扰人工阅读。

> **证据**：HTA 偏移 0x53a4 CheckNumber 函数；第二阶脚本两处 Get-Process | Sort-Object CPU | Format-Table
> 
> **来源**：`ev-000001` · `ev-000003`


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
| http | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmREcHA2N7FKb3Hzegws5wPajK5wRY4qQt9FNEeLyi7kJr` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `64[.]224[.]17[.]115;129[.]121[.]148[.]240;155[.]103[.]71[.]164` | 是 | 静态 |
| `payload_url` | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmREcHA2N7FKb3Hzegws5wPajK5wRY4qQt9FNEeLyi7kJr` | 是 | 静态 |
| `download_markers` | `<<STT>> / <<D>>` | 是 | 静态 |
| `encryption_algo` | `第一阶：自定义字母表重映射 + Base64 + 16 字节密钥逐字节减法 (key=4b8c6f638c001ab4da07ebcc08246fd9)；第二阶：6QYMqaSIoED7ztw2 字母表 base16 组合 + XOR 0x36` | 是 | 静态 |
| `reflective_entry` | `myprogram.Homees.runs` | 是 | 静态 |
| `loader_process_param` | `Msbuild` | 否 | 静态 |
| `architecture` | `x86` | 否 | 静态 |
| `sleep_seconds` | `3` | 否 | 静态 |
| `stage2_sha256` | `5d8aced526a1df2042bf4cf4252a7bfba47a4231c760fa42934eab2312b41326` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言最终 .NET 载荷的家族与具体功能：本次未取得该程序集，只看到加载与调用入口。
- 不能断言存在文件落地、注册表持久化、服务或计划任务：HTA 链在内存中完成，静态证据中没有写盘与自启动操作。
- 不能把 64.224.17[.]115、129.121.148[.]240、155.103.71[.]164 认定为 C2 控制端：它们只承担图床化的加载器分发。
- 不能断言样本具备窃密、勒索或远控能力：当前证据只覆盖下载与反射加载。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 该格式没有隔离动态通道，本次为纯静态分析，未运行样本，网络行为与后续载荷均未被观测。
2. 三台下载主机与 myfilebase[.]com 均未访问（默认无网），最终 .NET 程序集无法取得，其功能与真实 C2 无法确认。
3. IPFS 地址的协议前缀在存放时被截断（字符串反转后截掉尾部），https 与 443 端口依据脚本设置的 TLS1.2 推断，需动态确认。
4. 样本依赖 64 位系统上的 SysNative 路径；在 32 位宿主或该路径不可用时脚本可能直接失败，实际成功率未验证。
5. 载荷参数中的 "Msbuild"、"x86" 语义只能从命名推测为执行目标与架构，具体用途需取得程序集后确认。

## 证据索引

<details>
<summary>展开 3 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 对原始 HTA 抽取 437 条 ASCII 字符串，确认 HTA:APPLICATION 隐藏窗口配置、aFI1ocJxF 拼接链、Replace/CreateObject/shell.Run/window.close 等关键语句位置。 |
| `ev-000002` | evidence.record | 按脚本自身拼接与替换逻辑还原第一阶命令行，并按其自定义字母表/Base64/XOR 算法解出 2257 字节第二阶 PowerShell（sha256=5d8aced5…1326）。 |
| `ev-000003` | evidence.record | 还原第二阶全部混淆字符串：三个 JPEG 下载地址、<<STT>>/<<D>> 标记、反射入口 myprogram.Homees.runs、反转的 IPFS 地址与六个调用参数。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
