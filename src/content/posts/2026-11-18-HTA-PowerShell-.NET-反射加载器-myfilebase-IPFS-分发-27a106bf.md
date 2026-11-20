---
title: "恶意样本分析：HTA/PowerShell .NET 反射加载器（myfilebase/IPFS 分发）（other · hta · 27a106bf）"
published: 2026-11-18
draft: false
description: "恶意（置信度低）：HTA/PowerShell .NET 反射加载器（myfilebase/IPFS 分发） · loader/downloader · 难度 easy · 纯静态分析"
tags: ["HTA", "loader", "downloader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **HTA/PowerShell .NET 反射加载器（myfilebase/IPFS 分发）**（存疑） · 置信度 **低**
> 
> 别名：HTA loader、PowerShell downloader
> 
> 样本为 HTA 脚本：在隐藏窗口下通过 WScript.Shell 启动 64 位 PowerShell，内联脚本先删除插入的固定垃圾串，再以“自定义 64 字符表替换 + Base64 解码 + 24 字节密钥逐字节减法”还原出 2287 字节 PowerShell 并直接 iex 执行；该脚本从三个 IP 地址随机顺序下载带 <<STT>>/<<D>> 标记的文本，截取标记间内容 Base64 解码后以反射方式在内存加载 .NET 程序集，并反射调用类型 myprogram.Homees 的 runss 方法、传入外部 IPFS 地址。授权链、内存加载与远程取码均为直接可见的恶意行为，无任何合法软件特征。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **HTA/PowerShell .NET 反射加载器（myfilebase/IPFS 分发）** · 别名 HTA loader、PowerShell downloader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | easy |
| 首次出现 | 2026-11-16 08:02:04 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/27a106bf1227c1dd79791e153912bf90cbd5a0e3ea431f9dd31deca8af6dfab8/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">以隐藏窗口运行 HTA</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">插入垃圾串混淆代码</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">隐藏执行PowerShell</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解密并执行内联脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">三地址随机下载载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `27a106bf1227c1dd79791e153912bf90cbd5a0e3ea431f9dd31deca8af6dfab8` |
| MD5 | _未记录_ |
| 大小 | 22,360 字节（21.8 KB） |
| 类型 | other · `hta` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 以隐藏窗口运行 HTA

`T1564.003` · 置信度 **高** · 静态

HTA:APPLICATION 关闭边框、任务栏按钮、系统菜单并把窗口最小化，脚本执行完毕后调用 window.close 自行退出，使用户看不到界面。

> **证据**：off=57..272 的 <HTA:APPLICATION BORDER=none SHOWINTASKBAR=no SYSMENU=no WINDOWSTATE=minimize>；off=22298 window.close
> 
> **来源**：`ev-000001`

### 2. 插入垃圾串混淆代码

`T1027` · 置信度 **高** · 静态

在 VBScript 的每个字符串片段中插入固定串 aghreeSn，运行时用 Replace 删除后再拼接成完整命令，使静态字符串与命令不可直接读取。

> **证据**：off=386 起 500+ 处 'aghreeSn'；off=21737/22156 Replace(aq2LXNZEl, "aghreeSn", "")
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 隐藏执行PowerShell

`T1059.001` · 置信度 **高** · 静态

通过 CreateObject("WScript.Shell").Run 以窗口样式 0 执行 cmd /c %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe，并附加内联脚本参数，利用 SysNative 从 32 位宿主转到 64 位解释器。

> **证据**：off=674..729 拼接出 ...\SysNative\WindowsPowerShell\v1.0\powershell.exe；off=22156 WScript.Shell；off=22259 shell.Run aq2LXNZEl, 0, False
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 解密并执行内联脚本

`T1140` · 置信度 **高** · 静态

内联 PowerShell 以自定义 64 字符表把密文映射回标准 Base64，解码后再对每字节减去 24 字节密钥并取模，还原 2287 字节脚本，最后以 iex 直接执行，避免落盘。

> **证据**：密文 $vA9Li2、密钥 $sPKZvMb4OI=[byte[]](0xE1,0x34,0x9F,...) 见 off≈1736..19385；解码结果 2287 字节（stage2.ps1）；iex $oUNp54NAe
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 三地址随机下载载荷

`T1105` · 置信度 **高** · 静态

使用 System.Net.WebClient.DownloadData，先以 Get-Random 打乱三个 http 地址的顺序，再逐个尝试下载，失败则换下一个，提高可用性并规避单点封锁。

> **证据**：stage2.ps1: DownloadDataFromLinks + Get-Random；三个 URL 由 _ebrFj 解码为 hxxp://64.224.17[.]115/img/1.jpg、hxxp://129.121.148[.]240/img/pics/1.jpg、hxxp://155.103.71[.]164/1.jpg
> 
> **来源**：`ev-000002`

### 6. 标记截取并反射加载

`T1620` · 置信度 **高** · 静态

在下载返回的文本中定位 <<STT>> 与 <<D>>，截取两者之间内容做 Base64 解码，再用 [Reflection.Assembly]::Load 在内存中加载 .NET 程序集，磁盘上不产生可执行文件。

> **证据**：stage2.ps1: IndexOf('<<STT>>')/IndexOf('<<D>>') + Substring + FromBase64String + [System.Reflection.Assembly]::Load($b5)
> 
> **来源**：`ev-000002`

### 7. 反射调用 runss 入口

`T1620` · 置信度 **高** · 静态

取加载程序集中的类型 myprogram.Homees，反射获得方法 runss，并传入外部 IPFS 地址、"0"、空串、"Msbuild"、"0"、"x86" 六个参数调用，把控制权交给远端模块。

> **证据**：stage2.ps1: GetType('myprogram.Homees'); GetMethod('runss').Invoke($null, [object[]]($b9, '0', '', 'Msbuild', '0', 'x86'))
> 
> **来源**：`ev-000002`

### 8. 延时三秒规避检测

`T1497.003` · 置信度 **高** · 静态

在发起任何网络请求前执行 Start-Sleep -Seconds 3，并强制使用 TLS 1.2，降低在自动化沙箱观察窗口内触发网络行为的概率。

> **证据**：stage2.ps1: [Net.ServicePointManager]::SecurityProtocol = Tls12; Start-Sleep -Seconds 3
> 
> **来源**：`ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://64.224.17[.]115/img/1[.]jpg` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://129.121.148[.]240/img/pics/1[.]jpg` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://155.103.71[.]164/1[.]jpg` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmaJZLLPnnnUHM4sxM7eRj3Qc9eywuopZ5vPe5DCXR1PAr` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `64.224.17[.]115; 129.121.148[.]240; 155.103.71[.]164; misleading-lime-termite[.]myfilebase[.]com` | 是 | 静态 |
| `c2_uri` | `/img/1.jpg; /img/pics/1.jpg; /1.jpg; /ipfs/QmaJZLLPnnnUHM4sxM7eRj3Qc9eywuopZ5vPe5DCXR1PAr` | 是 | 静态 |
| `loader_chain` | `HTA -> VBScript string assembly -> powershell.exe (SysNative) -> iex -> WebClient.DownloadData -> Assembly.Load -> reflection invoke` | 是 | 静态 |
| `assembly_type` | `myprogram.Homees` | 是 | 静态 |
| `assembly_method` | `runss` | 是 | 静态 |
| `payload_markers` | `<<STT>> ... <<D>>` | 是 | 静态 |
| `encoding` | `custom 64-char alphabet substitution + Base64 + per-byte subtract key (24 bytes) ; second layer: 16-char table hex + XOR 0x16` | 是 | 静态 |
| `relay_url` | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmaJZLLPnnnUHM4sxM7eRj3Qc9eywuopZ5vPe5DCXR1PAr` | 否 | 静态 |
| `launch_path` | `%SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe` | 是 | 静态 |
| `initial_delay_seconds` | `3` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得断言最终载荷属于某一具体家族或具备窃密/RAT 功能：承载功能的 .NET 模块由远端下发，本次未取得样本，无法分析。
- 不得声称样本已写入注册表、创建服务或计划任务、建立持久化：静态还原的脚本中不存在任何相关调用。
- 不得声称样本实际使用了 MSBuild 代理执行："Msbuild" 仅作为字符串参数传给远程模块的 runss 方法，未见 msbuild.exe 被创建。
- 不得把三个 IP 地址认定为唯一或最终 C2：它们目前只被证明是载荷分发地址，且未实际访问，回传通道未知。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 纯静态分析，样本未在沙箱中引爆，没有任何动态行为可供确认；所有网络结论均来自脚本还原。
2. 三个下载地址与 IPFS 链接均未访问，无法确认其当前是否存活、返回内容及真实文件哈希。
3. 未取得 .NET 载荷，因此无法确定最终功能（RAT/窃密/勒索等）、配置与真实 C2 回传通道。
4. IPFS 链接在脚本中的字面值为 s:// 开头（缺少 http 前缀），本报告按 https 处理，需以运行时实际拼装结果为准。
5. 无可用的多引擎或家族签名数据，family 仅按载荷链描述并标记为待定。

## 证据索引

<details>
<summary>展开 3 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 字符串抽取：442 条 ASCII 字符串，包含 HTA:APPLICATION 属性、VBScript 拼接片段与 aghreeSn 混淆标记 |
| `ev-000002` | evidence.record | 自写脚本完整还原 HTA 第一级命令与 2287 字节第二级 PowerShell（含三个下载 URL、IPFS 地址、标记与反射调用参数） |
| `ev-000003` | evidence.record | 样本哈希与格式：sha256/md5/sha1、22360 字节、HTA 文本 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
