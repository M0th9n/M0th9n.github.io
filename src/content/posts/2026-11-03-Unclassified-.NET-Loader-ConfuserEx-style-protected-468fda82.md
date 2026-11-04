---
title: "恶意样本分析：Unclassified .NET Loader (ConfuserEx-style protected)（PE · exe · 468fda82）"
published: 2026-11-03
draft: false
description: "恶意（置信度低）：Unclassified .NET Loader (ConfuserEx-style protected) · loader/backdoor · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["loader", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unclassified .NET Loader (ConfuserEx-style protected)**（存疑） · 置信度 **低**
> 
> 隔离 Windows 10 环境中真实运行后，进程持续以 HTTP GET /ping 访问固定 IP:端口 185[.]91[.]69[.]99:8898，并在约 2 分钟内多次重连；同时样本为仅含 IL 的 .NET 程序，内置多个加密资源并具备反射加载/动态 API 解析能力，属于典型的内存加载器/后门通道行为。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unclassified .NET Loader (ConfuserEx-style protected)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · backdoor |
| 难度 | hard |
| 首次出现 | 2026-11-01 11:37:11 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/468fda829a6e1a7bb3789a31509e272e823e4ef20b4b81311ef2a81393441ef5/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">轮询C2心跳接口</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">延迟三十秒外联</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.003</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">解密内置加密资源</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">反射加载后续载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">动态解析系统API</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `468fda829a6e1a7bb3789a31509e272e823e4ef20b4b81311ef2a81393441ef5` |
| MD5 | _未记录_ |
| 大小 | 831,488 字节（812.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **6** 条行为，每条都挂了证据；其中 **4** 条静态可得、**2** 条经动态分析取得。

### 1. 轮询C2心跳接口

`T1071.001` · 置信度 **高** · 动态

进程启动约 30 秒后，以 HTTP GET /ping 向 185[.]91[.]69[.]99:8898 发起请求（Connection: Keep-Alive），约每 5 秒重试，之后约 2 分钟再次重连。

> **证据**：内存取证 0x7F4CB4: 'GET /ping HTTP/1.1 Host: 185.91.69[.]99:8898 Connection: Keep-Alive'; 网络监控 PID 7500 -> TCP 185.91.69[.]99:8898 于 08:55:25/30/35、08:57:40/45
> 
> **来源**：`ref:bf28020ec5` · `ref:a2e7a697a8` · `ref:0bd1c512c9`

### 2. 延迟三十秒外联

`T1497.003` · 置信度 **中** · 动态

进程创建后约 30 秒才进行首次外联，缩短沙箱观测窗口内的可见行为。

> **证据**：进程创建 20:54:55，首次 TCP 连接 20:55:25；PE 时间线与网络日志时间戳一致
> 
> **来源**：`ref:0bd1c512c9` · `ref:8c68cd1fe1`

### 3. 解密内置加密资源

`T1027.013` · 置信度 **高** · 静态

内置 4 个托管资源，运行时经 AES/Rijndael、TripleDES、GZip/Deflate 解密解压；最大资源 483,380 字节。

> **证据**：PE 资源目录 RVA 0x52F14 起连续 4 个资源；#Strings 含 AesCryptoServiceProvider / RijndaelManaged / TripleDES / GZipStream / DeflateStream
> 
> **来源**：`ref:855a31ca28` · `ref:d4e270a0ce`

### 4. 反射加载后续载荷

`T1620` · 置信度 **中** · 静态

通过 Assembly.Load / GetManifestResourceStream / GetEntryPoint 等反射接口从内存流加载并执行后续载荷。

> **证据**：TypeRef/MemberRef 含 Assembly.Load、GetManifestResourceStream、GetEntryPoint、CreateDecryptor、CryptoStream、DeflateStream
> 
> **来源**：`ref:d4e270a0ce` · `ref:93db342174`

### 5. 动态解析系统API

`T1106` · 置信度 **高** · 静态

静态导入仅 LoadLibrary/GetProcAddress（kernel32），其余敏感 API 按名动态解析；元数据保留 VirtualAlloc/WriteProcessMemory/VirtualProtect/OpenProcess 的参数名。

> **证据**：ImplMap 2 行，ModuleRef=kernel32；#Strings off 0x49DB0 起 lpAddress/flAllocationType/flProtect/hProcess/lpBaseAddress/flNewProtect/dwDesiredAccess/bInheritHandle/dwProcessId
> 
> **来源**：`ref:93db342174` · `ref:d4e270a0ce`

### 6. 混淆IL控制流

`T1027` · 置信度 **高** · 静态

方法体被改写为 switch/常量分派的控制流并随机化符号名，同时设置 SuppressIldasmAttribute，增加静态分析成本。

> **证据**：入口方法 RVA 0x21C4 的 IL 含 switch [109,68,439] 与 beq 990/989 分派；391 个类型、2192 个方法名均为随机串
> 
> **来源**：`ref:81597e7896` · `ref:855a31ca28`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控仿真服务完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://185[.]91[.]69[.]99:8898/ping` | 8898 | c2 | 动态 | 已观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `185[.]91[.]69[.]99:8898` | 是 | 动态 |
| `c2_path` | `/ping` | 是 | 动态 |
| `http_method` | `GET` | 否 | 动态 |
| `embedded_resources` | `4 encrypted managed resources (10887 / 2336 / 483380 / 454 bytes)` | 是 | 静态 |
| `encryption_algo` | `AES/Rijndael + TripleDES + GZip/Deflate (resource decryption)` | 否 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 未观察到文件加密、批量删除或勒索提示，不能判定为 ransomware/wiper。
- 未观察到浏览器凭据、钱包、剪贴板或键盘记录行为，不能判定为 stealer。
- 第二阶段 483,380 字节加密资源未解密，未匹配到家族特征串，不能断言属于某一已知 RAT/加载器家族。
- 进程/模块扫描未发现进程注入或进程镂空迹象，不能断言存在跨进程注入。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 第二阶段（483,380 字节加密资源）未能成功解密，最终载荷类型与家族无法确认。
2. 网络监控仅记录到请求，未取得服务端响应，下载/指令执行链未观测。
3. 未采集到注册表、文件或服务持久化证据，持久化能力未知。
4. 家族判定仅基于自身静态特征与动态行为，置信度低，需后续样本关联确认。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:ff430bb56a` | 样本分诊 | 哈希、节熵 7.421、无导入、加壳可能性 60% |
| `ref:855a31ca28` | PE 结构解析 | AMD64 .NET IL-only，2 节，CLI 头与资源目录 RVA 0x52F14/0x795B1 |
| `ref:d4e270a0ce` | 字符串提取 | 抽取 2770 条 ASCII/61 条 UTF-16 字符串，含 AES/Rijndael/TripleDES/GZip/Deflate/Assembly/反射与 WinAPI 参数名 |
| `ref:0bd1c512c9` | 动态分析平台 | 真实动态引爆：PID 7500，时间线/网络/内存转储打包，进程回滚 |
| `ref:bf28020ec5` | script (dump string extraction) | 在进程内存 0x7F4CB4 提取到完整 HTTP 请求 GET /ping Host: 185.91.69[.]99:8898 |
| `ref:a2e7a697a8` | script (network log extraction) | 网络日志显示样本进程于 08:55:25/30/35、08:57:40/45 请求 TCP 185.91.69[.]99:8898 |
| `ref:8c68cd1fe1` | script (timeline extraction) | 引爆时间线：20:54:55 创建，20:55:25 首次外联，20:57:52 收口 |
| `ref:93db342174` | script (metadata parsing) | ImplMap 仅 2 行、ModuleRef=kernel32（LoadLibrary/GetProcAddress） |
| `ref:81597e7896` | script (IL disassembly) | 入口方法 RVA 0x21C4 IL 为 switch/常量分派控制流 |
| `ref:adfa51a589` | script (memory context) | 配置区上下文含 deflate/Connection/Keep-Alive 与 HTTP 请求串 |
| `ref:c4a346ef2c` | script (PE carve) | 内存转储仅含 1 个 BSJB 元数据头，未发现第二个 .NET 程序集 |
| `c2_evidence:468fda82` | 连接证据提取 | 动态网络监控记录到 5 次到 185.91.69[.]99:8898 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
