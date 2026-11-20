---
title: "恶意样本分析：Meterpreter（PE · exe · d0370cf9）"
published: 2026-11-18
draft: false
description: "恶意（置信度中）：Meterpreter · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Meterpreter", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Meterpreter**（存疑） · 置信度 **中**
> 
> 别名：Metasploit x64 reverse_tcp stager、msfvenom staged loader、MSF shellcode stager
> 
> 这是一个 3.5 KB 的 64 位 PE 暂存器(stager)：入口用 PEB 遍历加双哈希(模块名+导出名, ror13)解析 API，运行时加载 user32/ws2_32/msvcrt，随后建立 TCP 套接字回连 116.62.172[.]147:443，失败则每 10 秒重试；连接成功后发送固定上线标识，再申请 30 MB PAGE_EXECUTE_READWRITE 内存、分块 recv 第二阶段、逐字节 XOR 0x99 后直接 call 执行。静态反编译/反汇编与动态沙箱中的真实 TCP 连接请求相互印证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Meterpreter** · 别名 Metasploit x64 reverse_tcp stager、msfvenom staged loader、MSF shellcode stager · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-17 00:42:27 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/d0370cf97c5960654ba39198d3fe41916d0b6ce03a4b8726d785f402a2985fcd/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">哈希遍历PEB取API</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">运行时装载网络库</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">回连固定IP的443</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">发送40字节上线标识</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">申请30MB可执行内存</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `d0370cf97c5960654ba39198d3fe41916d0b6ce03a4b8726d785f402a2985fcd` |
| MD5 | _未记录_ |
| 大小 | 3,584 字节（3.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **6** 条静态可得、**1** 条经动态分析取得。

### 1. 哈希遍历PEB取API

`T1027` · 置信度 **高** · 静态

通过 gs:[0x60] 取 PEB，沿 Ldr 模块链表遍历导出表，以 ror13 + 大写化 + 模块名/导出名双哈希方式解析 API，导入表只保留 Sleep 一个符号以规避静态检测。

> **证据**：0x14000145c 哈希解析函数；0x14000148d 读取 gs:[0x60]；PE 导入表仅 KERNEL32!Sleep
> 
> **来源**：`ref:af7bb7af10` · `ref:4e956ff90e` · `ref:a32f2d702e`

### 2. 运行时装载网络库

`T1129` · 置信度 **高** · 静态

在内存中动态加载 user32.dll、ws2_32.dll、msvcrt.dll，这些依赖未出现在 PE 导入表中；仿真过程记录到三次 LoadLibraryA 及其参数字符串。

> **证据**：0x140001051 / 0x14000106f / 0x14000108d call rax (LoadLibraryA)；仿真 API 记录参数 user32.dll / ws2_32.dll / msvcrt.dll；内存取证模块列表含 ws2_32、msvcrt、user32
> 
> **来源**：`ref:1321795876` · `ref:5fd7ed4ebf` · `ref:3494585f8b`

### 3. 回连固定IP的443

`T1095` · 置信度 **高** · 动态

调用 WSAStartup(0x202)、WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)，把配置的 116.62.172[.]147 拼接成字符串后 connect 到 TCP 443；连接失败时进入 Sleep(10000) 无限重试。

> **证据**：0x1400012a4 call [rbp-0x30] (WSAStartup, 0x202)；0x140001321 call rsi (connect, sockaddr 0xbb010002=端口443)；0x140001341 call qword ptr [rip+0xce9] (Sleep, 10000)；沙箱网络日志 pid 1828 请求 TCP 116.62.172[.]147:443
> 
> **来源**：`ref:5fd7ed4ebf` · `ref:10307a3555`

### 4. 发送40字节上线标识

`T1095` · 置信度 **高** · 静态

连接建立后连续调用 send 发送 40 字节固定握手：6 字节 "w64 "、2 字节网络序端口、四个 IP 文本分段(116./62.1/72.1/47)以及 16 字节补零，用于向对端标识自身。

> **证据**：0x140001335 起连续 10 次 call rdi (send)，长度依次 6/2/4×8；首包字符串 "w64 " 由 0x1400012d5 附近立即数 0x20343677 构造
> 
> **来源**：`ref:5fd7ed4ebf` · `ref:8b2f9dc2d1`

### 5. 申请30MB可执行内存

`T1620` · 置信度 **高** · 静态

调用 VirtualAlloc(0, 0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE) 申请约 30 MB 可读写可执行内存，作为第二阶段载荷的落地缓冲区。

> **证据**：0x1400013e8 mov edx, 0x1c9c380；0x1400013f9 call qword ptr [rbp-0x20] (VirtualAlloc, r8d=0x1000, r9d=0x40)
> 
> **来源**：`ref:6fdc33e0da`

### 6. 分块拉取第二阶段

`T1105` · 置信度 **高** · 静态

在循环中以 0x64000 为块大小反复 recv 数据并累加写入上述可执行缓冲区，直到对端关闭或出错，实现无文件落地的载荷传输。

> **证据**：0x140001438 call r15 (recv, r8d=0x64000)；0x14000143c 比较返回值并累加到偏移
> 
> **来源**：`ref:6fdc33e0da`

### 7. XOR 0x99后跳转执行

`T1140` · 置信度 **高** · 静态

对收到的每个字节原地执行 XOR 0x99 解码，随后 closesocket 并直接 call 缓冲区首地址，把第二阶段当作代码执行。

> **证据**：0x14000141f xor byte ptr [rcx+rdi], 0x99；0x140001443 call qword ptr [rbp-0x18] (closesocket)；0x140001446 call rdi (执行载荷)
> 
> **来源**：`ref:6fdc33e0da`


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
| tcp | `116[.]62[.]172[.]147:443` | 443 | c2 | 动态 | 已观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `116[.]62[.]172[.]147` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `transport` | `raw TCP reverse_tcp stager (WSAStartup→WSASocket→connect)` | 是 | 静态 |
| `stage_xor_key` | `0x99` | 是 | 静态 |
| `stage_alloc_size` | `0x1C9C380 (30000000)` | 否 | 静态 |
| `handshake_banner` | `w64 (6 字节) + 端口 2 字节 + IP 文本分段 + 补零，共 40 字节` | 否 | 静态 |
| `temp_path_template` | `%TEMP%\log_de.log` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能称其为勒索软件或窃密木马：样本中不存在文件加密、凭据读取、浏览器数据访问代码，沙箱遥测也未出现相关行为。
- 不能断言已成功上线或已下发第二阶段：沙箱只记录到一次到 116.62.172[.]147:443 的 TCP 连接请求，无应用层会话，也未被回传任何 recv 数据。
- 不能宣称已创建 %TEMP%\log_de.log 或任何落地文件：该路径仅由 GetTempPathA 与 sprintf 拼接得出，未观察到文件创建或写入。
- 不能宣称存在持久化：静态代码与动态遥测中均无服务、计划任务或注册表 Run 项操作。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 未获取第二阶段载荷：C2 无应答，最终载荷类型(Meterpreter 或其他)与后续能力无法确认。
2. C2 仅有一次 TCP 连接请求记录，无完整请求/响应，故 c2 仍标记 recoverability=static 且 pending_dynamic_verify=true。
3. 解析出的具体 API 名称由动态仿真的 LoadLibraryA 记录、Winsock 参数形态及 PEB/导出表遍历逻辑推断，未对全部 13 个哈希逐一离线复算。
4. 代码中用 GetTempPathA 拼出的 %TEMP%\log_de.log 未观察到实际写入，用途不明。
5. PE 无数字签名、无版本资源，编译时间戳仅说明构建工具链，不能作为归属依据。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=d0370cf97c5960654ba39198d3fe41916d0b6ce03a4b8726d785f402a2985fcd, md5=dab5e1bbe23c59893df1473c00e7a43f, 3584 字节 |
| `ev-000002` | scan.imphash | imphash=e82dd51b077167be63c004bed23d0c1e |
| `ev-000003` | scan.rich | Rich header 4 条 MSVC 工具链记录, richhash=f74c346ecbd50a4203aa4437d0f039c4 |
| `ev-000008` | 字符串提取 | 70 条 ASCII 字符串, 无 flag 命中; 可见 ws2_/msvcrt/user32 片段与 'w64' 数据 |
| `ev-000009` | decompile.ghidra | entry @0x140001000 反编译: 哈希解析 API, WSAStartup/WSASocket/connect/send, VirtualAlloc(30000000,0x40), recv 后 XOR 0x99 并调用 |
| `call:call_8da1849f40d64f7cb4378b39` | 动态分析平台 | 真实动态: 投放过 2 个进程(pid 1828/2696), 记录时间线与内存取证产物, 已回滚 |
| `call:call_791ceddf6ab7426bbc8bf3f0` | sandbox.log | 网络监控日志第 223 行: d0370...exe (1828) requested TCP 116.62.172[.]147:443 |
| `c2_evidence:d0370cf9` | 连接证据提取 | 动态网络监控记录到 1 次到 116.62.172[.]147:443 的连接尝试；未捕获完整会话 |
| `telemetry:d0370cf9` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 107 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 30 条 |
| `etw:d0370cf9:1828` | 进程事件监控 | 短命进程事件：d0370cf97c5960654ba39198d3fe41916d0b6ce03a4b8726d785f402a2985fcd.exe（pid 1828；MD5=DAB5E1BBE23C59893DF1473C00E7A43F,SHA256=D0370CF97C5960654BA39198D3FE41916D0B6CE03A4B8726D785F402A2985FCD,IMPHASH=E82DD51B077167BE63C004BED23D0C1E） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
