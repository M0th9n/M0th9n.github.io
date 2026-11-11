---
title: "恶意样本分析：Unclassified ROR13 hash-resolving TCP stager（PE · exe · e6e51ff0）"
published: 2026-11-10
draft: false
description: "恶意（置信度低）：Unclassified ROR13 hash-resolving TCP stager · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unclassified ROR13 hash-resolving TCP stager**（存疑） · 置信度 **低**
> 
> 3.5KB 的 32 位 GUI PE 无任何正常功能导入（仅 KERNEL32!Sleep），启动后通过 PEB 遍历与 ROR13 哈希动态解析 18 个网络/内存/字符串 API，连接硬编码公网地址 134.122.154[.]92:2086，发送 40 字节主机指纹握手，随后分配 30MB RWX 内存、分块接收远端数据并以 XOR 0x99 解密后直接执行。该套行为在真实动态沙箱中被完整观测到外联与握手，属典型无文件下载/加载器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unclassified ROR13 hash-resolving TCP stager** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-07 21:30:14 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/e6e51ff061c04b656f2d4187e34c95331444a9d28ea585ecd9a576550a2dc4c6/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">哈希解析加载 API</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">检查临时标记文件</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">连接硬编码 C2</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">发送主机心跳</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">分配 RWX 内存</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `e6e51ff061c04b656f2d4187e34c95331444a9d28ea585ecd9a576550a2dc4c6` |
| MD5 | _未记录_ |
| 大小 | 3,584 字节（3.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **5** 条静态可得、**2** 条经动态分析取得。

### 1. 哈希解析加载 API

`T1027` · 置信度 **高** · 静态

静态导入表只有 KERNEL32!Sleep；样本通过 fs:[0x30] 读 PEB、沿 InMemoryOrderModuleList 遍历模块，按“模块名 UTF-16 字节 + 导出名（含结尾 NUL）逐个 ROR13 累加”的哈希解析 18 个 API（LoadLibraryA/GetTempPathA/wsprintfA/_access/WSAStartup/WSASocketA/connect/send/recv/VirtualAlloc/MessageBoxA 等），抹除真实导入面。

> **证据**：0x40145F FUN_0040145f 以哈希常量填充函数表；0x401369 FUN_00401369 遍历 PEB 导出表；ROR13 循环位于 0x4013BA-0x4013D6
> 
> **来源**：`ev-000011` · `ev-000010` · `ev-000002`

### 2. 检查临时标记文件

`T1480` · 置信度 **中** · 静态

调用 GetTempPathA 取得 %TEMP%，用 wsprintfA 拼出 %TEMP%\log_de.log，再以 _access(path,0) 检测是否已存在；存在则直接退出，实现单实例/重复运行保护。

> **证据**：0x40102D GetTempPathA；0x40109E _access；指令级仿真得到路径 C:\Users\<user>\AppData\Local\Temp\log_de.log
> 
> **来源**：`ev-000012` · `ev-000009`

### 3. 连接硬编码 C2

`T1095` · 置信度 **高** · 动态

WSAStartup(0x202) 后以 WSASocketA(2,1,6) 建流式套接字，填 sockaddr_in（AF_INET、端口 2086、inet_addr("134.122.154[.]92")），connect 失败则 Sleep(10000) 无限重试。

> **证据**：0x4011E6 WSASocketA；0x401244 connect；沙箱网络侧记录 e6e51ff0...exe(PID 1340) requested TCP 134.122.154[.]92:2086
> 
> **来源**：`ev-000013` · `ev-000012` · `ev-000009`

### 4. 发送主机心跳

`T1041` · 置信度 **高** · 动态

连接建立后立即发送 40 字节固定握手："w32 " + 端口（大端 0x08 0x26）+ 自身目标 IP 字符串 "134.122.154[.]92"，其余补零。

> **证据**：动态网络监控抓到 40 字节载荷 77 33 32 20 20 20 08 26 31 33 34 2E 31 32 32 2E 31 35 34 2E 39 32 00...，与仿真发送序列一致
> 
> **来源**：`ev-000013` · `ev-000012`

### 5. 分配 RWX 内存

`T1620` · 置信度 **高** · 静态

在连接成功后调用 VirtualAlloc(NULL, 0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE)，预留约 30MB 可读可写可执行内存用于接收远端载荷。

> **证据**：0x4012E8 push 0x40 / 0x1000 / 0x1C9C380 / 0；0x4012F5 call VirtualAlloc
> 
> **来源**：`ev-000009` · `ev-000012`

### 6. 分块接收并解密载荷

`T1140` · 置信度 **高** · 静态

循环 recv(socket, buf, 0x64000, 0) 直到返回 0；对每块新到数据逐字节 XOR 0x99 解密，并把写入偏移按块推进。

> **证据**：0x401327 xor byte ptr [esi],0x99；0x401339/0x40133D 分块 recv(0x64000)；0x4012F5 VirtualAlloc 后进入该循环
> 
> **来源**：`ev-000009` · `ev-000012`

### 7. 内存执行远程载荷

`T1620` · 置信度 **高** · 静态

载荷接收/解密完成后 closesocket，并直接 call 跳入刚分配的 RWX 缓冲区执行第二阶段，实现无文件驻留。

> **证据**：0x401358 call closesocket；0x401360 call ebx（ebx=VirtualAlloc 返回的 RWX 缓冲区）
> 
> **来源**：`ev-000009` · `ev-000012`


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
| tcp | `134.122.154[.]92` | 2086 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%TEMP%\log_de.log`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `134.122.154[.]92` | 是 | 静态 |
| `c2_port` | `2086` | 是 | 静态 |
| `c2_protocol` | `raw TCP; 40-byte beacon = "w32 " + 2-byte big-endian port + IP string zero-padded` | 是 | 静态 |
| `marker_path` | `%TEMP%\log_de.log (single-instance check; exits if present)` | 否 | 静态 |
| `encryption_algo` | `XOR 0x99 applied byte-wise to each received stage chunk` | 是 | 静态 |
| `stage2_alloc` | `VirtualAlloc(NULL, 0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE); recv chunk 0x64000` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能定性为窃密木马或勒索软件：未观测到凭据/浏览器数据读取，也未观测到文件加密或勒索行为。
- 不能声称已建立有效 C2 会话或已下载/执行第二阶段：动态沙箱仅见连接建立与样本发出的 40 字节握手，仿真服务器无响应，第二阶段未取回。
- 不能声称存在持久化：系统遥测中 Run 键、服务与计划任务均无与样本相关的变更。
- 不能声称发生进程注入：内存扫描未发现注入、IAT Hook 或可疑内存补丁，样本仅在自身进程内活动。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. C2 仅有连接建立与样本发出的 40 字节握手，网络仿真服务未返回任何内容，未形成请求/响应会话；按规则 C2 记为 static 且 pending_dynamic_verify=true。
2. 未取得第二阶段载荷，无法确认最终家族、驻留与后续能力；VirtualAlloc/XOR 0x99/跳转执行仅由静态代码与指令级仿真确认，未在真机看到 shellcode 实际运行。
3. %TEMP%\log_de.log 单实例检查由指令级仿真恢复，系统遥测未记录该文件访问事件，置信度为中。
4. 无厂商引擎或 YARA 匹配，家族命名保持不确定，需结合第二阶段样本再确认。
5. 系统遥测未发现文件落地、注册表、服务、计划任务等样本相关变更；样本最终能力受限于未下发的第二阶段。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=e6e51ff061c04b656f2d4187e34c95331444a9d28ea585ecd9a576550a2dc4c6, md5=05d233edd2de6095c7831c82c2033476, size=3584 |
| `ev-000002` | scan.imphash | imphash=e82dd51b077167be63c004bed23d0c1e；导入面仅 KERNEL32!Sleep |
| `ev-000007` | 样本分诊 | 加壳可能性 25%（导入符号极少），无结构异常 |
| `ev-000008` | 字符串提取 | ASCII 90 条、无 UTF-16LE、无 flag；仅能见 Sleep/KERNEL32.dll 与代码片段 |
| `ev-000009` | decompile.function | 反编译 0x401005：GetTempPathA/wsprintfA/_access → WSASocketA/connect → 发送 → VirtualAlloc(RWX) → recv+XOR 0x99 → call |
| `ev-000010` | decompile.function | 反编译 0x401369：PEB fs:[0x30] 模块遍历 + 导出名 ROR13 哈希匹配 |
| `ev-000011` | decompile.function | 反编译 0x40145F：以 18 个哈希常量解析 LoadLibraryA/GetTempPathA/wsprintfA/_access/WSAStartup/WSASocketA/connect/send/recv/VirtualAlloc 等 |
| `ev-000012` | evidence.record | 指令级仿真恢复：标记路径 %TEMP%\log_de.log、C2 134.122.154[.]92:2086、40 字节 "w32 "+端口+IP 握手、VirtualAlloc(0x1C9C380,0x40)、recv 0x64000 分块、XOR 0x99 |
| `ev-000013` | evidence.record | 动态沙箱网络日志：PID 1340 请求 TCP 134.122.154[.]92:2086，首发 40 字节 77 33 32 20 20 20 08 26 31 33 34 2E ..., 无服务器响应 |
| `ref:f2e42e397d` | 动态分析平台 | 真实引爆：样本 PID 1340 运行，网络分流记录 C2 外联；内存扫描 0 可疑、无注入；遥测无持久化变更；分析结束回滚 |
| `c2_evidence:e6e51ff0` | 连接证据提取 | 动态网络监控记录到 1 次到 134.122.154[.]92:2086 的连接尝试；未捕获完整会话 |
| `telemetry:e6e51ff0` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 122 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 26 条 |
| `etw:e6e51ff0:1340` | 进程事件监控 | 短命进程事件：e6e51ff061c04b656f2d4187e34c95331444a9d28ea585ecd9a576550a2dc4c6.exe（pid 1340；MD5=05D233EDD2DE6095C7831C82C2033476,SHA256=E6E51FF061C04B656F2D4187E34C95331444A9D28EA585ECD9A576550A2DC4C6,IMPHASH=E82DD51B077167BE63C004BED23D0C1E） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
