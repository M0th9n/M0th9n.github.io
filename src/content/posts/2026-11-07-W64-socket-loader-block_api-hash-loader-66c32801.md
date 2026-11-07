---
title: "恶意样本分析：W64 socket loader (block_api hash loader)（PE · exe · 66c32801）"
published: 2026-11-07
draft: false
description: "恶意（置信度低）：W64 socket loader (block_api hash loader) · downloader/loader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["W64", "downloader", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **W64 socket loader (block_api hash loader)**（存疑） · 置信度 **低**
> 
> 别名：x64 哈希解析下载器、w64 上线包加载器、XOR-0x99 stage-2 downloader
> 
> 反编译显示入口以 PEB 哈希解析 API，构造硬编码地址 103[.]149[.]93[.]150，建立原始 TCP 连接(端口8084)并发送 w64 上线包，随后接收数据按 0x99 逐字节异或写入 RWX 内存并执行；真实动态沙箱中同一进程确实发起了该 TCP 连接并发出上述上线包（连接超时，未取得第二阶段）。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **W64 socket loader (block_api hash loader)** · 别名 x64 哈希解析下载器、w64 上线包加载器、XOR-0x99 stage-2 downloader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | medium |
| 首次出现 | 2026-11-04 00:56:59 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/66c32801f7888c76b23f54992482c2175a6826f94eb53760d0c633c28f4cb01a/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">哈希遍历解析导入</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">动态加载网络库</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">拼装硬编码C2地址</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">套接字连接8084</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">发送w64上线包</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `66c32801f7888c76b23f54992482c2175a6826f94eb53760d0c633c28f4cb01a` |
| MD5 | _未记录_ |
| 大小 | 3,584 字节（3.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **5** 条静态可得、**2** 条经动态分析取得。

### 1. 哈希遍历解析导入

`T1027` · 置信度 **高** · 静态

入口通过 gs:[0x60] 读取 PEB，遍历模块导出表，用 ror13 风格哈希逐个比对解析 API，导入表仅保留 KERNEL32!Sleep。

> **证据**：0x14000145c 哈希解析函数；0x140001495 mov rax, gs:[0x60]；PE 导入仅 Sleep
> 
> **来源**：`ref:dedc23179a` · `ref:e013029059` · `ref:aaa77a28c6`

### 2. 动态加载网络库

`T1129` · 置信度 **高** · 静态

通过解析出的 LoadLibraryA 依次加载 user32.dll、ws2_32.dll、msvcrt.dll，为后续 winsock 与格式化调用准备导出函数。

> **证据**：0x14000105x 连续 call LoadLibraryA；字符串 'user32.dll'/'ws2_32.dll'/'msvcrt.dll'
> 
> **来源**：`ref:967052c453` · `ref:f4745f772d`

### 3. 拼装硬编码C2地址

`T1095` · 置信度 **高** · 静态

用立即数分段拼出字符串 103.149.93[.]150，并作为连接目标写入 sockaddr_in。

> **证据**：0x1400011cf 起 mov dword '103.'/'149.'/'93.1'/'50'，0x140001257 前 wsprintf 拼接
> 
> **来源**：`ref:7cb2310859` · `ref:f4745f772d`

### 4. 套接字连接8084

`T1095` · 置信度 **高** · 动态

调用 WSAStartup(0x202) 与 socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)，随后 connect 到 103.149.93[.]150:8084；失败时每 10 秒重试。

> **证据**：0x14000129d WSAStartup；0x1400012c9 socket；0x140001321 connect 循环内 Sleep(10000)
> 
> **来源**：`ref:f4745f772d` · `ref:7cb2310859` · `ref:0982a741d1`

### 5. 发送w64上线包

`T1095` · 置信度 **高** · 动态

连接成功后发送 44 字节上线包：'w64 ' + 网络序端口(0x1F94=8084) + '103.149.93[.]150' + 零填充。

> **证据**：动态网络监控 0x77 36 34 20 20 20 1F 94 31 30 33 2E 31 34 39 2E 39 33 2E 31 35 30；代码 0x140001335 起多次 send
> 
> **来源**：`ref:0982a741d1` · `ref:7cb2310859`

### 6. XOR 0x99解密载荷

`T1140` · 置信度 **高** · 静态

循环 recv 最多 0x64000 字节的分块，对每个字节异或 0x99 后累积到已分配缓冲区，直到对端关闭。

> **证据**：0x14000141f xor byte ptr [rcx+rdi], 0x99；0x140001438 call recv
> 
> **来源**：`ref:7cb2310859` · `ref:f4745f772d`

### 7. 分配RWX执行载荷

`T1620` · 置信度 **高** · 静态

以 PAGE_EXECUTE_READWRITE 申请约 30 MB 可执行内存，解密完成后 closesocket 并直接 call 该缓冲区，在自身进程内执行第二阶段。

> **证据**：0x1400013f9 VirtualAlloc(0,0x1c9c380,0x1000,0x40)；0x140001446 call rdi
> 
> **来源**：`ref:7cb2310859` · `ref:f4745f772d`


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
| tcp | `103[.]149[.]93[.]150` | 8084 | c2 | 动态 | 已观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `103[.]149[.]93[.]150` | 是 | 动态 |
| `c2_port` | `8084` | 是 | 动态 |
| `encryption_algo` | `单字节 XOR 0x99（对 recv 收到的第二阶段数据逐字节处理）` | 是 | 静态 |
| `beacon_prefix` | `w64 （后接网络序端口与本机/目标 IP 字符串及零填充，共44字节）` | 是 | 动态 |
| `stage2_exec` | `VirtualAlloc(NULL, 30000000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)；recv 分块(<=409600)接收后就地解密并在进程内直接执行` | 是 | 静态 |
| `build_string_candidate` | `log_de.log` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不应判定为勒索软件或窃密程序：未发现文件加密、凭据读取、浏览器数据收集等行为。
- 不应声称已获取第二阶段载荷或完整指令集：真实动态中 C2 连接超时，未收到任何响应数据。
- 不应把内存字符串 'log_de.log' 直接当作已确认 C2 域名：动态中未观测到对该名称的域名解析，其用途未定。
- 内存取证未发现注入或模块替换只说明本次运行如此，不能据此认定样本整体无害。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. C2 103[.]149[.]93[.]150:8084 在动态沙箱中未响应，连接超时；未取得第二阶段载荷，其最终能力、持久化与横向行为无法确认。
2. 样本内构造的 'log_de.log' 字符串用途未定：动态中未观测到对该名称的域名解析，不能确认其为备用 C2。
3. 内存取证扫描未发现注入或模块替换，但仅基于未收到第二阶段的单次运行，不能外推到后续阶段。
4. 无可用的代码签名或 PDB 路径信息，家族归属缺少外部引擎/YARA/公开报告佐证，family 为候选标注。
5. 隔离环境未放行真实外联，网络结论来自伪造网络服务的被动记录。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 3584 |
| `ev-000002` | scan.imphash | imphash=e82dd51b077167be63c004bed23d0c1e |
| `ev-000003` | scan.rich | Rich header 4 条工具链记录，richhash=f74c346ecbd50a4203aa4437d0f039c4 |
| `ev-000007` | 样本分诊 | 3 个节区、0 异常、导入仅 1 个符号(Sleep) |
| `ev-000008` | 字符串提取 | user32/ws2_32/msvcrt、'w64 '、'%s%s' 等字符串 |
| `ev-000009` | decompile.ghidra | 入口反编译：解析 API、连接 C2、recv+XOR 0x99、RWX 执行 |
| `ev-000010` | evidence.record | 动态产物解析：TCP 103.149.93[.]150:8084、44 字节 w64 上线包、连接超时、内存字符串 |
| `c2_evidence:66c32801` | 连接证据提取 | 动态网络监控记录到 2 次到 103.149.93[.]150:8084, maps[.]windows[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
