---
title: "恶意样本分析：MSF block_api-style shellcode stager（PE · exe · 89da6d13）"
published: 2026-10-30
draft: false
description: "恶意（置信度低）：MSF block_api-style shellcode stager · downloader/loader · 难度 easy · 动态沙箱 + 静态反编译"
tags: ["MSF", "downloader", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **MSF block_api-style shellcode stager**（存疑） · 置信度 **低**
> 
> 别名：Metasploit-style reverse TCP stager、ROR13 hash-resolving shellcode loader
> 
> 静态还原出完整的下载-执行 stager：遍历 PEB 并以 ROR13 哈希解析 API，连接硬编码的 176[.]97[.]117[.]157:80，发送 40 字节注册报文，把 recv 收到的第二阶段逐字节 XOR 0x99 后写入 30MB RWX 内存并直接调用。真实沙箱中该进程确实向 176[.]97[.]117[.]157:80 发起了 TCP 连接，随后进程退出。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **MSF block_api-style shellcode stager** · 别名 Metasploit-style reverse TCP stager、ROR13 hash-resolving shellcode loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | easy |
| 首次出现 | 2026-10-28 19:32:19 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/89da6d134da1f71ca1ebba3eca2d429034a011fb74dcd45b287c06b71bb11b9f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">哈希解析导入API</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">动态加载三个DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">构造临时目录标记</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1083</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">连接硬编码C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">发送w64注册报文</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `89da6d134da1f71ca1ebba3eca2d429034a011fb74dcd45b287c06b71bb11b9f` |
| MD5 | _未记录_ |
| 大小 | 3,584 字节（3.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **8** 条静态可得、**1** 条经动态分析取得。

### 1. 哈希解析导入API

`T1027` · 置信度 **高** · 静态

不依赖导入表，从 PEB 的 InLoadOrderModuleList 遍历已加载模块，对模块名（UTF-16LE 含结尾 NUL）与导出名（ASCII 含结尾 NUL）分别做 ROR13 累加哈希并求和比对，命中即返回函数地址。

> **证据**：FUN_14000145c (rva 0x145c): mov rax, gs:[0x60] → [rax+0x18] → [rdx+0x10]；循环内 ror edx,0xd / cmp byte,0x61 / add edx,-0x20
> 
> **来源**：`ref:11370cb44f` · `ref:8b3e2c9450` · `ref:3610939526`

### 2. 动态加载三个DLL

`T1129` · 置信度 **高** · 静态

通过解析出的 LoadLibraryA 依次加载 user32.dll、ws2_32.dll、msvcrt.dll，为后续网络与字符串操作准备模块。

> **证据**：rva 0x104f/0x106d/0x108b call rbx (LoadLibraryA)，栈上常量 'user32.dll'/'ws2_32.dll'/'msvcrt.dll'；仿真亦记录三次 kernel32.LoadLibraryA
> 
> **来源**：`ref:ca5b5accd7` · `ref:11327c8a79` · `ref:087b9aee80`

### 3. 构造临时目录标记

`T1083` · 置信度 **高** · 静态

调用 GetTempPathA 取得 %TEMP%，再用 sprintf("%s%s%s") 拼接出 %TEMP%\log_de.log，并以 _access(path,0) 做存在性检查；文件不存在才继续联网，存在则直接退出。

> **证据**：rva 0x1133 call GetTempPathA(0x80, buf)；rva 0x117f sprintf；rva 0x1188 call _access；内存取证可见 C:\Users\analyst\AppData\Local\Temp\log_de.log
> 
> **来源**：`ref:ca5b5accd7` · `ref:3610939526` · `ref:d35ab028b8`

### 4. 连接硬编码C2

`T1095` · 置信度 **高** · 动态

WSAStartup(0x202) 后创建 AF_INET/SOCK_STREAM/TCP 套接字，解析并连接 176[.]97[.]117[.]157:80；连接失败时 Sleep(10000) 无限重试。

> **证据**：常量 0x006B8029=WSAStartup、0xE0DF0FEA=WSASocketA、0x6174A599=connect；sockaddr_in=0x50000002(AF_INET,port 80)；rva 0x1321 call connect；rva 0x130c Sleep(0x2710) 重试
> 
> **来源**：`ref:ca5b5accd7` · `ref:2cb8f5b269` · `ref:d35ab028b8` · `ref:3610939526`

### 5. 发送w64注册报文

`T1095` · 置信度 **高** · 静态

连接建立后连续 send 固定 40 字节：'w64 ' 6 字节 + 网络序端口 0x0050 2 字节 + '176.97.117[.]157' 16 字节 + 16 字节 0，作为注册/心跳头。

> **证据**：rva 0x1335/0x139e/0x13c4/0x13ea/0x1410/0x1436/0x1482/0x14a8/0x14ce 连续 call send；栈常量 'w64 ' 与 '176.'+'97.1'+'17.1'+'57'
> 
> **来源**：`ref:2cb8f5b269` · `ref:3610939526` · `ref:d35ab028b8`

### 6. 分配30MB RWX内存

`T1620` · 置信度 **高** · 静态

VirtualAlloc(0, 0x1C9C380, MEM_COMMIT|MEM_RESERVE(0x1000), PAGE_EXECUTE_READWRITE(0x40)) 申请约 30MB 可读可写可执行内存作为第二阶段落地区。

> **证据**：rva 0x14f9 call qword ptr [rbp-0x20]；立即数 edx=0x1C9C380, r8d=0x1000, r9d=0x3c+4=0x40
> 
> **来源**：`ref:2cb8f5b269` · `ref:ca5b5accd7` · `ref:3610939526`

### 7. 循环接收第二阶段

`T1105` · 置信度 **高** · 静态

在 RWX 缓冲区上循环 recv(sock, buf+offset, 0x64000, 0)，直到 recv 返回 <=0（服务端关闭连接）为止，实现无长度前缀的流式下载。

> **证据**：rva 0x1438 call r15 (recv)；r12d=0x64000；循环 cmp eax,r14d / jge
> 
> **来源**：`ref:2cb8f5b269` · `ref:ca5b5accd7`

### 8. XOR0x99解密阶段

`T1140` · 置信度 **高** · 静态

对每次 recv 收到的字节就地逐字节 XOR 0x99，得到明文第二阶段；密钥为单字节硬编码。

> **证据**：rva 0x141f: 80 34 39 99 → xor byte ptr [rcx+rdi], 0x99
> 
> **来源**：`ref:2cb8f5b269` · `ref:3610939526`

### 9. 内存执行第二阶段

`T1620` · 置信度 **高** · 静态

closesocket 后直接 call 解密后的缓冲区首地址，在自身进程内执行下载的第二阶段（无落地文件）。

> **证据**：rva 0x1523 call closesocket；rva 0x152e call rdi（rdi = VirtualAlloc 返回地址）
> 
> **来源**：`ref:2cb8f5b269` · `ref:ca5b5accd7`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `176[.]97[.]117[.]157` | 80 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%TEMP%\log_de.log`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `176[.]97[.]117[.]157` | 是 | 动态 |
| `c2_port` | `80` | 是 | 动态 |
| `transport` | `raw TCP (WSASocketA/connect/send/recv)` | 是 | 静态 |
| `handshake_magic` | `w64` | 是 | 静态 |
| `handshake_layout` | `6 字节 magic + 2 字节网络序端口 + 16 字节 IP 字符串 + 16 字节保留(0)` | 是 | 静态 |
| `stage_xor_key` | `0x99` | 是 | 静态 |
| `stage_recv_chunk` | `0x64000 (409600)` | 否 | 静态 |
| `rwx_alloc_size` | `0x1C9C380 (30000000)` | 否 | 静态 |
| `marker_path` | `%TEMP%\log_de.log` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不应判为勒索/窃密：样本没有文件加密、凭据或浏览器数据读取、持久化写入等行为，只是下载并执行后续 payload 的 stager。
- 不应把家族直接定为 Meterpreter 或某个具体 RAT：只能确认其使用 Metasploit block_api 风格的哈希解析与 stager 结构，40 字节 'w64' 报文、%TEMP%\log_de.log 标记均非 stock Meterpreter 行为。
- 不应断言第二阶段的功能（远控/窃密/挖矿等）：沙箱未取得有效第二阶段内容，最终能力未知。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 第二阶段 payload 未被成功取回（动态沙箱未提供有效 stage），其最终能力未知；家族仅按代码谱系给出候选并标记 uncertain。
2. API 名称与常量字符串的映射由自写脚本复现样本哈希算法得出，并与运行期内存中的解析结果互相印证，属推导性证据。
3. %TEMP%\log_de.log 只做存在性检查，未观察到创建/写入，无法确认其单实例或持久化语义。
4. 动态仅观测到一次 TCP 连接与发送，未观测到第二阶段下载完成与执行成功。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1/imphash，文件 3584 字节 |
| `ev-000007` | 样本分诊 | 3 个节区、熵正常、仅 1 个导入符号、无结构异常、加壳评分 0.25 |
| `ev-000008` | 字符串提取 | 70 条 ASCII 字符串，无明文 C2/flag；可见 DLL 名片段 |
| `ev-000009` | decompile.function | 主函数 FUN_140001008 伪代码：加载 DLL、GetTempPathA、_access、WSAStartup/WSASocketA/connect/send、VirtualAlloc、recv+XOR、执行 |
| `ev-000010` | decompile.function | 解析器 FUN_14000145c：PEB 遍历 + ROR13 哈希比对导出表 |
| `ev-000011` | evidence.record | 脚本复现哈希算法，13 个常量全部命中 API 名；重建 'w64 '/176.97.117[.]157:80/XOR 0x99/%TEMP%\log_de.log |
| `ref:2cb8f5b269` | disasm.function | rva 0x1301-0x152e 调用点：connect、9 次 send、VirtualAlloc、recv、xor 0x99、closesocket、call 阶段 |
| `ref:11327c8a79` | dyn.run | 仿真记录 3 次 kernel32.LoadLibraryA(user32/ws2_32/msvcrt) |
| `ref:d35ab028b8` | 动态分析平台 | 真实沙箱：进程发起 TCP 176.97.117[.]157:80；加载 user32/ws2_32/msvcrt；进程随后退出；内存取证可见 'w64 '、'176.97.117[.]157'、%TEMP%\log_de.log |
| `c2_evidence:89da6d13` | 连接证据提取 | 动态网络监控记录到 1 次到 176.97.117[.]157:80 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
