---
title: "恶意样本分析：Metasploit Meterpreter stager (x64 reverse_tcp)（PE · exe · be9c4db2）"
published: 2026-11-03
draft: false
description: "恶意（置信度中）：Metasploit Meterpreter stager (x64 reverse_tcp) · loader/downloader · 难度 easy · 动态沙箱 + 静态反编译"
tags: ["Metasploit Meterpreter", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Metasploit Meterpreter stager (x64 reverse_tcp)**（存疑） · 置信度 **中**
> 
> 别名：Meterpreter、MSF block_api stager、reverse_tcp stager
> 
> 样本在隔离 Windows 沙箱中真实启动（PID 116），并于启动后主动向 103.30.76[.]206:443 发起 TCP 回连；代码自身实现按哈希动态解析 API、套接字回连、RWX 大内存申请、分块接收并 XOR 0x99 解密后直接执行，属于典型的内存加载型远程控制 stager。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Metasploit Meterpreter stager (x64 reverse_tcp)** · 别名 Meterpreter、MSF block_api stager、reverse_tcp stager · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader · downloader |
| 难度 | easy |
| 首次出现 | 2026-11-02 04:28:31 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">哈希遍历解析API</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">装载网络运行库</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">连接C2端口443</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">发送w64回调握手</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">申请30MB可执行内存</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583` |
| MD5 | _未记录_ |
| 大小 | 3,584 字节（3.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **6** 条静态可得、**1** 条经动态分析取得。

### 1. 哈希遍历解析API

`T1027` · 置信度 **高** · 静态

通过 gs:[0x60] 读取 PEB，遍历 InLoadOrderModuleList 与导出表，按 ror13+大写字符累加哈希匹配 API；静态导入表仅保留 Sleep 以降低可见性。

> **证据**：0x14000145C mov rax,gs:[0x60]；0x1400014D1 ror edx,0xD；0x14000151A cmp eax(hash_func+hash_dll),ebp
> 
> **来源**：`ref:a5c96862db` · `ref:849fd6ce07`

### 2. 装载网络运行库

`T1129` · 置信度 **高** · 静态

调用动态解析得到的 LoadLibraryA，依次加载 user32.dll、ws2_32.dll、msvcrt.dll。

> **证据**：0x140001024 解析哈希 0x0726774C(LoadLibraryA)；0x140001030/0x140001054/0x140001078 写入 dll 名并 call rbx
> 
> **来源**：`ref:b334c5b268` · `ref:bead9d643b`

### 3. 连接C2端口443

`T1095` · 置信度 **高** · 动态

组装 sockaddr_in(AF_INET、端口字节 0x01BB、目标 103.30.76[.]206)并调用 connect；失败时 Sleep(10000) 循环重试。沙箱内真实观测到该进程发起 103.30.76[.]206:443 的 TCP 连接。

> **证据**：0x1400012DC mov dword [rbp-0x40],0xBB010002；0x14000130C Sleep(10000)；0x140001321 call connect；沙箱事件 pid 116 requested TCP 103.30.76[.]206:443
> 
> **来源**：`ref:bead9d643b` · `ref:64b18ae47f` · `ref:2a5f67c413`

### 4. 发送w64回调握手

`T1571` · 置信度 **中** · 静态

连接成功后先 send 6 字节 "w64 "，再 send 2 字节网络序端口 0x01BB(443)、4 字节 IP 片段("103."/"30.7"/"6.20"/"6")以及 4 个 4 字节保留字段。

> **证据**：0x140001327 lea r8d,[rax+6]；0x140001332 lea rdx,[rbp-0x80]("w64 ")；0x140001337 call send；随后连续 send 6/2/4/4/4/4/4/4 字节
> 
> **来源**：`ref:bead9d643b` · `ev-000009`

### 5. 申请30MB可执行内存

`T1620` · 置信度 **高** · 静态

调用 VirtualAlloc(0, 30000000, 0x1000, 0x40) 预留约 28.6MB 的 PAGE_EXECUTE_READWRITE 缓冲区，用于承载二阶段。

> **证据**：0x1400013DB mov edx,0x01C9C380；0x1400013ED call [rbp-0x20](VirtualAlloc)，r8=0x1000、r9=0x40
> 
> **来源**：`ref:bead9d643b` · `ev-000009`

### 6. 接收异或解密载荷

`T1140` · 置信度 **高** · 静态

循环 recv(sock, buf, 0x64000) 接收数据，对每个字节与 0x99 异或后写入 RWX 缓冲区并累计长度，直到 recv 不再返回正数。

> **证据**：0x140001438 call recv(0x64000)；0x14000141F xor byte ptr [rcx+rdi],0x99；0x140001441 add esi,eax
> 
> **来源**：`ref:bead9d643b` · `ev-000009`

### 7. 关闭套接字执行载荷

`T1620` · 置信度 **高** · 静态

接收结束后关闭套接字，直接 call 进入已解密的 RWX 区域执行二阶段，不在磁盘落地。

> **证据**：0x140001443 call [rbp-0x18](closesocket)；0x140001446 call rdi(RWX 基址)
> 
> **来源**：`ref:bead9d643b` · `ev-000009`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `103.30.76[.]206:443` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `103.30.76[.]206` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `protocol` | `原始 TCP；先发送 6 字节 'w64 ' 头，再发 2 字节网络序端口与 4 字节 IP 片段及 4 个 4 字节保留字段` | 是 | 静态 |
| `encryption_algo` | `XOR 0x99（对接收到的二阶段逐字节异或）` | 是 | 静态 |
| `stage_alloc_size` | `30000000 字节 RWX（VirtualAlloc MEM_COMMIT/PAGE_EXECUTE_READWRITE）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭 30MB RWX 内存断言样本已注入其他进程：未观测到跨进程写入、线程劫持或 hollowing 行为。
- 未收到二阶段载荷，不能断言其为信息窃取、勒索、挖矿或横向移动等最终功能。
- 未观测到服务/计划任务/注册表 Run 或落地文件，不能判定其具备持久化能力。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 二阶段载荷未获取（C2 未返回数据），最终能力、完整配置与家族细节无法确认。
2. 回连尝试已由网络监控记录（requested TCP），但未获得会话/响应内容；握手后的原始 TCP 负载未做应用层解析，载荷内容未知。
3. msvcrt 辅助调用（构建 "log_de.log" 字符串、0x80 缓冲区初始化）的具体语义未最终确认，未作为结论。
4. 以仿真方式运行样本时未在时限内返回结果，最终结论仅采用真实沙箱观测与静态证据。
5. 未观测持久化、文件释放或进程注入行为；相关能力不作推断。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 |
| `ref:6349dd7802` | 样本分诊 | 3 段区、熵正常、导入仅 1 个 Sleep、无结构异常 |
| `ref:849fd6ce07` | 导入表解析 | 仅 KERNEL32.dll!Sleep，imphash e82dd51b077167be63c004bed23d0c1e |
| `ev-000008` | 字符串提取 | 无明文 C2/URL；仅 dll 名片段与格式串片段 |
| `ref:bead9d643b` | disasm.function | entry 全量反汇编：哈希解析、WSA/连接、RWX 申请、recv+XOR 0x99、执行 |
| `ref:b334c5b268` | decompile.function | entry C 伪代码：加载 3 个 DLL、组装 C2、下载并执行 |
| `ref:a5c96862db` | disasm.function | 0x145C 解析器：PEB 遍历 + ror13 哈希比对 |
| `ref:64b18ae47f` | 动态分析平台 | 真实沙箱引爆：PID 116 进程诞生，产生内存转储与网络观测，结束回滚 |
| `ref:2a5f67c413` | bash | 网络监控日志：be9c…exe (116) requested TCP 103.30.76[.]206:443 |
| `ev-000009` | decompile.ghidra | Ghidra 伪代码与字符串常量 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
