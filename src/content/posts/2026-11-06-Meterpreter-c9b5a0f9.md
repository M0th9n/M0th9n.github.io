---
title: "恶意样本分析：Meterpreter（PE · exe · c9b5a0f9）"
published: 2026-11-06
draft: false
description: "恶意（置信度高）：Meterpreter · loader/rat · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Meterpreter", "loader", "rat", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Meterpreter** · 置信度 **高**
> 
> 别名：Metasploit Meterpreter、msfvenom meterpreter/reverse_http (x64)、Meterpreter reverse_http stager
> 
> 静态: .data 内置 893 字节 4 字节循环 XOR 加密载荷, 解密后为 Metasploit x64 meterpreter reverse_http stager(PEB 遍历 + ROR13 解析 wininet, 硬编码 192.168.28[.]128:6666, URI /qRh2, 伪造 MSIE 10.0 UA)。动态: 沙箱内样本进程自建命名管道 \\.\pipe\MSSE-2265-server, 内存中出现解密后的明文 stager, 并向 192.168.28[.]128:6666 发起 GET /qRh2(UA 与内置串一致), 进程常驻休眠。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Meterpreter** · 别名 Metasploit Meterpreter、msfvenom meterpreter/reverse_http (x64)、Meterpreter reverse_http stager |
| 置信度 | **高** |
| 行为类 | loader · rat |
| 难度 | medium |
| 首次出现 | 2026-11-05 15:19:41 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/c9b5a0f9a56bf6b79b11550ddc560f1c0b863e86653afed1d11746e27e4fc910/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">自建管道暂存载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">四字节异或解密</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">内存分配并执行</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解析PEB取API</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">伪装UA外联C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `c9b5a0f9a56bf6b79b11550ddc560f1c0b863e86653afed1d11746e27e4fc910` |
| MD5 | _未记录_ |
| 大小 | 19,456 字节（19.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **5** 条静态可得、**2** 条经动态分析取得。

### 1. 自建管道暂存载荷

`T1105` · 置信度 **高** · 静态

主线程用 GetTickCount%0x26aa 拼出 \\.\pipe\MSSE-<n>-server, 起线程作管道服务端把 .data 内置加密 blob 写入, 同时本进程作为客户端连回同一管道读走, 完成内存暂存回环。

> **证据**：0x4017F8 sprintf("%c%c%c%c%c%c%c%c%cMSSE-%d-server") + CreateThread(0x4016E6); 0x401630 CreateNamedPipeA/ConnectNamedPipe/WriteFile; 0x401704 CreateFileA/ReadFile
> 
> **来源**：`ref:401346c7f0` · `ref:febc5328cc` · `ref:0d5b914056` · `ref:3dd292ebf8`

### 2. 四字节异或解密

`T1140` · 置信度 **高** · 静态

对读回的 893 字节 blob 以 4 字节循环密钥 8B F5 0E 80 逐字节 XOR, 还原出明文 x64 shellcode。

> **证据**：0x401595 内 rep 逻辑: dst[i] = src[i] ^ key[i & 3]; 结构 .data+0x0=0x2630, +0x4=0x37D(893), +0x8 密钥, +0x14 密文
> 
> **来源**：`ref:62bc6e7ffe` · `ref:6d4917704d` · `ref:50f5888ce8`

### 3. 内存分配并执行

`T1620` · 置信度 **高** · 静态

VirtualAlloc(PAGE_READWRITE) 申请与载荷等长的内存, 复制解密结果, VirtualProtect 改为 PAGE_EXECUTE_READ(0x20), 再 CreateThread 直接执行, 全程不落盘。

> **证据**：0x401595: VirtualAlloc(...,0x3000,4) → memcpy 循环 → VirtualProtect(...,0x20) → CreateThread(0x401560); 运行时内存 dump 中出现 fc4883e4f0e8c8000000 明文 stage
> 
> **来源**：`ref:62bc6e7ffe` · `ref:50f5888ce8`

### 4. 解析PEB取API

`T1027` · 置信度 **高** · 静态

shellcode 从 gs:[0x60] 走 PEB→Ldr→InLoadOrderModuleList 定位模块, 用 ROR13 哈希匹配并 GetProcAddress 风格解析 LoadLibraryA/InternetOpenA 等, 网络 API 无静态导入。

> **证据**：stage 偏移 0x00-0xC4: mov rdx,gs:[rdx+0x60] 遍历 Ldr; 哈希 0x0726774C LoadLibraryA、0xA779563A InternetOpenA
> 
> **来源**：`ref:b802be11db` · `ref:6d4917704d`

### 5. 伪装UA外联C2

`T1071.001` · 置信度 **高** · 动态

以 Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0) 作 UA, 向 hxxp://192[.]168[.]28[.]128:6666/qRh2 发 GET 请求, Connection: Keep-Alive、Cache-Control: no-cache。

> **证据**：动态网络日志: 样本 PID 6224 requested TCP 192.168.28[.]128:6666, HTTPListener 记录 GET /qRh2 HTTP/1.1 + Host/UA; 静态 InternetConnectA 端口参数 r8d=0x1A0A(6666)
> 
> **来源**：`ref:c4382b53bf` · `ref:b092ff7d85` · `ref:6d4917704d`

### 6. HTTP取二阶段

`T1105` · 置信度 **中** · 动态

stager 用 InternetOpenA/InternetConnectA/HttpOpenRequestA/HttpSendRequestA 发起请求, 再循环 InternetReadFile 读取响应块并写入 VirtualAlloc(0x400000) 内存后跳转执行二阶段。

> **证据**：stage 偏移 0xD0-0x30: 解析 wininet 后 HttpSendRequestA→InternetReadFile 循环(0x56A2B5F0)+VirtualAlloc(0x40/0x1000); 请求仅一次, 未见后续 metsrv 行为
> 
> **来源**：`ref:b092ff7d85` · `ref:b802be11db` · `ref:c4382b53bf`

### 7. 循环休眠保活

`T1497.003` · 置信度 **高** · 静态

初始化与载荷执行后主线程进入 Sleep(10000) 无限循环, 进程持续驻留; 管道读取前亦有 Sleep(0x400) 重试等待。

> **证据**：0x403040: FUN_00401950; FUN_004017F8; do { Sleep(10000); } while(true); 0x4017A6 Sleep(0x400) 重试
> 
> **来源**：`ref:d85c8f3d31` · `ref:bfb9dc3277`


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
| http | `hxxp://192[.]168[.]28[.]128:6666/qRh2` | 6666 | c2 | 静态 | 已观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `192[.]168[.]28[.]128` | 是 | 静态 |
| `c2_port` | `6666` | 是 | 静态 |
| `c2_uri` | `/qRh2` | 是 | 静态 |
| `user_agent` | `Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)` | 是 | 静态 |
| `staging_pipe` | `\\.\pipe\MSSE-<GetTickCount%0x26aa>-server` | 是 | 静态 |
| `encryption_algo` | `4-byte repeating XOR, key 8B F5 0E 80` | 是 | 静态 |
| `embedded_stage_size` | `893` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不应仅凭 \\.\pipe\MSSE-%d-server 的管道命名就判定为 Cobalt Strike SMB Beacon: 解出的内置载荷与运行行为均为 Metasploit meterpreter 的 x64 reverse_http stager。
- 未观察到文件落地、注册表写入、服务安装或计划任务, 不应报告 dropper 持久化行为。
- 未观察到凭据窃取、文件加密或批量数据回传, 不应归类为 stealer/ransomware/wiper; 本次仅见一次 HTTP GET 取二阶段的尝试。
- C2 地址 192[.]168[.]28[.]128 为私网段地址, 且由沙箱假网拦截, 不能据此推断真实外部基础设施或真实攻击者归属。
- 外层加载器无签名/无版本资源、MinGW 编译, 尚未与已知家族精确对应; 家族判定仅针对被解密并执行的 Meterpreter 载荷。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `deacb44440abccffbd48e71e18bc9b5a07a8664663bceb3c5277fc8317031908`） |

**局限与待验证**

1. 二阶段(metsrv)未在本次动态观察中确认投递/执行: 假网对 GET /qRh2 的响应不构成有效 stage, 进程驻留但无后续命令、文件或网络行为, 因此 RAT 的完整指令能力未实测。
2. URI 与端口可直接从解密载荷静态读取(/qRh2, InternetConnectA 端口 0x1A0A=6666), 并与动态请求一致; 请求之后的服务端交互无法在无真实 C2 环境下复现。
3. 外层加载器为 MinGW 编译、无签名与版本信息, 未与已知家族精确匹配, 其管道暂存实现可能为定制或二次封装。
4. 样本以 WINDOWS_GUI 子系统静默运行, 无控制台输出, 无法从用户可见界面获得额外线索。
5. 动态结论来自单次沙箱引爆与内存取证; 反虚拟机/反调试行为未观察到, 但未做长时间驻留观测。

## 证据索引

<details>
<summary>展开 19 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:4194066e64` | 样本分诊 | 分诊: sha256/imphash, 9 段, 熵均 <6, packing score 0 |
| `ref:80a60e9277` | PE 结构解析 | x64 GUI PE, 时间戳 0, 入口 RVA 0x14C0, 导入表 RVA 0x9000 |
| `ref:c642a03844` | 导入表解析 | 仅 KERNEL32/msvcrt; 含 CreateNamedPipeA/ConnectNamedPipe/CreateFileA/ReadFile/WriteFile/VirtualAlloc/VirtualProtect/CreateThread |
| `ref:03b2457dea` | 字符串提取 | 字符串 '%c%c%c%c%c%c%c%c%cMSSE-%d-server'、Mingw-w64 runtime、GCC 9.x |
| `ref:401346c7f0` | decompile.function | 0x4017F8: 生成 \\.\pipe\MSSE-<tick%0x26aa>-server, CreateThread(0x4016E6) 与 0x4017A6 |
| `ref:febc5328cc` | decompile.function | 0x401630: CreateNamedPipeA/ConnectNamedPipe/WriteFile 管道服务端 |
| `ref:0d5b914056` | decompile.function | 0x401704: CreateFileA(pipe)/ReadFile 读回载荷 |
| `ref:62bc6e7ffe` | decompile.function | 0x401595: 4 字节循环 XOR 解密 + VirtualAlloc + VirtualProtect(0x20) + CreateThread |
| `ref:bfb9dc3277` | decompile.function | 0x4017A6: Sleep(0x400) 重试读取, 成功后调用 0x401595 执行 |
| `ref:d85c8f3d31` | decompile.function | 0x403040: 初始化后 do { Sleep(10000); } while(true) 常驻 |
| `ref:b802be11db` | disasm.bytes | 解密 stage 0x00-0xC4: PEB/Ldr 遍历 + ROR13 哈希解析(block_api) |
| `ref:b092ff7d85` | disasm.bytes | 解密 stage 0x100-0x190: InternetOpenA/InternetConnectA(端口 0x1A0A)/HttpOpenRequestA/HttpSendRequestA |
| `ref:6d4917704d` | evidence.record | 自写脚本: 解密 .data 893B 载荷, 得 host 192.168.28[.]128、port 6666、URI /qRh2、UA, sha256=deacb444... |
| `ref:97eeeb998c` | 动态分析平台 | 真实动态引爆: 进程 PID 6224 诞生并驻留; 时间线/内存 dump/隔离网络日志打包, 已回滚 |
| `ref:c4382b53bf` | sandbox(network log) | PID 6224 requested TCP 192.168.28[.]128:6666; HTTP GET /qRh2 + 伪装 UA + Host 头 |
| `ref:50f5888ce8` | sandbox(memory dump) | 进程内存含明文 stager 头 fc4883e4f0e8c8000000 与 'GET /qRh2 HTTP/1.1'、UA 字符串 |
| `ref:3dd292ebf8` | sandbox(memory dump) | 进程内存含管道实例 '\\.\pipe\MSSE-2265-server' 与解密后 stage sha256 |
| `ref:753a2e32b7` | sandbox(监控组件 target list) | PID 6224 存在并随后 GONE; 无 hollows 命中, 无新增子进程 |
| `c2_evidence:c9b5a0f9` | 连接证据提取 | 动态网络监控记录到 3 次到 192.168.28[.]128:6666, 192[.]168[.]28[.]128:80, maps[.]windows[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
