---
title: "恶意样本分析：Unattributed shellcode stager（PE · exe · dffa6d46）"
published: 2026-11-26
draft: false
description: "恶意（置信度低）：Unattributed shellcode stager · downloader/loader · 难度 easy · 动态沙箱 + 静态反编译"
tags: ["downloader", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed shellcode stager**（存疑） · 置信度 **低**
> 
> 别名：未归因 shellcode 加载器、custom shellcode stager、shellcode downloader
> 
> 样本是一个仅 3584 字节的 PE64 存根，只静态导入 Sleep，运行后用 PEB 遍历 + ROR13 哈希自解析 13 个系统 API，连接硬编码地址 8.210.131[.]228:443，发送 40 字节自定义上线报文，随后分配 30MB 可读写可执行内存、循环接收远程数据并按单字节 0x99 就地解密，最后直接 call 该内存缓冲执行。动态沙箱内实测到该进程向 8.210.131[.]228 发起 DNS 查询与 TCP 443 连接，属典型的内存 shellcode 下载/加载行为，判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed shellcode stager** · 别名 未归因 shellcode 加载器、custom shellcode stager、shellcode downloader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | easy |
| 首次出现 | 2026-11-24 02:29:23 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/dffa6d4603b3e7926da0d7ca4a39f7cb044751598539f948d30bd1df16645644/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">哈希解析系统API</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">加载网络运行库</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">检查临时标记文件</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1083</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">直连硬编码C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">发送上线握手包</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `dffa6d4603b3e7926da0d7ca4a39f7cb044751598539f948d30bd1df16645644` |
| MD5 | _未记录_ |
| 大小 | 3,584 字节（3.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **7** 条静态可得、**2** 条经动态分析取得。

### 1. 哈希解析系统API

`T1027` · 置信度 **高** · 静态

通过 GS:[0x60] 读取 PEB 并遍历 InLoadOrderModuleList，对模块名（UTF-16，含结尾 0）与导出函数名（ASCII）分别做 ROR13 累加后求和，与内置哈希常量比对，解析出 LoadLibraryA、VirtualAlloc、GetTempPathA、WSAStartup、WSASocketA、connect、send、recv、closesocket、gethostbyname、inet_addr、wsprintfA、_access 共 13 个 API，导入表中只有 Sleep。

> **证据**：0x145C 解析器：gs:[0x60]→PEB→[0x18]→Ldr→[0x10] 链表；0x14D1/0x150A 两处 ror 0xD 累加；哈希常量 0x726774C、0x6B8029 等 13 个
> 
> **来源**：`ref:b3d862000d` · `ref:afeefb5c35`

### 2. 加载网络运行库

`T1129` · 置信度 **高** · 动态

调用自行解析的 LoadLibraryA 依次加载 user32.dll、ws2_32.dll、msvcrt.dll，为后续网络通信（Winsock）、字符串格式化（wsprintfA）和临时文件检查（_access）准备函数。

> **证据**：0x1051/0x106F/0x108D 三次 call LoadLibraryA；内存扫描的模块列表中出现 user32.dll、ws2_32.dll、msvcrt.dll 以及 mswsock.dll、dnsapi.dll 等网络依赖
> 
> **来源**：`ref:e30a3b9a8d` · `ref:6d05dee171` · `ref:3a4c7a7ee0`

### 3. 检查临时标记文件

`T1083` · 置信度 **高** · 静态

用 GetTempPathA 取 %TEMP% 路径，再用 wsprintfA 拼出 "%TEMP%\log_de.log"，调用 _access(path, 0) 检查文件是否存在，存在则直接退出，作为单实例守卫；代码中没有创建该文件的逻辑。

> **证据**：0x1133 GetTempPathA(0x80, buf)；0x117F wsprintfA("%s%s%s")→log_de.log；0x1188 call _access；0x1194 je 退出
> 
> **来源**：`ref:d33d0777ea` · `ref:afeefb5c35`

### 4. 直连硬编码C2

`T1095` · 置信度 **高** · 动态

将内置分片 "8.21"+"0.13"+"1.22"+"8" 拼成 IP 字面量 8.210.131[.]228，WSAStartup(0x202) 初始化 Winsock 后创建 AF_INET/SOCK_STREAM/IPPROTO_TCP 套接字，先 gethostbyname 再回退 inet_addr 取得地址，连接 8.210.131[.]228:443，失败则 Sleep(10000) 重试。动态沙箱中该进程实际发起对 8.210.131[.]228 的 DNS 查询与 TCP 443 连接。

> **证据**：0x11CF/0x11DF/0x11EF/0x11FB 压入 IP 分片；0x1295 wsprintfA 拼接；0x12A4 WSAStartup(0x202)；0x12C9 WSASocketA(2,1,6)；0x12E7 gethostbyname；0x1321 connect（sockaddr 端口 0x01BB=443）；网络日志：dffa...exe (4772) requested TCP 8.210.131[.]228:443
> 
> **来源**：`ref:e913684ff3` · `ref:47462d82b5` · `ref:966ee212d9`

### 5. 发送上线握手包

`T1095` · 置信度 **高** · 静态

连接成功后连续 send：先发 6 字节魔数 "w64 "，再发 2 字节网络序端口（0x01BB），随后把 IP 字符串按 4 字节分片发出（"8.21"、"0.13"、"1.22"、"8\0\0\0"）并补 16 字节零，共 40 字节自定义上线报文。

> **证据**：0x1335 send("w64 ")；0x134E send(2 字节端口)；0x1361/0x1373/0x1385/0x1397 send(IP 分片)；0x13B0-0x13E1 send(4 个零 dword)
> 
> **来源**：`ref:e913684ff3` · `ref:d33d0777ea`

### 6. 分配RWX执行内存

`T1620` · 置信度 **高** · 静态

调用 VirtualAlloc(NULL, 0x1C9C380(30000000 字节，约 28.6MB), 0x1000(MEM_COMMIT), 0x40(PAGE_EXECUTE_READWRITE)) 分配一块可读可写可执行的大缓冲；失败则退出。

> **证据**：0x13F9 mov edx,0x1C9C380；mov r8d,0x1000；lea r9d,[rsi+0x3C]=0x40；call [rbp-0x20]
> 
> **来源**：`ref:e913684ff3`

### 7. 接收远程载荷

`T1105` · 置信度 **高** · 静态

循环调用 recv(socket, buf+offset, 0x64000, 0) 把远程数据追加写入刚分配的 RWX 缓冲，直到 recv 返回值小于等于 0，累计长度记录在偏移变量中。

> **证据**：0x1438 call r15(recv)；r8d=0x64000；recv 返回后 cmp eax,0 / jge 回循环
> 
> **来源**：`ref:e913684ff3`

### 8. XOR解密载荷

`T1140` · 置信度 **高** · 静态

对本次 recv 到的每个字节就地执行 XOR 0x99（xor byte ptr [rcx+rdi], 0x99），即远程载荷以单字节 0x99 异或编码传输，解密结果留在 RWX 内存中。

> **证据**：0x141F xor byte [rcx+rdi],0x99；0x1425 cmp r8d,eax / jb 0x1415 循环
> 
> **来源**：`ref:e913684ff3`

### 9. 内存直接执行载荷

`T1620` · 置信度 **高** · 静态

接收结束后 closesocket 关闭套接字，随即 mov rcx,rbx / call rdi 直接跳入 RWX 缓冲执行已解密的 shellcode，全程不写磁盘、不创建子进程。

> **证据**：0x1443 call [rbp-0x18]（closesocket）；0x1446 call rdi（rdi=VirtualAlloc 返回缓冲）
> 
> **来源**：`ref:e913684ff3` · `ref:bae7388936`


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
| tcp | `8.210.131[.]228:443` | 443 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%TEMP%\log_de.log`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `8.210.131[.]228` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `transport` | `原始 TCP（WSASocketA AF_INET/SOCK_STREAM/IPPROTO_TCP），连接失败每 10 秒重连` | 是 | 静态 |
| `handshake_magic` | `w64 （6 字节）+ 端口 2 字节 + 16 字节 IP 字符串分片 + 16 字节零填充，共 40 字节` | 是 | 静态 |
| `payload_xor_key` | `0x99（单字节 XOR，接收时在内存中就地解密）` | 是 | 静态 |
| `exec_method` | `VirtualAlloc(0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE) 后直接 call 缓冲执行` | 是 | 静态 |
| `single_instance_marker` | `%TEMP%\log_de.log（仅用 _access 检查是否存在，不创建）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不可断言已取得或执行最终载荷：动态窗口内 C2 未返回数据，未捕获 stage2，最终载荷能力未知。
- 不可断言存在持久化、服务或注册表修改：代码中没有任何写入磁盘/注册表的 API，遥测中该进程也无文件创建事件，仅用 _access 检查过 %TEMP%\log_de.log 是否存在。
- 不可归因为勒索软件或信息窃取器：代码中没有文件枚举、加密外传、浏览器凭据访问等逻辑。
- 不可仅凭 "w64" 魔数或哈希解析写法断言具体家族：两者在多个加载器/框架中通用，缺少唯一家族指纹。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. C2 未返回载荷，stage2 未取得；其最终功能（远控/窃密/勒索等）无法判定，家族归因只能保持未归因。
2. 动态仅观测到 DNS 查询与 TCP 443 连接尝试，没有完整请求/响应会话，故 c2 条目按静态恢复记录并标记待动态验证。
3. 动态窗口内进程在连接后异常终止（WerFault），未能观测到接收/解密/执行阶段的运行时行为；该阶段结论来自静态反汇编。
4. 静态分析基于反汇编与自写 ROR13 哈希映射脚本（对照本机系统 DLL 导出表），未使用厂商 YARA 或公开情报比对。
5. 内存扫描未发现异常注入/挂钩，属于本次未收到远程载荷的必然结果，不能据此认为样本不具备后续注入能力。

## 证据索引

<details>
<summary>展开 20 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:2060c7832d` | 样本分诊 | sha256/md5/imphash、3 个节、导入 1 个符号、加壳可能性 25%（仅因导入极少） |
| `ref:2b3dc3c3cf` | PE 结构解析 | PE64、AMD64、GUI 子系统、entry 0x1000、镜像 16KB、无异常节 |
| `ref:ebd8550d72` | 导入表解析 | 仅 KERNEL32.dll!Sleep，imphash e82dd51b077167be63c004bed23d0c1e |
| `ref:7135777e59` | 字符串提取 | 70 条 ASCII 字符串，含 ws2_32/msvcrt/user32 拼接片段与 log_de 片段 |
| `ref:e30a3b9a8d` | disasm.function | 入口 0x1000 前 120 条指令：LoadLibraryA×3、13 次哈希解析、GetTempPathA/wsprintfA/_access、IP 分片与 wsprintfA 拼接 |
| `ref:bae7388936` | cfg.function | 入口 CFG 18 个基本块，含连接重试环、接收解密环与最终 call 缓冲 |
| `ref:e913684ff3` | disasm.function | 0x1290 起 140 条指令：WSAStartup/WSASocketA/gethostbyname/connect、40 字节 send、VirtualAlloc RWX、recv+XOR 0x99、closesocket、call 载荷 |
| `ref:b3d862000d` | disasm.function | 0x145C 哈希解析器：PEB/Ldr 遍历 + ROR13 模块名/函数名比对 |
| `ref:afeefb5c35` | script | 自写脚本按模块名 UTF-16(含 NUL) ROR13 + 函数名 ASCII(含 NUL) ROR13 求和，精确匹配全部 13 个哈希到 13 个 API |
| `ref:6d05dee171` | dyn.run | 仿真执行观测到 LoadLibraryA(user32.dll/ws2_32.dll/msvcrt.dll) |
| `ref:2c0388c859` | 动态分析平台 | 沙箱引爆：pid 4772、时间线、5 个转储、网络与遥测产物打包并回滚 |
| `ref:47462d82b5` | sandbox.log | 网络监控日志：dffa...exe (4772) requested TCP 8.210.131[.]228:443 |
| `ref:966ee212d9` | sandbox.telemetry | 监控组件：pid 4772 对 8.210.131[.]228 的 DNS 查询（QueryStatus 0） |
| `ref:b8ecb391d7` | sandbox.telemetry | 监控组件 事件序列：4772 进程创建、DNS 查询、WerFault、t0/t3 内存扫描 |
| `ref:3a4c7a7ee0` | memory.scan | pid 4772 内存扫描：模块列表含 ws2_32/user32/msvcrt，t0/t3 无可疑注入区（总可疑 0） |
| `ref:d33d0777ea` | manual.hexdump | .text 原始字节：字符串拼接 "log_"/"de."/"log"、"8.21"/"0.13"/"1.22"/"8"、"w64 " 等常量 |
| `ref:34075c6580` | 动态产物收集 | 产物 zip 清单：网络监控日志、监控组件/ETW、内存扫描报告、进程/模块转储 |
| `c2_evidence:dffa6d46` | 连接证据提取 | 动态网络监控记录到 1 次到 8.210.131[.]228:443 的连接尝试；未捕获完整会话 |
| `telemetry:dffa6d46` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 115 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 26 条 |
| `etw:dffa6d46:4772` | 进程事件监控 | 短命进程事件：dffa6d4603b3e7926da0d7ca4a39f7cb044751598539f948d30bd1df16645644.exe（pid 4772；MD5=7F0439FBD3689890DF30B881B29C3D99,SHA256=DFFA6D4603B3E7926DA0D7CA4A39F7CB044751598539F948D30BD1DF16645644,IMPHASH=E82DD51B077167BE63C004BED23D0C1E） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
