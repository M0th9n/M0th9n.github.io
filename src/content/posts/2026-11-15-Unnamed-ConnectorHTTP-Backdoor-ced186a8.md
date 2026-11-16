---
title: "恶意样本分析：Unnamed ConnectorHTTP Backdoor（PE · exe · ced186a8）"
published: 2026-11-15
draft: false
description: "恶意（置信度低）：Unnamed ConnectorHTTP Backdoor · backdoor/rat · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Unnamed ConnectorHTTP", "backdoor", "rat", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unnamed ConnectorHTTP Backdoor**（存疑） · 置信度 **低**
> 
> 静态还原出 RC4 加密的内置 C2 配置（主机 minecraf-world-register[.]io.vn、端口 443、POST /api/v1/updates、自定义头 X-Beacon-Id），并确认程序以 PEB/导出表哈希方式动态解析 123 个 API（含 CreateProcessA/CreatePipe/ReadFile/WriteFile、InternetOpenA/HttpSendRequestA、socket/connect/recv 等），主循环按数据包类型分发远程命令、文件传输与套接字转发。动态沙箱中该样本真实启动后解析同一域名并连续发出 671 次同构 HTTP POST 信标，与静态配置逐字一致，故判定为具备远程控制能力的后门。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unnamed ConnectorHTTP Backdoor** · _存疑_ |
| 置信度 | **低** |
| 行为类 | backdoor · rat |
| 难度 | medium |
| 首次出现 | 2026-11-14 00:26:12 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置C2配置</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">哈希解析系统API</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">HTTP信标轮询C2</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">443端口明文HTTP</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">远程Shell执行命令</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900` |
| MD5 | _未记录_ |
| 大小 | 104,448 字节（102.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **7** 条静态可得、**2** 条经动态分析取得。

### 1. 解密内置C2配置

`T1027` · 置信度 **高** · 静态

从 .rdata 起始处（文件偏移 0x17C00 / RVA 0x1A000）读取 [u32 长度][RC4 密文][16 字节密钥] 结构，用标准 RC4 解密 233 字节并顺序解析出 C2 主机、端口、URI、HTTP 方法与自定义请求头；另生成 16 字节随机会话数据用于通信标识。

> **证据**：0x140003e8e 解析配置；0x14000d630 RC4 KSA / 0x14000d720 PRGA；blob off 0x17C00
> 
> **来源**：`ev-000029` · `ev-000031` · `ev-000032` · `ev-000036` · `ev-000038` · `ev-000039` · `ev-000051`

### 2. 哈希解析系统API

`T1027` · 置信度 **高** · 静态

遍历 PEB 的已加载模块链表，按 h=0x624、h=h*0x21+小写字符 的 32 位哈希匹配模块基名与导出名，动态解析 123 个 API；导入表因此只保留 KERNEL32/msvcrt 的 CRT 函数，隐藏真实能力面。

> **证据**：0x140010e5a PEB 遍历；0x140010d80/0x140010ded 哈希函数；0x14000477e 解析表
> 
> **来源**：`ev-000044` · `ev-000045` · `ev-000047` · `ev-000048` · `ev-000028` · `ev-000052`

### 3. HTTP信标轮询C2

`T1071.001` · 置信度 **高** · 动态

通过 WinINet 向 minecraf-world-register[.]io.vn:443 周期发送 POST /api/v1/updates，附带 X-Beacon-Id: <Base64 会话数据>、固定 UA、Content-Length: 0、Keep-Alive；本次运行 4 分钟内记录 671 次同构请求。

> **证据**：动态网络监控：POST /api/v1/updates HTTP/1.1，Host: minecraf-world-register[.]io.vn；0x14000ea87 主循环；0x14000477e 解析 InternetOpenA/HttpSendRequestA
> 
> **来源**：`ev-000053` · `ev-000051` · `ev-000023` · `ev-000052`

### 4. 443端口明文HTTP

`T1571` · 置信度 **高** · 动态

配置端口为 443，但实际以明文 HTTP/1.1 通信（无 TLS 握手），借常见 HTTPS 端口规避简单的端口/协议过滤。

> **证据**：网络监控在 443 捕获完整明文 HTTP 请求；配置 c2_port=443、c2_uri=/api/v1/updates
> 
> **来源**：`ev-000053` · `ev-000051`

### 5. 远程Shell执行命令

`T1059.003` · 置信度 **高** · 静态

命令处理链用 CreateProcessA 创建进程，CreatePipe/PeekNamedPipe/ReadFile/WriteFile 转发标准输出与输入，并把结果封装为 0x25/0x27 型数据包回传；以 0x103 错误作为会话结束条件。

> **证据**：0x140010920 中 CreateProcessA/CreatePipe/PeekNamedPipe/ReadFile/WriteFile 调用链与 0x25/0x27 包类型
> 
> **来源**：`ev-000043` · `ev-000052` · `ev-000023`

### 6. 文件上传下载管理

`T1105,T1083` · 置信度 **中** · 静态

0x14000da30 以状态机打开目标文件、按块 ReadFile 并通过 0x20 型数据包回传进度；0x14000e520 维护另一类传输条目；解析表包含 CreateFileA/CopyFileA/MoveFileA/DeleteFileA/FindFirstFileA/GetLogicalDrives 等文件管理函数。

> **证据**：0x14000da30 文件块读取与 0x20 包；0x14000e520 传输条目状态机；0x14000477e 文件 API 解析
> 
> **来源**：`ev-000040` · `ev-000041` · `ev-000052`

### 7. 套接字转发/代理

`T1090` · 置信度 **中** · 静态

0x140010920 对 type=2 句柄使用 ioctlsocket(FIONREAD=0x4004667f) 取待读长度后 recv 读取数据，并调用半关闭/关闭；解析表同时含 accept/bind/listen/select，具备把 C2 通道与本地或内网套接字互转（端口转发/代理）的代码路径。本次未收到指令，未实际触发。

> **证据**：0x140010920 ioctlsocket 0x4004667f + recv；0x14000477e 解析 accept/bind/listen/select
> 
> **来源**：`ev-000043` · `ev-000052`

### 8. 命名管道进程通信

`T1559` · 置信度 **中** · 静态

解析 CreateNamedPipeA/WaitNamedPipeA/SetNamedPipeHandleState/DisconnectNamedPipe，并使用格式串 \\.\pipe\%08lx 生成管道名，用于本机组件或实例之间的通信。

> **证据**：字符串 \\.\pipe\%08lx @ rva 0x1A234 (off 0x17954)；0x140007b9c/0x14000851c 管道句柄管理；0x14000477e 解析命名管道 API
> 
> **来源**：`ev-000013` · `ev-000050` · `ev-000049` · `ev-000052`

### 9. 主机指纹信息采集

`T1082,T1016,T1033` · 置信度 **高** · 静态

连接初期用 GetAdaptersInfo、GetComputerNameExA、GetUserNameA、RtlGetVersion、GetTimeZoneInformation、GetLocalTime 等组装约 0x11c 字节的主机信息包，序列化后作为首个连接数据交给通信对象发送。

> **证据**：0x14000439e 采集主机信息；0x140003a9e 序列化；0x14000ea87 建立连接时先发送该数据
> 
> **来源**：`ev-000027` · `ev-000025` · `ev-000023` · `ev-000052`


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
| http | `hxxp://minecraf-world-register[.]io[.]vn/api/v1/updates` | 443 | c2 | 动态 | 已观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `minecraf-world-register[.]io.vn` | 是 | 动态 |
| `c2_port` | `443` | 是 | 动态 |
| `c2_uri` | `/api/v1/updates` | 是 | 动态 |
| `http_method` | `POST` | 是 | 动态 |
| `http_header` | `X-Beacon-Id` | 是 | 动态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0` | 是 | 动态 |
| `header_encoding` | `base64` | 否 | 动态 |
| `encryption_algo` | `RC4 (KSA+PRGA) for embedded config blob; 16-byte key appended after ciphertext` | 是 | 静态 |
| `config_magic` | `0xBE4C0149` | 否 | 静态 |
| `config_blob_location` | `file_off=0x17C00 rva=0x1A000 len=253 (u32=233 + 233 ciphertext + 16 key)` | 否 | 静态 |
| `separator` | `\r\n` | 否 | 静态 |
| `config_timestamp_unix` | `1742829843` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得判定为勒索/擦除类：未发现文件加密、卷影删除或大规模破坏逻辑，也无对应 API 解析。
- 不得判定为窃密/银行木马：未发现浏览器数据、凭据库或键盘/屏幕采集相关 API 与调用链，本次动态亦未观察到相关读写。
- 不得声称存在持久化：本次运行未观察到服务、启动项、注册表 Run 键或计划任务写入；解析出的 API 表也不含相应写入函数，样本更像驻留内存的信标。
- 不得声称已发生进程注入或凭据转储：内存扫描未发现替换/植入模块，动态中亦无该样本的子进程或 LSASS 访问行为。
- 不得把“具备令牌相关 API”直接当作已实施令牌窃取：令牌相关函数仅出现在 API 解析表中，未观察到实际调用链。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态沙箱仅记录到客户端的 HTTP 请求，服务端未返回可解析的任务指令，因此远程 Shell、文件传输、套接字转发等能力由静态调用链判定，未获动态执行印证。
2. 未观察到持久化或自启动行为；但本次运行时间较短，不能据此断言长期驻留能力不存在。
3. 未观察到进程注入或凭据转储；仅能说明本次运行与内存扫描未发现，不能排除后续指令触发。
4. PE 编译时间戳为 2026-10-24，晚于通常的样本出现时间，可能被伪造或构建环境时钟异常。
5. 家族命名缺少厂商引擎/YARA 交叉验证，仅依据配置魔数、RTTI 类名、请求头与行为特征给出候选，标注 uncertain。
6. C2 域名在沙箱伪网中被解析到保留测试地址，真实基础设施未做外联验证。

## 证据索引

<details>
<summary>展开 29 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 |
| `ev-000002` | scan.imphash | imphash=2eb0e19e399049c7d933ef4e6502cd2a |
| `ev-000013` | 字符串提取 | 字符串：\\.\pipe\%08lx、ConnectorHTTP/Connector RTTI、api-ms-win-/ext-ms- |
| `ev-000023` | decompile.function | 主循环 0x14000ea87：连接、收包、命令分发、回复 |
| `ev-000025` | decompile.function | 0x140003a9e 将主机信息与 16 字节会话数据序列化 |
| `ev-000026` | decompile.function | 0x14000365e 配置/会话对象构造，生成 16 字节随机数据 |
| `ev-000027` | decompile.function | 0x14000439e 采集主机指纹信息 |
| `ev-000028` | decompile.function | 0x14000477e 动态解析模块与 API 的哈希表构建 |
| `ev-000029` | decompile.function | 0x140003e8e 内嵌配置结构解析流程 |
| `ev-000031` | decompile.function | 0x140001480 配置 blob 指针 = 0x14001a000 |
| `ev-000032` | decompile.function | 0x14000148d 配置 blob 长度 = 0xfd |
| `ev-000036` | decompile.function | 0x14000d83c 配置解密入口（KSA+PRGA） |
| `ev-000038` | decompile.function | 0x14000d630 RC4 KSA |
| `ev-000039` | decompile.function | 0x14000d720 RC4 PRGA |
| `ev-000040` | decompile.function | 0x14000da30 文件块读取与 0x20 包状态机 |
| `ev-000041` | decompile.function | 0x14000e520 传输条目状态机与 0x8437 包类型 |
| `ev-000043` | decompile.function | 0x140010920 管道/套接字处理与 0x25/0x27 回传 |
| `ev-000044` | decompile.function | 0x140010e5a PEB InMemoryOrderModuleList 遍历 |
| `ev-000045` | decompile.function | 0x140010f00 导出表哈希匹配与 API 解析 |
| `ev-000047` | decompile.function | 0x140010d80 名称哈希 h=h*0x21+c |
| `ev-000048` | decompile.function | 0x140010ded 模块名哈希（宽字符） |
| `ev-000049` | decompile.function | 0x14000851c 多通道句柄读取/关闭 |
| `ev-000050` | decompile.function | 0x140007b9c 创建管道/句柄对象 |
| `ev-000051` | evidence.record | 脚本：RC4 解密并解析内嵌配置 |
| `ev-000052` | evidence.record | 脚本：复算哈希算法并枚举 123 个动态解析 API |
| `ev-000053` | evidence.record | 脚本：动态沙箱 DNS/HTTP 信标与内存扫描结果汇总 |
| `c2_evidence:ced186a8` | 连接证据提取 | 动态网络监控记录到 307 次到 minecraf-world-register[.]io[.]vn:443 的连接尝试；未捕获完整会话 |
| `telemetry:ced186a8` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 117 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:ced186a8:7212` | 进程事件监控 | 短命进程事件：ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900.exe（pid 7212；MD5=A293B28028115D676FCA89E38FE8A441,SHA256=CED186A8664F5ED95A4F516D04E614A27D2407536DD69B5CB8C0045CD3DB1900,IMPHASH=2EB0E19E399049C7D933EF4E6502CD2A） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
