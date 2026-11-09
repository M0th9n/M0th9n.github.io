---
title: "恶意样本分析：OnyxDynamicsVentures Go Loader（PE · exe · 07d4b1f7）"
published: 2026-11-08
draft: false
description: "恶意（置信度低）：OnyxDynamicsVentures Go Loader · loader/implant · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["OnyxDynamicsVentures", "loader", "implant", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **OnyxDynamicsVentures Go Loader**（存疑） · 置信度 **低**
> 
> 别名：Onyx Dynamics Ventures
> 
> 真实隔离环境中观测到：主进程写入并启动 %TEMP%\dex.exe，随后向固定 IP 发起加密 HTTP POST，且 explorer.exe 内存中出现植入的原生 PE 与 shellcode；结合高度混淆的 Go 主模块和伪造版本信息的子进程，判定为恶意多阶段加载器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **OnyxDynamicsVentures Go Loader** · 别名 Onyx Dynamics Ventures · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · implant |
| 难度 | hard |
| 首次出现 | 2026-11-07 18:17:07 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/07d4b1f763d1d9479635e58980100f90d7fd4fa89808cac1c97e91607e0ad6ca/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">释放 dex.exe 并启动</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105; T1106</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">伪造 Briani 更新器</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">回连固定 IP 发心跳</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001; T1573</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">向 explorer 植入 PE</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.002</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">随机符号混淆 Go 模块</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `07d4b1f763d1d9479635e58980100f90d7fd4fa89808cac1c97e91607e0ad6ca` |
| MD5 | _未记录_ |
| 大小 | 5,219,256 字节（5.0 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **6** 条静态可得、**4** 条经动态分析取得。

### 1. 释放 dex.exe 并启动

`T1105; T1106` · 置信度 **高** · 动态

主进程在 %TEMP% 下写入 dex.exe，随后以该路径创建子进程；子进程 PID 与样本进程形成明确父子链。

> **证据**：进程创建遥测：ProcessId 2360 产生 File created TargetFilename=%TEMP%\dex.exe；随后 Image=%TEMP%\dex.exe（PID 1324）启动，父进程为样本。
> 
> **来源**：`ref:71a1e5e9d4` · `ref:e749bbd816`

### 2. 伪造 Briani 更新器

`T1036.005` · 置信度 **高** · 动态

子进程携带伪造版本资源：FileVersion 2.4.9[.]0、Description 'Briani Updater'、Product 'Briani'、Company 'Clitrusciar'、OriginalFileName 'Briani-app.exe'，工作目录为 system32。

> **证据**：进程创建遥测中 dex.exe 的版本信息字段与文件名不一致。
> 
> **来源**：`ref:71a1e5e9d4`

### 3. 回连固定 IP 发心跳

`T1071.001; T1573` · 置信度 **高** · 动态

样本进程向 95[.]217[.]96[.]240:80 发起 HTTP POST /，Content-Type 为 application/json，请求体为 132 字符 Base64（解码 97 字节）的高熵数据。

> **证据**：网络监控捕获：样本进程 (2360) requested TCP 95[.]217[.]96[.]240:80；随后 HTTP 记录 'POST / HTTP/1.1'、'Content-Type: application/json'、'Content-Length: 132' 及 Base64 体。
> 
> **来源**：`ref:9267022c7f` · `ref:e749bbd816`

### 4. 向 explorer 植入 PE

`T1055.002` · 置信度 **中** · 动态

内存扫描在 explorer.exe（PID 5208）发现 MEM_PRIVATE 可执行区域（基址 0x2ea0000，0xb0000 字节），其中含 PE 头、8 个节与 shellcode；转储为 2ea0000.shc 与 2eab000.dll。

> **证据**：内存扫描报告：main_image_path=explorer.exe，implanted_pe=1，has_shellcode=1，protection=0x40，is_listed_module=0；注入 PE 的 SHA256=2763364eb6bf347a62b997c729c6e8482713f048e5639fc28b78fef79710e673。
> 
> **来源**：`ref:963c6abc41` · `ref:76848631bf` · `ref:06e9f6b4a4` · `ref:5830f16814`

### 5. 随机符号混淆 Go 模块

`T1027` · 置信度 **高** · 静态

主模块为静态链接的 Go 1.24.5 程序，main 包 37 个函数全部使用随机名（如 scyph、xgojxGMoy、dzLWDcpn2H1），并混入大量 println 死代码，保留构建模块路径 OnyxDynamicsVentures。

> **证据**：符号表与反编译结果：main.(*AdfhyvMPy7Q).scyph 等随机命名；main.main 内 1500+ 次调用，其中大量 runtime.print* 死代码；.data 中 Go build info 含 'path OnyxDynamicsVentures'。
> 
> **来源**：`ref:381b790c4d` · `ref:b7c181365c` · `ref:c49ff078c1` · `ref:6d580c8b1a`

### 6. 运行时解析 Win32 API

`T1106` · 置信度 **高** · 静态

静态导入表仅包含 kernel32.dll 的 46 个符号；其余 ntdll/ws2_32/advapi32 等 API 通过 syscall.LoadLibrary、GetProcAddress 与 LazyProc.Call 在运行时解析调用。

> **证据**：导入表 dll_count=1（kernel32，46 符号）；调用图中 main.* 多处调用 syscall.(*LazyProc).Call / LoadLibrary / GetProcAddress；字符串含 ntdll.dll、ws2_32.dll、advapi32.dll。
> 
> **来源**：`ref:66502a8eec` · `ref:c3c787b92e` · `ref:d44659eb05`

### 7. 采集主机与网络指纹

`T1082; T1012` · 置信度 **中** · 静态

链接了网卡、域、卷、用户与注册表查询相关 API 的解析路径（GetAdaptersAddresses、GetAdaptersInfo、NetGetJoinInformation、GetVolumeNameForVolumeMountPointW、ConvertSidToStringSidW、GetUserNameExW、RegQueryValueExW），具备主机指纹采集能力。

> **证据**：字符串表中出现上述 API 名称（Go syscall 惰性解析表），并伴随 GetComputerNameW、GetSystemInfo 等。
> 
> **来源**：`ref:d44659eb05`

### 8. 链接服务与注册表操作

`T1543.003; T1547.001` · 置信度 **中** · 静态

包含 OpenSCManagerW/OpenServiceW/QueryServiceStatus 与 RegCreateKeyExW/RegSetValueExW/RegDeleteValueW 的解析路径，具备服务控制与注册表写入能力；本次运行未观测到实际新增 Run 键或服务。

> **证据**：字符串命中上述 API；运行前后 Run 键仅保留 OneDrive 与 SecurityHealth，无新增项。
> 
> **来源**：`ref:d44659eb05` · `ref:71a1e5e9d4`

### 9. 内置可疑落地路径

`T1036.005` · 置信度 **中** · 静态

二进制中硬编码两个非系统目录路径：C:\Program Files (x86)\sotho\githinyuasp.txt 与 C:\Program Files\scotland\mccaaninnaett.inf，可在后续阶段用于写入配置或 INF 相关操作。

> **证据**：字符串扫描偏移 0x35603a 与 0x356f98；同区域还出现 'Main file name provided' 与 'application buffer large enough data, trying extract code'。
> 
> **来源**：`ref:d44659eb05`

### 10. 携带代码签名数据

`T1553.002` · 置信度 **中** · 静态

PE 安全目录包含 8120 字节 Authenticode 数据，证书链涉及 DigiCert Assured ID Root CA / DigiCert Trusted G4 系列；签名有效性未做密码学校验。

> **证据**：PE 数据目录 SECURITY：rva=0x4F8400，size=8120；字符串中含 DigiCert OCSP/CRL 地址。
> 
> **来源**：`ref:fe02cdb9df` · `ref:d44659eb05`


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
| http | `hxxp://95[.]217[.]96[.]240/` | 80 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%TEMP%\dex.exe`
- `C:\Program Files (x86)\sotho\githinyuasp.txt`
- `C:\Program Files\scotland\mccaaninnaett.inf`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `95[.]217[.]96[.]240` | 是 | 动态 |
| `c2_port` | `80` | 是 | 动态 |
| `c2_uri` | `/` | 是 | 动态 |
| `beacon_format` | `HTTP POST; Content-Type: application/json; Base64 body (132 chars)` | 是 | 动态 |
| `staging_path` | `%TEMP%\dex.exe` | 是 | 动态 |
| `campaign_id` | `OnyxDynamicsVentures` | 否 | 静态 |
| `install_path` | `C:\Program Files (x86)\sotho\githinyuasp.txt` | 否 | 静态 |
| `encryption_algo` | `unidentified; AES and SHA-256 constants present; beacon body is high-entropy Base64 (97 bytes decoded)` | 否 | 静态 |
| `go_runtime` | `go1.24.5; CGO_ENABLED=0; GOOS=windows; GOARCH=amd64; -trimpath=true` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 未观测到文件批量加密或勒索信（ransom_notes=0），不应判定为 ransomware。
- 未观测到 LSASS 访问或浏览器凭据文件读取，不应据此判定为 stealer。
- 仅捕获到一次出站 HTTP POST，未取得服务端响应或下发指令，命令与控制协议完整性未知，不应断言其已具备完整远控会话。
- dex.exe 文件本体未取回（打开失败），其内部实现、最终载荷家族与配置无法确认。
- 不应把 gate-check、soft-focus、color-pass、set-review、'Film dailies review queue' 等内置字符串当作真实域名或业务，它们更可能是混淆串或诱饵。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 仅捕获到一次出站 POST，未记录服务端响应与后续指令；C2 命令协议与持久化能力未验证。
2. dex.exe 在扫描时已退出或无法打开（open_failed=87），文件本体未取回，其家族归属和内部配置未知。
3. explorer.exe 内植入 PE 的注入者未由调用链直接证实，仅依据样本→dex.exe 的父子链与时间线推断。
4. 注册表/服务写入仅为链接 API 的静态能力判断；运行前后 Run 键无变化，未观测到实际持久化。
5. Go 主模块大量函数为随机名并混入死代码，静态字符串含混淆/诱饵内容，静态层结论置信度有限。
6. Authenticode 签名仅解析到证书链与数据目录，未做签名有效性校验。
7. C2 仅观测到请求侧，未获得响应，故未确认其是否构成完整会话。

## 证据索引

<details>
<summary>展开 24 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:15240bf255` | 样本分诊 | 哈希、节熵、导入数量、加壳评分与结构异常（0 异常、packing 0） |
| `ref:fe02cdb9df` | PE 结构解析 | PE64 头、8 节、入口 0x70B80、SECURITY 目录 8120 字节、Go 构建特征 |
| `ref:66502a8eec` | 导入表解析 | 仅 kernel32.dll 46 符号，imphash d42595b695fc008ef2c56aabd8efd68e |
| `ref:d44659eb05` | 字符串提取 | 自定义路径、emirp/scene/flow/gate-check 等字符串、advapi32/ws2_32 API 名 |
| `ref:62fd7d19e1` | 密码学常量识别 | AES S-box/逆 S-box、SHA-256 K 常量、TEA delta |
| `ref:381b790c4d` | decompile.symbols | 2169 个函数，main.* 随机命名 |
| `ref:6d580c8b1a` | decompile.function | main.main 位于 RVA 0xC9F20 |
| `ref:b7c181365c` | pclntab | 解析出 37 个 main 包函数及随机方法名 |
| `ref:c3c787b92e` | callgraph | main.* 对 LazyProc.Call/LoadLibrary/GetProcAddress/WSAStartup 的调用 |
| `ref:c49ff078c1` | mem-scan | 进程内存中命中 OnyxDynamicsVentures、dex.exe、emirp 等字符串 |
| `ref:c02173474a` | 动态分析平台 | 真实动态引爆：候选进程 PID 2360、5 个转储、hollows 结果与回滚 |
| `ref:e749bbd816` | telemetry+network | ETW：子进程 dex.exe（PID 1324，父 2360）；网络监控：POST 95[.]217[.]96[.]240:80 |
| `ref:9267022c7f` | network-capture | 样本进程 2360 向 95[.]217[.]96[.]240:80 发送 application/json 的 POST，132 字节 Base64 请求体 |
| `ref:71a1e5e9d4` | sysmon-telemetry | 2360 创建 %TEMP%\dex.exe；1324 以 'Briani Updater' 版本信息启动；Run 键无新增 |
| `ref:963c6abc41` | memory-forensics | explorer.exe(PID 5208) 检出 implanted_pe=1、has_shellcode=1，转储 2ea0000.shc/2eab000.dll |
| `ref:76848631bf` | artifact-package | 动态产物包含内存转储、网络日志、进程时间线与哈希清单 |
| `ref:06e9f6b4a4` | 哈希与指纹 | 植入 PE SHA256=2763364e...、imphash=3819dc02...，MinGW 风格 8 节 DLL |
| `ref:5830f16814` | 导入表解析 | 植入 DLL 依赖 kernel32/user32/ntdll，含 IsDebuggerPresent、VirtualProtect 等 |
| `ref:4079cfa6f4` | 节表解析 | 植入 DLL 8 节（.text/.rdata/.data/.pdata/.fptable/.tls/_RDATA/.reloc） |
| `ref:80820d15c4` | 字符串提取 | 植入 DLL 仅 1060 条 ASCII 字符串，无可读 C2，疑似运行时解密 |
| `c2_evidence:07d4b1f7` | 连接证据提取 | 动态网络监控记录到 1 次到 95.217.96[.]240:80 的连接尝试；未捕获完整会话 |
| `telemetry:07d4b1f7` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 112 条；ETW 短命进程事件 2 条；已过滤工具/系统噪声 27 条 |
| `etw:07d4b1f7:2360` | 进程事件监控 | 短命进程事件：07d4b1f763d1d9479635e58980100f90d7fd4fa89808cac1c97e91607e0ad6ca.exe（pid 2360；MD5=81E31923CFF2646A2B7C3112E9AB13C0,SHA256=07D4B1F763D1D9479635E58980100F90D7FD4FA89808CAC1C97E91607E0AD6CA,IMPHASH=D42595B695FC008EF2C56AABD8EFD68E） |
| `etw:07d4b1f7:1324` | 进程事件监控 | 短命进程事件：dex.exe（pid 1324；MD5=0EBF04631F6023B5C2A7149C192B2F09,SHA256=5BA916C49724FF6985E1F53C41D6B4E8AB81DF547A3726BB60D58E36AAADDC4B,IMPHASH=353E10C266C3446F0B89B28FD1733CF8） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
