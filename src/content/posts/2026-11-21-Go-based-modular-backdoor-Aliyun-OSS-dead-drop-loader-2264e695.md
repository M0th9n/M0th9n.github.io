---
title: "恶意样本分析：Go-based modular backdoor (Aliyun OSS dead-drop loader)（PE · exe · 2264e695）"
published: 2026-11-21
draft: false
description: "恶意（置信度低）：Go-based modular backdoor (Aliyun OSS dead-drop loader) · backdoor/loader/implant · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Go-based modular", "backdoor", "loader", "implant", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Go-based modular backdoor (Aliyun OSS dead-drop loader)**（存疑） · 置信度 **低**
> 
> 别名：wheel01st 域名族
> 
> 样本以 64 位 PE 形式启动后，在分析窗口内由自身进程（PID 1776）向 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com 发起 HTTPS 请求 GET /tad（User-Agent: 3M），网络监控捕获到完整请求行与 Host 头；同时其 32 MB 的 .data 段内嵌完整的 Go 运行时与依赖字符串表（Go buildinf、go[.]mongodb[.]org、protobuf、golang[.]org/x/net）以及硬编码域名 wheel01st-ru[.]crossout[.]net。程序真实代码仅约 125 KB，其余体积为内嵌载荷与填充数据，符合“伪装成合法软件外观的加载器 + 内嵌 Go 后门”结构，据此判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Go-based modular backdoor (Aliyun OSS dead-drop loader)** · 别名 wheel01st 域名族 · _存疑_ |
| 置信度 | **低** |
| 行为类 | backdoor · loader · implant |
| 难度 | hard |
| 首次出现 | 2026-11-20 21:07:41 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/2264e6958399df51e2f9c244f8c9dfc85fba3f55ec942a45afdc94035dad284a/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">外联阿里云存储桶取指令</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">内存中驻留 Go 植入体</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">内嵌硬编码回连域名</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">伪造腾讯组件外观</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">夹带超大填充载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `2264e6958399df51e2f9c244f8c9dfc85fba3f55ec942a45afdc94035dad284a` |
| MD5 | _未记录_ |
| 大小 | 32,320,160 字节（30.8 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **5** 条静态可得、**2** 条经动态分析取得。

### 1. 外联阿里云存储桶取指令

`T1071.001` · 置信度 **高** · 动态

进程启动约 40 秒后向 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com:443 发起 HTTPS 请求，请求行 GET /tad、User-Agent 为 3M，Host 头指向该对象存储域名。

> **证据**：网络监控日志：'2264e69...exe (1776) requested TCP 192.0.2[.]123:443'，随后捕获 'GET /tad HTTP/1.1 / User-Agent: 3M / Host: 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com'
> 
> **来源**：`ref:0c2984b08b`

### 2. 内存中驻留 Go 植入体

`T1027` · 置信度 **中** · 动态

进程存活期间的内存镜像包含 Go 运行时、protobuf（duration.proto/timestamp.proto）、google[.]golang[.]org/grpc、go[.]mongodb[.]org 等符号与路径，说明实际执行的是内嵌 Go 后门，而非表面的 C++ 组件。

> **证据**：对 PID 1776 的 minidump 检索到 'Go buildinf:'、'go[.]mongodb[.]org'、'duration.proto'、'google[.]golang[.]org' 等字符串，并出现 wheel01st-ru[.]crossout[.]net 三次
> 
> **来源**：`ref:0ec81dae14` · `ref:6dc96c6c0e`

### 3. 内嵌硬编码回连域名

`T1071.001` · 置信度 **高** · 静态

文件 .data 段中硬编码 wheel01st-ru[.]crossout[.]net（三处副本），与运行期内存中的同一字符串一致，构成备用/上游 C2 域名。

> **证据**：静态检索命中 offset 0x2d45e4 / 0xa2a7b4 / 0x19c42d4，内存转储中同样出现
> 
> **来源**：`ref:80bbbfe1c4`

### 4. 伪造腾讯组件外观

`T1036` · 置信度 **中** · 静态

资源段写入腾讯版本信息（LegalCopyright 'Tencent Corporation'、版本 3.37.1[.]426），并带指向 DigiCert 与腾讯科技（深圳）的代码签名目录项，用于降低用户与静态检测的警惕。

> **证据**：PE 资源 VS_VERSION_INFO @0x1ecf34e；安全目录 RVA 0x1ED000，内含 CN=Tencent Technology (Shenzhen) Company Limited 证书
> 
> **来源**：`ref:ea71e090e3`

### 5. 夹带超大填充载荷

`T1027.002` · 置信度 **高** · 静态

.text 仅约 125 KB，而 .data 达 31.9 MB，且大部分为零填充与来自无关项目的 RTTI、字体、文件类型表，真实代码占比极小，属于载荷夹带与体积膨胀手法。

> **证据**：pe.parse：.text size_of_raw_data=125440，.data size_of_raw_data=31979520；.data 熵 4.105 且含 RPCS3/Qt/Courier Prime 等无关字符串
> 
> **来源**：`ref:c394d7e925` · `ref:1c5c80b48f`

### 6. 运行期动态解析 API

`T1129` · 置信度 **中** · 静态

导入表只保留 88 个基础 API，含 LoadLibraryA/W、GetProcAddress、VirtualAlloc，用于运行期按需装载能力模块，符合加载器/插件式后门结构。

> **证据**：pe.imports：KERNEL32 LoadLibraryA iat_rva 0x20048、GetProcAddress 0x20038、VirtualAlloc 0x20280
> 
> **来源**：`ref:681cbc24ab`

### 7. 反调试与异常分发探测

`T1622` · 置信度 **低** · 静态

导入 IsDebuggerPresent、SetUnhandledExceptionFilter、RtlCaptureContext/RtlVirtualUnwind，具备调试器与环境探测能力（本次运行未观察到由此引发的反分析动作）。

> **证据**：IAT：IsDebuggerPresent @0x20270、SetUnhandledExceptionFilter @0x202D0、RtlVirtualUnwind @0x202C0
> 
> **来源**：`ref:681cbc24ab`


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
| http | `hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad` | 443 | c2 | 动态 | 已观测 |
| dns | `wheel01st-ru[.]crossout[.]net` | 0 | c2 | 静态 | ⏳ 未观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com\|wheel01st-ru[.]crossout[.]net` | 是 | 动态 |
| `c2_port` | `443` | 是 | 动态 |
| `c2_uri` | `/tad` | 是 | 动态 |
| `user_agent` | `3M` | 是 | 动态 |
| `transport` | `HTTPS，对象存储桶作为指令通道` | 否 | 动态 |
| `payload_language` | `Go，含 protobuf 与 MongoDB 驱动` | 否 | 静态 |
| `install_path` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言样本是腾讯官方发行组件：版本资源与签名目录可被复制或滥用，需独立校验证书链与签名有效性。
- 不能断言已发生进程注入、计划任务或注册表持久化：内存扫描未发现植入 PE/shellcode，也未观测到注册表或服务写入。
- 不能断言数据已被外传：仅捕获到一次 GET /tad 请求，未见响应体与上传行为。
- 不能断言 wheel01st-ru[.]crossout[.]net 在本次运行中被实际连接：它只出现在静态字符串与内存中，没有对应网络会话。
- 不能仅凭 AES/SHA-256 常量就认定存在勒索加密或自定义加密协议：这些常量位于内嵌数据与通用库中。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态通道仅捕获一次外联（GET /tad），未取得响应内容，无法判定下发指令类型。
2. 未观察到子进程创建、文件写入、注册表/服务/计划任务变更，持久化能力未知。
3. 未完成对 .data 中内嵌 Go 载荷的完整提取与恢复（.data 大部分为填充数据，载荷边界未确定），因此载荷哈希为空。
4. 未对 Authenticode 证书链做有效性验证，签名归属仅按目录中的证书主体描述。
5. wheel01st-ru[.]crossout[.]net 的回连未在本次运行中出现，需外部网络或更长观测窗口确认。
6. 静态层面存在大量来自无关项目的 RTTI 与资源字符串，可能干扰基于字符串的家族归类。

## 证据索引

<details>
<summary>展开 14 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:1c5c80b48f` | 样本分诊 | 哈希/imphash/段熵与加壳评分（packing.score=0） |
| `ref:cc4bf94422` | 哈希与指纹 | sha256 与 imphash=20abbe0f6ab059ea4a375bcb6b8a717b |
| `ref:c394d7e925` | PE 结构解析 | 段表：.text 125440 字节 / .data 31979520 字节 |
| `ref:681cbc24ab` | 导入表解析 | 4 个 DLL、88 个符号，含 LoadLibrary/GetProcAddress/VirtualAlloc/IsDebuggerPresent |
| `ref:ea71e090e3` | 字符串提取 | 资源段 Tencent 版本信息 3.37.1[.]426 与版权字符串 |
| `ref:80bbbfe1c4` | static-grep | wheel01st-ru[.]crossout[.]net 三处偏移与 Go buildinf/mongo 依赖名 |
| `ref:bc0b0c7c07` | decompile.ghidra | FUN_140002fd0 反编译，确认为薄壳式 C++ 启动逻辑 |
| `ref:48a31897ef` | 动态分析平台 | 真实动态运行：PID 1776 引爆，34 次轮询，产出时间线与内存转储 |
| `ref:0c2984b08b` | network-monitor | 样本进程请求 192.0.2[.]123:443 并发出 GET /tad，Host=3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com，UA=3M |
| `ref:0ec81dae14` | memory-forensics | 进程内存转储含 Go 运行时、protobuf、mongo 驱动与 C2 域名 |
| `ref:3d5156c9bd` | dyn.run | 仿真仅停留在 CRT 初始化阶段，未复现网络行为，故以真实动态为准 |
| `c2_evidence:2264e695` | 连接证据提取 | 动态网络监控记录到 1 次到 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com:443 的连接尝试；未捕获完整会话 |
| `telemetry:2264e695` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 110 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 18 条 |
| `etw:2264e695:1776` | 进程事件监控 | 短命进程事件：2264e6958399df51e2f9c244f8c9dfc85fba3f55ec942a45afdc94035dad284a.exe（pid 1776；MD5=9CBE0AA9E2217AEE24F80162EFBEF7D4,SHA256=2264E6958399DF51E2F9C244F8C9DFC85FBA3F55EC942A45AFDC94035DAD284A,IMPHASH=20ABBE0F6AB059EA4A375BCB6B8A717B） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
