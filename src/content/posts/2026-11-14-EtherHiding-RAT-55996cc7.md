---
title: "恶意样本分析：EtherHiding RAT（PE · exe · 55996cc7）"
published: 2026-11-14
draft: false
description: "恶意（置信度中）：EtherHiding RAT · dropper/backdoor · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["EtherHiding", "dropper", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **EtherHiding RAT**（存疑） · 置信度 **中**
> 
> 别名：EtherRAT-like、EtherHiding loader/backdoor
> 
> 动态沙箱中真实执行：样本落地伪装命名副本 %LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe 并启动，随后写入 HKCU\Environment\UserInitMprLogonScript 实现登录自启动；落地副本周期性地向 api[.]telegra[.]ph、三个 Polygon JSON-RPC 节点发起请求，并尝试升级到 wss://lookup[.]wavegrid79[.]lol/kmtkcw 的 WebSocket 控制通道。文件投递、持久化与 C2 请求均被独立观测到，判定为恶意后门。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **EtherHiding RAT** · 别名 EtherRAT-like、EtherHiding loader/backdoor · _存疑_ |
| 置信度 | **中** |
| 行为类 | dropper · backdoor |
| 难度 | hard |
| 首次出现 | 2026-11-11 02:32:33 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/55996cc76b81dccfbe6b7d3720f25ab9569e5dbe7c54cd2db18cbeca71376e40/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">投递伪装系统副本</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">写入登录脚本自启动</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1037.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">解密高熵节载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解析智能合约 C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">读取 Telegram 死信箱</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `55996cc76b81dccfbe6b7d3720f25ab9569e5dbe7c54cd2db18cbeca71376e40` |
| MD5 | _未记录_ |
| 大小 | 2,908,160 字节（2.8 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **6** 条静态可得、**3** 条经动态分析取得。

### 1. 投递伪装系统副本

`T1036.005` · 置信度 **高** · 动态

将内置载荷写为 %LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe 并启动该副本；系统事件同时记录到文件创建（PID 3176）与新进程创建（PID 4892）。

> **证据**：01:04:59 文件创建 C:\Users\analyst\AppData\Local\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe（Image=PID 3176）+ 0.15s 后同路径进程启动（PID 4892）
> 
> **来源**：`ref:7207a2fe5c` · `ref:c46b3223c6`

### 2. 写入登录脚本自启动

`T1037.001` · 置信度 **高** · 动态

设置 HKCU\Environment\UserInitMprLogonScript 指向上述伪装副本，使恶意程序在用户登录时自动执行。

> **证据**：注册表值写入：HKU\S-1-5-21-...\Environment\UserInitMprLogonScript = C:\Users\analyst\AppData\Local\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe（PID 3176）
> 
> **来源**：`ref:7207a2fe5c` · `ref:c46b3223c6`

### 3. 解密高熵节载荷

`T1027.002` · 置信度 **高** · 静态

PE 的 .text/.rdata/.data/.4E] 四个节在磁盘上 SizeOfRawData 均为 0，真实代码与配置位于熵 7.95 的 .l3c 节；运行后内存镜像中出现可执行代码与明文配置，说明存在自解密/解包阶段。

> **证据**：.l3c RVA 0x1C0000 大小 0x2C59B0 熵 7.952；EP RVA 0x3BF785 位于 .l3c；内存镜像有 2 个解包节
> 
> **来源**：`ref:36e325e09e` · `ref:849fed78dc` · `ref:f794b7c06a`

### 4. 解析智能合约 C2

`T1102` · 置信度 **高** · 静态

落地副本向 rpc[.]hostdefi[.]com、matic[.]rpc[.]sentio[.]xyz、polygon[.]gateway[.]tenderly[.]co 三个 Polygon JSON-RPC 节点 POST eth_call，合约 0xC95DDD2C9a7F7fe53Ffd226E02421d020C880Bd7、方法 0xb6154dab，用链上返回值解析控制端信息。

> **证据**：网络监控日志：POST / 与 /api/rpc/polygon，body 为 eth_call，to=0xC95DDD2C...，data=0xb6154dab
> 
> **来源**：`ref:e370c3d67d` · `ref:11618b7cef` · `ref:1eb7fa2bea`

### 5. 读取 Telegram 死信箱

`T1102.001` · 置信度 **高** · 静态

向 api[.]telegra[.]ph 请求 /getPage/Cedar-meadow-valley-10-30?return_content=false，并从返回页面中提取 description 字段作为备用配置。

> **证据**：网络监控日志 GET /getPage/Cedar-meadow-valley-10-30?return_content=false；内存镜像 .data RVA 0x10B68/0x10B88/0x10BB8 为页面标识与解析串
> 
> **来源**：`ref:e370c3d67d` · `ref:1eb7fa2bea`

### 6. 升级 WebSocket 通道

`T1071.001` · 置信度 **高** · 静态

使用 WinHTTP 请求 hxxps://lookup[.]wavegrid79[.]lol/kmtkcw 并发起 WebSocket Upgrade（Connection: Upgrade、Sec-WebSocket-Key），建立命令与控制通道。

> **证据**：导入 WinHttpWebSocketCompleteUpgrade @IAT 0x11360；网络日志持续出现 GET /kmtkcw HTTP/1.1 + Upgrade: websocket，Host: lookup[.]wavegrid79[.]lol
> 
> **来源**：`ref:a222c2558e` · `ref:e370c3d67d` · `ref:4a46c2781c`

### 7. 采集主机指纹

`T1082` · 置信度 **中** · 静态

调用 GetComputerNameW、GetUserNameW、GlobalMemoryStatusEx、GetUserDefaultUILanguage、GetSystemDefaultUILanguage 采集主机名、用户名、内存与系统语言等指纹信息。

> **证据**：运行时 IAT：kernel32.GetComputerNameW @0x113E0、GetUserNameW @0x113F8、GetUserDefaultUILanguage @0x11B18、GetSystemDefaultUILanguage @0x11B28、GlobalMemoryStatusEx @0x113D0
> 
> **来源**：`ref:a222c2558e` · `ref:1eb7fa2bea`

### 8. 动态解析 API

`T1027.007` · 置信度 **高** · 动态

内存中被重建的 IAT 含 GetModuleHandleA、LoadLibraryA、GetProcAddress，配合磁盘上仅 5 个诱饵导入，运行时按需加载网络、注册表等 API。

> **证据**：重建 IAT 0x1BF058：kernel32.GetModuleHandleA / LoadLibraryA / GetProcAddress / HeapAlloc / HeapFree / FatalExit
> 
> **来源**：`ref:826a0cfd9f`

### 9. 识别 VirtualBox 环境

`T1497.001` · 置信度 **中** · 静态

在 RVA 0x42FA00 附近以逐字节比较方式检查 "VirtualBox"/"Virtual" 等字符串，属于虚拟机环境探测。

> **证据**：RVA 0x42FA00 字节序列 41 80 7C 08 02 72 ... 41 80 39 56 ...（立即数依次为 r/t/u/a/l/B/o/x、V/i/r/t/u/a/l）
> 
> **来源**：`ref:b3e08951b7`


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
| http | `hxxps://lookup[.]wavegrid79[.]lol/kmtkcw` | 443 | c2 | 动态 | 已观测 |
| other | `hxxps://rpc[.]hostdefi[.]com/api/rpc/polygon` | 443 | c2 | 动态 | 已观测 |
| other | `hxxps://matic[.]rpc[.]sentio[.]xyz` | 443 | c2 | 动态 | 已观测 |
| other | `hxxps://polygon[.]gateway[.]tenderly[.]co` | 443 | c2 | 动态 | 已观测 |
| other | `Polygon 合约 0xC95DDD2C9a7F7fe53Ffd226E02421d020C880Bd7 / 选择子 0xb6154dab` | - | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://api[.]telegra[.]ph/getPage/Cedar-meadow-valley-10-30?return_content=false` | 443 | download | 动态 | 已观测 |

### 主机

**互斥体**

- `Global\0179BD0D60273EEF`

**落地路径**

- `%LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe`

**注册表**

- `HKCU\Environment\UserInitMprLogonScript`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `lookup[.]wavegrid79[.]lol` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `/kmtkcw` | 是 | 静态 |
| `c2_protocol` | `WebSocket over HTTPS（WinHTTP Upgrade）` | 是 | 静态 |
| `dead_drop_page` | `api[.]telegra[.]ph/getPage/Cedar-meadow-valley-10-30?return_content=false` | 否 | 静态 |
| `blockchain_contract` | `0xC95DDD2C9a7F7fe53Ffd226E02421d020C880Bd7` | 是 | 静态 |
| `blockchain_selector` | `0xb6154dab` | 是 | 静态 |
| `blockchain_rpc` | `rpc[.]hostdefi[.]com/api/rpc/polygon; matic[.]rpc[.]sentio[.]xyz; polygon[.]gateway[.]tenderly[.]co` | 是 | 静态 |
| `mutex` | `Global\0179BD0D60273EEF` | 是 | 静态 |
| `install_path` | `%LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe` | 是 | 动态 |
| `persistence` | `HKCU\Environment\UserInitMprLogonScript = %LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe` | 是 | 动态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0[.]0 Safari/537.36` | 否 | 静态 |
| `embedded_hex_blob_1` | `abde1360384f9ce569f7982ad5832487cdcca591143da43c8dd23cd980b38771f0aef182ce905c81a812417b5662c096` | 否 | 静态 |
| `embedded_hex_blob_2` | `30ea7f6e2d6af0d8ca2fe3e73b551f770e4812bdf80314c5919fd02c16aa1034` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得判定为勒索软件：未观察到文件加密、卷影删除或勒索提示（动态运行期间勒索提示计数为 0）。
- 不得声称第二阶段来自互联网下载：第二阶段由样本内置的加密数据解出并写盘执行，未观察到 HTTP 下载文件的行为。
- 不得声称已与 C2 完成指令交互或已回传主机数据：仅观察到 DNS 查询、HTTP 请求与 WebSocket Upgrade 尝试，无完整应用层响应/会话。
- 不得声称具备凭据、钱包或剪贴板窃取能力：未观察到相关 API 调用或浏览器/钱包目录访问。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `2328a19d75e98020ed4eb47018e2846af1344c16c4dd1c71cbb3379980553a26`） |

**局限与待验证**

1. C2 方向仅观察到 DNS 查询、HTTP eth_call 请求与 WebSocket Upgrade 请求，未获得应用层响应或指令，故所有 C2 条目按 static + pending_dynamic_verify 记录。
2. 未直接观测到互斥量创建/检查事件，mutex 来自运行时镜像中的字符串与 CreateMutexW 导入，置信度为中。
3. 静态反调试扫描在高熵节上给出的 rdtsc / int 2Dh / cpuid 命中未能排除随机字节误报，未作为结论采信。
4. .l3c 约 2.3MB 的首段在内存中仍保持高熵（约 7.99），疑似仍有加密载荷/插件未解密，本报告未覆盖其功能。
5. 第二阶段仅取得内存中的 realigned 镜像，未取得原始落盘文件；recovered 中的哈希对应内存镜像而非磁盘文件。
6. 沙箱已做虚拟机环境伪装，样本的 VirtualBox 检测未触发；该检测仅为静态反汇编观察。
7. 因无完整 C2 会话，未观察到远程 shell、文件窃取、键盘记录等具体后门功能，行为分类基于持久化 + WebSocket 控制通道的架构判断。

## 证据索引

<details>
<summary>展开 15 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:a8b8bac13f` | 静态分诊 | 哈希/imphash/节熵/导入面：.l3c 熵 7.952，仅 5 个导入符号，加壳分 0.25 |
| `ref:36e325e09e` | PE 结构解析 | AMD64 GUI，6 节，EP RVA 0x3BF785 位于 .l3c；四个节的 SizeOfRawData 为 0，.l3c 原始数据 0x2C5A00 @0x600 |
| `ref:7f6cd44d95` | 导入表解析 | 磁盘导入仅 lstrlenA/DialogBoxParamW/ExtractIconExW/GetROP2/CoCreateGuid |
| `ref:849fed78dc` | 壳检测 | 判定 packed=true，策略 emulate_to_oep；信号为 .l3c 高熵与导入极少 |
| `ref:826a0cfd9f` | 内存取证 | PE 镜像重建 IAT：GetModuleHandleA/LoadLibraryA/GetProcAddress/HeapAlloc/HeapFree/FatalExit @0x1BF058 |
| `ref:1eb7fa2bea` | 内存取证 | 第二阶段 .data 明文配置：mutex Global\0179BD0D60273EEF、Realtek 缓存路径、UserInitMprLogonScript、RPC/合约/页面/UA |
| `ref:4a46c2781c` | 内存取证 | 运行时堆中出现完整 URL hxxps://lookup[.]wavegrid79[.]lol/kmtkcw 与会话标识 |
| `ref:a222c2558e` | 内存取证 | 第二阶段导入：ws2_32.WSAStartup、winhttp.*（含 WinHttpWebSocketCompleteUpgrade）、CreateMutexW、RegOpenKeyExW/RegQueryValueExW |
| `ref:7207a2fe5c` | 系统事件遥测 | 文件创建（PID 3176）→ 注册表 UserInitMprLogonScript 写入 → 同路径进程启动（PID 4892）→ 反复 DNS 查询 |
| `ref:e370c3d67d` | 网络监控 | eth_call(0xb6154dab → 0xC95DDD2C...)、telegra[.]ph 页面请求、WebSocket Upgrade GET /kmtkcw |
| `ref:b3e08951b7` | 反汇编 | RVA 0x42FA00 处逐字节比较 VirtualBox/Virtual 字符串 |
| `ref:c183b5f9fd` | 动态沙箱 | 回滚→投放→轮询；捕获 PID 3176 与落地副本 PID 4892，内存转储与时间线已收集 |
| `c2_evidence:55996cc7` | 连接证据提取 | 动态网络监控记录到 41 次到 api[.]telegra[.]ph:443, lookup[.]wavegrid79[.]lol:443, matic[.]rpc[.]sentio[.]xyz:443, polygon[.]gateway[.]tenderly[.]co:443, rpc[.]hostdefi[.]com:443 的连接尝试；未捕获完整会话 |
| `telemetry:55996cc7` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 143 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:55996cc7:3176` | 进程事件监控 | 短命进程事件：55996cc76b81dccfbe6b7d3720f25ab9569e5dbe7c54cd2db18cbeca71376e40.exe（pid 3176；MD5=AA92AD5C2C0620CC61D06D87D09BA5B8,SHA256=55996CC76B81DCCFBE6B7D3720F25AB9569E5DBE7C54CD2DB18CBECA71376E40,IMPHASH=80809665711013F1BD93814069E02A29） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
