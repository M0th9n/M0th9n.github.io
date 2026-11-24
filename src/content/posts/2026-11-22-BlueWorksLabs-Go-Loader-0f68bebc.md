---
title: "恶意样本分析：BlueWorksLabs Go Loader（PE · exe · 0f68bebc）"
published: 2026-11-22
draft: false
description: "恶意（置信度低）：BlueWorksLabs Go Loader · loader/rat/spyware · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["BlueWorksLabs", "loader", "rat", "spyware", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **BlueWorksLabs Go Loader**（存疑） · 置信度 **低**
> 
> 别名：BlueWorksLabs、sy3theo[.]tattoo 面板、bf5eea7e 活动标识
> 
> 样本是 UPX 加壳、经符号混淆的 Go 程序；在隔离 Windows 环境中实际运行后，它解析并回连 sy3theo[.]tattoo，以明文 HTTP 向 443 端口发送带 tag/exp/hwid 的注册信标，随后以 multipart 上传二进制数据；同一进程私有内存中出现一个被注入的原生可执行模块，该模块内含与信标一致的 32 位活动标识 bf5eea7eb9dd0adade73f83a0970f1eb，并具备桌面句柄与 GDI 截屏接口。上述均为运行时直接观测到的行为，判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **BlueWorksLabs Go Loader** · 别名 BlueWorksLabs、sy3theo[.]tattoo 面板、bf5eea7e 活动标识 · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · rat · spyware |
| 难度 | medium |
| 首次出现 | 2026-11-19 23:48:23 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/0f68bebc56a491a29e49ee246b0ac47fbe9092507fbd75fcfaed88d7854eaed5/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX 双层包裹</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">混淆 Go 符号</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">隐藏加密载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">自注入原生模块</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">回连指定 C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `0f68bebc56a491a29e49ee246b0ac47fbe9092507fbd75fcfaed88d7854eaed5` |
| MD5 | _未记录_ |
| 大小 | 1,286,024 字节（1.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **3** 条静态可得、**6** 条经动态分析取得。

### 1. UPX 双层包裹

`T1027.002` · 置信度 **高** · 静态

样本为 64 位 PE，仅有 4 个导入符号，段名为 UPX0/UPX1/UPX2，UPX0 与 UPX1 同时可写可执行，UPX1 熵 7.915，符合 UPX 加壳特征。

> **证据**：scan.triage/pe.parse：UPX0/UPX1 为 W^X，import_dll_count=1、导入符号 4 个，加壳评分 0.85；unpack.detect 判定 upx。
> 
> **来源**：`ref:57cc08dbaa` · `ref:d1a7120601` · `ref:8e548b8a3e` · `ref:d645e22f9b`

### 2. 混淆 Go 符号

`T1027` · 置信度 **高** · 静态

解包后为 Go 1.24.5 程序，模块路径 BlueWorksLabs，main 包 78 个函数名全部为随机串（garble 风格），构建参数含 -trimpath，静态可读语义被削弱。

> **证据**：解包映像 rva 0x2fb000 的 Go buildinfo；pclntab(magic 0xfffffff1, nfunc=2291) 解析出 main.FNJOSzDbwb7y 等随机函数名。
> 
> **来源**：`ref:8aa62d116d`

### 3. 隐藏加密载荷

`T1140` · 置信度 **中** · 静态

解包映像 rva 0x1f0000-0x240000 存在约 0x51000 字节、熵 7.7-8.0 的连续高熵块，且二进制含 AES 正/逆 S-box 常量，形态与加密内嵌载荷一致。

> **证据**：逐 32KB 熵扫描：0x1f0000 起熵 7.7-8.0；scan.crypto 命中 AES S-box @ off 0x302940 与逆 S-box @ 0x302a40。
> 
> **来源**：`ref:43cb34267d` · `ref:ca6149b667`

### 4. 自注入原生模块

`T1055` · 置信度 **高** · 动态

样本运行后在同一进程的私有内存 0x140000000 处出现一个 264,351 字节、4 个节的可执行 PE 镜像，未出现在已加载模块列表中，判定为运行期手动映射的植入模块。

> **证据**：内存扫描：implanted_pe=1、hdr_modified=1，module=0x140000000、module_size=0x4091F、mapping_type=MEM_PRIVATE、protection=0x40。
> 
> **来源**：`ref:df8afade51` · `ref:eb9eaee973`

### 5. 回连指定 C2

`T1071.001` · 置信度 **高** · 动态

进程解析 sy3theo[.]tattoo 后向 192.0.2[.]123:443 发起明文 HTTP POST，Host 为 sy3theo[.]tattoo，全程仅此一个 C2 域名。

> **证据**：网络监控：pid 3656 → TCP 192.0.2[.]123:443，HTTPListener 记录 POST /、Host: sy3theo[.]tattoo。
> 
> **来源**：`ref:df8afade51` · `ref:23d991c996`

### 6. 上报主机指纹

`T1082` · 置信度 **高** · 动态

首个信标以 application/x-www-form-urlencoded 上报 tag=bf5eea7eb9dd0adade73f83a0970f1eb、exp=1794982993、hwid=7b14dee56f09a06933c6bd6f0ae8df1f，用活动标识、到期时间和机器指纹做注册/授权校验。

> **证据**：网络监控首个 POST 的 body：tag=bf5eea7eb9dd0adade73f83a0970f1eb&exp=1794982993&hwid=7b14dee56f09a06933c6bd6f0ae8df1f（Content-Length: 89）。
> 
> **来源**：`ref:23d991c996` · `ref:eb9eaee973`

### 7. 上传加密数据

`T1041` · 置信度 **高** · 动态

注册信标之后，同一进程以 multipart/form-data 上传 1259 字节二进制（access_token 为空、type=0、file filename=data），并再发一个 6 字节 application/octet-stream 请求继续交互。

> **证据**：网络监控 multipart 请求（boundary=He2BV7uuigcy9L3PmX7，Content-Length: 1259）及 6 字节 octet-stream 请求（de 35 dc 35 bc 1d）。
> 
> **来源**：`ref:23d991c996`

### 8. 具备截屏能力

`T1113` · 置信度 **高** · 动态

被注入模块导入 CreateDesktopW/OpenDesktopW、GetDC/GetWindowDC/GetWindowRect、BitBlt/CreateCompatibleBitmap/GetDIBits 等桌面与 GDI 接口，同时导入 CoCreateInstance/CoSetProxyBlanket 用于 COM 调用，具备截取桌面画面的能力。

> **证据**：内存转储模块导入表：user32.GetDC/GetWindowDC/CreateDesktopW/OpenDesktopW、gdi32.BitBlt/CreateCompatibleBitmap/GetDIBits、combase.CoCreateInstance/CoSetProxyBlanket。
> 
> **来源**：`ref:8d2d9071fc` · `ref:1c24598b39` · `ref:eb9eaee973`

### 9. 伪装浏览器流量

`T1036` · 置信度 **高** · 动态

所有 C2 请求统一使用 Chrome/117 的 User-Agent，并采用常规表单与 multipart 上传头，使流量混同于浏览器 Web 访问。

> **证据**：网络监控中 3 个 POST 均带 Mozilla/5.0 ... Chrome/117.0.0[.]0 Safari/537.36。
> 
> **来源**：`ref:23d991c996`


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
| http | `hxxp://sy3theo[.]tattoo/` | 443 | c2 | 动态 | 已观测 |
| http | `hxxp://sy3theo[.]tattoo/` | 443 | exfil | 动态 | 已观测 |

### 主机

**落地路径**

- `%TEMP%\box-<pid>-<id>.dat（二进制内格式串 "box-%d-%d.dat"，未观测到实际落盘）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `sy3theo[.]tattoo` | 是 | 动态 |
| `c2_port` | `443` | 是 | 动态 |
| `c2_uri` | `/` | 是 | 动态 |
| `campaign_tag` | `bf5eea7eb9dd0adade73f83a0970f1eb` | 是 | 动态 |
| `license_expiry` | `exp=1794982993 (2026-11-18T06:23:13Z)，与模块内明文 18.11.2026 一致` | 是 | 动态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0[.]0 Safari/537.36` | 是 | 动态 |
| `encryption_algo` | `AES（二进制含标准/逆 S-box；上传体为密文，未解密）` | 否 | 静态 |
| `upload_fields` | `access_token, type, file(filename=data)` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭二进制中存在 AES S-box 与高熵数据块就判定为勒索软件；运行期间未观测到任何文件加密、扩展名篡改或勒索说明。
- 不能把被注入模块的 GDI/COM 导入等同于完整远程控制、键盘记录或凭据窃取；本次仅证实其具备截屏接口和网络能力，未观测到键鼠钩子、浏览器凭据读取等行为。
- 不能把 443 端口上的 POST 描述为 TLS 加密信道；网络监控捕获到的是明文 HTTP 请求。
- 不能把动态环境中新增的 WinDivert1.3/PROCMON25 服务归因于样本；这些是分析设施自身引入的组件，样本未创建服务。
- 不能在缺乏厂商引擎/家族命名佐证的情况下把家族名当作确定结论；当前家族名为基于模块路径与活动标识的候选。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `8b8a02c8e00d7c134b7ac0cc40ab52b5ebe43d3b58911cf0f672897e17551da9`） |

**局限与待验证**

1. 文件系统行为未完整采集（系统调用级跟踪产物未随本次分析包归档），未观测到实际落盘文件；%TEMP%\box-%d-%d.dat 仅为二进制内格式串，不能据此断言已创建文件。
2. 未观测到持久化、提权、凭据窃取、键盘记录等行为：注册表 Run 键与服务列表前后一致，且无子进程。
3. 网络监控只回放默认响应，未取得真实 C2 响应体，指令通道与远程控制命令集未能还原。
4. 上传的 1259 字节负载在流量中为密文，未解密，无法确认其内容是屏幕图像、系统信息或其他数据。
5. 家族归属缺少厂商引擎/公开情报交叉验证，family 为候选名；活动标识 bf5eea7eb9dd0adade73f83a0970f1eb 可作为检索/关联线索。
6. 动态环境对虚拟化痕迹做了宿主侧预处理，样本自身是否内置反虚拟化/反调试逻辑未能静态证实（字符串被混淆/加密）。

## 证据索引

<details>
<summary>展开 21 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:57cc08dbaa` | 样本分诊 | 原始样本哈希/分段熵/加壳评分 0.85 |
| `ref:d1a7120601` | PE 结构解析 | PE64 头/段表/数据目录，UPX0/UPX1 为 W^X |
| `ref:8e548b8a3e` | 导入表解析 | 仅 KERNEL32 的 4 个导入，imphash 6ed4f5f04d62b18d96b26d6db7c18840 |
| `ref:d645e22f9b` | unpack.detect | 判定 UPX 加壳（confidence 0.9） |
| `ref:5fd6e05df2` | unpack.auto | 自动 OEP 定位超预算，后续以自行仿真完成解包 |
| `ref:e02c3bff92` | 字符串提取 | 原始加壳样本字符串（Go build ID、runtime 片段） |
| `ref:712014f3fd` | dyn.run | 仿真运行越过 UPX 桩进入 Go 运行时（pc 0x472add 起） |
| `ref:df8afade51` | 动态分析平台 | 真实动态：单进程引爆、内存转储、时间线与网络产物 |
| `ref:4ff1e3f9fb` | PE 结构解析 | 内存转储的解包 PE（3,727,266 字节，56 个导入 DLL） |
| `ref:8d2d9071fc` | PE 结构解析 | 被注入原生模块（基址 0x140000000，4 节） |
| `ref:1c24598b39` | 字符串提取 | 被注入模块字符串（含活动标识与驱动/接口名） |
| `ref:b9bb13f7b1` | 导入表解析 | 解包 PE 导入面（Go 运行时 API 集合，imphash eed0c0f0bfab67fc8a46397a2961c0c3） |
| `ref:ca6149b667` | 密码学常量识别 | AES 正/逆 S-box 与 SHA-256 轮常量 |
| `ref:bbef417c14` | decompile.symbols | 对解包 PE 的函数识别（无 Go 符号，函数以地址呈现） |
| `ref:8aa62d116d` | evidence.record | Go buildinfo/pclntab 解析（module BlueWorksLabs、garble 函数名、入口 rva 0x72380） |
| `ref:43cb34267d` | evidence.record | 自行仿真解 UPX 的过程与高熵块定位 |
| `ref:eb9eaee973` | evidence.record | 被注入模块内活动标识/到期日定位及指针引用 |
| `ref:23d991c996` | evidence.record | 网络监控日志解析：3 次 POST、tag/exp/hwid、multipart 上传、6 字节请求 |
| `c2_evidence:0f68bebc` | 连接证据提取 | 动态网络监控记录到 1 次到 sy3theo[.]tattoo:443 的连接尝试；未捕获完整会话 |
| `telemetry:0f68bebc` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 116 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 22 条 |
| `etw:0f68bebc:3656` | 进程事件监控 | 短命进程事件：0f68bebc56a491a29e49ee246b0ac47fbe9092507fbd75fcfaed88d7854eaed5.exe（pid 3656；MD5=D1C23949BF4FF61BFAEF0A83FC4D39AD,SHA256=0F68BEBC56A491A29E49EE246B0AC47FBE9092507FBD75FCFAED88D7854EAED5,IMPHASH=00000000000000000000000000000000） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
