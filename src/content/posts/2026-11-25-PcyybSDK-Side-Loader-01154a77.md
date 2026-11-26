---
title: "恶意样本分析：PcyybSDK Side-Loader（other · iso · 01154a77）"
published: 2026-11-25
draft: false
description: "恶意（置信度中）：PcyybSDK Side-Loader · loader · 难度 hard · 纯静态分析"
tags: ["PcyybSDK Side", "loader"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **PcyybSDK Side-Loader**（存疑） · 置信度 **中**
> 
> 别名：pcyyb_sdk_dll.dll sideloader、Androws SDK DLL side-loader、Tencent YYB SDK impersonation loader
> 
> ISO 内放置了腾讯有效签名的 Androws 扩展宿主 EXE，以及一个与之同名、被宿主导入表静态引用的 pcyyb_sdk_dll.dll。该 DLL 的 .text/.rdata/.data 均无原始数据，约 4 MB 有效载荷集中在高熵 .TEXT2（熵 7.98），入口点与 TLS 目录位于加密段内，入口引导序列随后跳入含直接 syscall 的加载器；其版本信息为 Setup 2.6.9[.]1 / Company .T.，签名主体为自签名 CN=BenchByte AI，而宿主 EXE 的腾讯签名摘要校验通过。合法腾讯宿主 + 非腾讯签名的加壳同名 DLL 构成明确的 DLL 侧加载执行链，故判定为恶意加载器；加密载荷未解出，家族暂不能归入既有命名。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **PcyybSDK Side-Loader** · 别名 pcyyb_sdk_dll.dll sideloader、Androws SDK DLL side-loader、Tencent YYB SDK impersonation loader · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader |
| 难度 | hard |
| 首次出现 | 2026-11-25 11:51:14 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/01154a7727e5ca63054637cf0145aedd60be752288a2af7006bac5a9a8487456/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">侧加载腾讯签名宿主</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">仿冒腾讯SDK元数据</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">加密四兆载荷加壳</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">入口藏于加密段</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">直调系统调用</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `01154a7727e5ca63054637cf0145aedd60be752288a2af7006bac5a9a8487456` |
| MD5 | _未记录_ |
| 大小 | 6,813,696 字节（6.5 MB） |
| 类型 | other · `iso` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 侧加载腾讯签名宿主

`T1574.002` · 置信度 **高** · 静态

ISO 同时放置腾讯有效签名的 Androws 扩展 EXE 和同名 pcyyb_sdk_dll.dll；宿主导入表静态引用该 DLL 的 34 个函数，启动时会优先从自身目录加载被替换的 DLL，形成 DLL 侧加载执行链。

> **证据**：宿主 EXE 导入表 pcyyb_sdk_dll.dll 34 项（IAT rva 0xBD4E0 起）；ISO 根目录同时存在 EXE 与 PCYYB_SDK_DLL.DLL
> 
> **来源**：`ref:b17614d318` · `ref:732ac153bb`

### 2. 仿冒腾讯SDK元数据

`T1036.005` · 置信度 **高** · 静态

被侧加载 DLL 导出 pcyyb_sdk_dll.dll 的 129 个 SDK 接口（LaunchApp、UpdateEngine、ReportDomainSnifferResult 等），但版本信息写作 Setup / 2.6.9[.]1 / Company .T. / Copyright 2026，与其声称的腾讯 SDK 身份不符，属名称与元数据伪装。

> **证据**：导出表 129 项 pcyyb API；VS_VERSION_INFO FileDescription=Setup、FileVersion=2.6.9[.]1、CompanyName=.T.
> 
> **来源**：`ref:497453e82b` · `ref:8c2d4c82a9`

### 3. 加密四兆载荷加壳

`T1027.002` · 置信度 **高** · 静态

.text/.rdata/.data/.pdata 等段 RawPtr/RawSize 均为 0，有效内容集中在 .TEXT2（文件偏移 0x1200、RawSize 0x3DBC00，约 4 MB）且段熵 7.98，符合加壳/加密载荷布局。

> **证据**：.TEXT2 VA 0x42E000 RawPtr 0x1200 RawSz 0x3DBC00 entropy 7.98；其余代码/数据段 RawSz=0
> 
> **来源**：`ref:174649b7ba` · `ref:375efddfb9`

### 4. 入口藏于加密段

`T1620` · 置信度 **中** · 静态

PE 入口 0x6B231B 与 TLS 目录 0x6B3530 均落在高熵 .TEXT2 内；入口处为 push rbp / pushfq / movabs / call 的引导序列并跳向 0x1807BFD6D，说明需先解密或映射后再转移执行，不是常规编译器产物。

> **证据**：AddressOfEntryPoint=0x6B231B；TLS=0x6B3530；0x6B231B: push rbp; pushfq; movabs rbp,0x8C90B9B7BB1F399A; call 0x1807BFD6D
> 
> **来源**：`ref:39b6acc40c` · `ref:50e2e97b14`

### 5. 直调系统调用

`T1106` · 置信度 **中** · 静态

引导路径在 0x1807BFD6D 附近执行 0F 05（syscall）并配合 pushfq/popfq 与 rsp 重排，直接进入内核调用而非经过常规 Win32 API，具备规避用户态钩子的加载器特征。

> **证据**：0x1807BFD6D：shr bp,0x1B; lea rbp,[...]; push [rsp+8]; popfq; lea rsp,[rsp+0x10]; call 0x1807F0961; syscall
> 
> **来源**：`ref:c75ce883b9`

### 6. 自签名伪装发行者

`T1553.002` · 置信度 **高** · 静态

该 DLL 的 Authenticode 摘要与签名内容一致（sha256 A6A4CDD5…），但签发主体为自签名证书 CN=BenchByte AI（带 2026-11-25 时间戳），并非腾讯；同包宿主 EXE 的腾讯签名摘要（9F0FAFBB…）校验通过，签名不一致集中于被替换的 DLL。

> **证据**：DLL SpcIndirectData sha256=A6A4CDD5CE9578AD…，cert subject CN=BenchByte AI；EXE SpcIndirectData sha256=9F0FAFBB7E70B797…，subject=Tencent Technology (Shenzhen) Company Limited
> 
> **来源**：`ref:6ae9aeb92f` · `ref:df493cb918` · `ref:be19566be3`

### 7. 宿主持久化续装

`T1547.001` · 置信度 **中** · 静态

宿主 EXE 字符串包含 RunOnce 键、TencentInstallState/TencentInstallResume 值以及 ms-windows-store://DownloadsAndUpdates?resumeInstall=true 续装 URL，并创建 Local\SM0:… 互斥量、读写 SOFTWARE\Tencent\Androws；这些是腾讯宿主的安装恢复逻辑，本次未发现加密载荷自身的持久化。

> **证据**：UTF-16 字符串：SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce、TencentInstallState、TencentInstallResume、rundll32 url,OpenURL ms-windows-store://…；Local\SM0:%lu:%lu:%hs
> 
> **来源**：`ref:79ad280e3f` · `ref:7c01c42ab2`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**互斥体**

- `Local\SM0:%lu:%lu:%hs`

**落地路径**

- `pcyyb_sdk_dll.dll（与宿主 EXE 同目录侧加载）`

**注册表**

- `SOFTWARE\Tencent\Androws（宿主组件；根键静态未解析）`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce（宿主续装；根键静态未解析）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `loader_technique` | `DLL side-loading：合法腾讯 Androws EXE 从同目录加载被替换的 pcyyb_sdk_dll.dll` | 是 | 静态 |
| `imitated_module` | `pcyyb_sdk_dll.dll（腾讯 PC 应用宝 / Androws SDK）` | 是 | 静态 |
| `payload_section` | `.TEXT2，RawSize 0x3DBC00（约 4 MB），熵 7.98` | 是 | 静态 |
| `payload_encrypted` | `true（高熵，未解出）` | 是 | 静态 |
| `entry_point` | `0x6B231B（位于 .TEXT2 加密区内）` | 是 | 静态 |
| `packer` | `未知自定义 PE 加载器（直接 syscall 引导代码）` | 否 | 静态 |
| `encryption_algo` | `未恢复` | 否 | 静态 |
| `publisher_dll` | `CN=BenchByte AI（自签名）` | 否 | 静态 |
| `publisher_host` | `Tencent Technology (Shenzhen) Company Limited（Authenticode 摘要校验通过）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要仅凭包内 EXE 的腾讯有效签名判定整个 ISO 合法：签名只覆盖宿主 EXE，同名 DLL 的签发主体为自签名 BenchByte AI。
- 不要把 yybadaccess.3g[.]qq[.]com / yybadaccess[.]sparta[.]html5[.]qq[.]com 当作恶意 C2：它们是宿主组件的腾讯接入/遥测域名，加密载荷尚未解出，没有恶意回连证据。
- 不要把该 DLL 归入 ValleyRAT、AsyncRAT 等具体家族：4 MB 加密载荷未解密，无法与既有家族比对。
- 不要声称已观察到真实网络通信、注册表写入或持久化：本次为纯静态分析，未执行样本。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 纯静态分析，无隔离动态执行通道；未观察样本运行时的网络、注册表或进程行为。
2. 约 4 MB 的 .TEXT2 加密载荷未完成内存解密/脱壳，未取得载荷的 C2、配置或家族特征。
3. 被侧加载 DLL 的签名主体为自签名 CN=BenchByte AI（2026-11-25 时间戳），无法在离线环境核验其真实身份与签发来源。
4. 宿主 EXE 内的腾讯域名、RunOnce 与注册表字符串属于安装/遥测逻辑，尚未证实可被载荷滥用为持久化或回连。
5. 未联网与厂商情报或公开沙箱报告交叉验证，家族判定仅基于本地静态证据。

## 证据索引

<details>
<summary>展开 15 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:ee5c817bc6` | 样本分诊 | 宿主 EXE 分诊：无壳信号，7 个导入 DLL/184 符号，SHA256 52c199ff… |
| `ref:b17614d318` | 导入表解析 | 宿主 EXE 导入 pcyyb_sdk_dll.dll 的 34 个 SDK 函数 |
| `ref:7c01c42ab2` | pe.version | 宿主版本信息：Company=Tencent，Product/InternalName=Androws，FileVersion=1.1001.86.0 |
| `ref:732ac153bb` | iso.extract | ISO9660 文件清单与逐文件 SHA256：EXE、PCYYB_SDK_DLL.DLL 及 VC 运行库 |
| `ref:497453e82b` | PE 结构解析 | DLL 段表/版本/导入/129 个导出：Company=.T.，FileDescription=Setup，Version=2.6.9[.]1 |
| `ref:174649b7ba` | PE 结构解析 | DLL 段原始布局：代码/数据段 RawSz=0，.TEXT2 RawSz=0x3DBC00，熵 7.98 |
| `ref:375efddfb9` | unpack.detect | DLL 判定 packed，信号：可执行段 .TEXT2 高熵 7.98 |
| `ref:39b6acc40c` | PE 结构解析 | DLL 入口 0x6B231B、TLS 0x6B3530、ImageBase 0x180000000 |
| `ref:50e2e97b14` | disasm.function | 入口 0x6B231B 引导序列：push rbp/pushfq/movabs/call 0x1807BFD6D |
| `ref:c75ce883b9` | disasm.function | 0x1807BFD6D 加载器路径含 syscall（0F 05）与栈重排 |
| `ref:6ae9aeb92f` | cert.parse | 证书主体：EXE=Tencent Technology (Shenzhen)；DLL=CN=BenchByte AI（自签名） |
| `ref:df493cb918` | cert.parse | DLL SpcIndirectData sha256=A6A4CDD5…，与文件 Authenticode 摘要一致 |
| `ref:be19566be3` | cert.parse | EXE Authenticode sha256=9F0FAFBB…，与签名内容摘要一致，腾讯签名有效 |
| `ref:79ad280e3f` | 字符串提取 | 宿主 UTF-16 字符串：腾讯访问域、SOFTWARE\Tencent\Androws、RunOnce、互斥量模板 |
| `ref:8c2d4c82a9` | 字符串提取 | DLL 导出/导入与字符串面：129 个 pcyyb SDK 名称、BeaconClient 导出、证书主体 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
