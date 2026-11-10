---
title: "恶意样本分析：Unattributed Themida-packed fake installer（other · iso · ca8e5a8d）"
published: 2026-11-09
draft: false
description: "恶意（置信度低）：Unattributed Themida-packed fake installer · dropper/loader · 难度 hard · 静态反编译（动态执行未取得运行时行为）"
tags: ["dropper", "loader"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed Themida-packed fake installer**（存疑） · 置信度 **低**
> 
> 别名：S8035FGRD_SW02CMIP_EDCIP、Blur Interactive fake installer
> 
> 该 ISO9660 镜像是一个投放容器，其 README 明确诱导受害者绕过 Windows SmartScreen 警告。镜像内唯一的可执行文件是一个未签名的 64 位 GUI 程序，会请求管理员权限，受 Themida 保护（.themida W^X 段、熵 7.96 的 .boot、仅 1 个导入），带有伪造的发布者/版本元数据与 2088 年的编译时间戳，并包含 rdtsc 计时检查、int 2Dh 与 cpuid 探测。仿真显示其 stub 在运行期解析 user32/advapi32/ntdll/shell32/shlwapi。这一组合符合加壳假安装包恶意加载器的特征，而与正常产品不符。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed Themida-packed fake installer** · 别名 S8035FGRD_SW02CMIP_EDCIP、Blur Interactive fake installer · _存疑_ |
| 置信度 | **低** |
| 行为类 | dropper · loader |
| 难度 | hard |
| 首次出现 | 2026-11-07 19:10:08 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ca8e5a8d645c1084d2eee77e146589cc6a28cb9616106f177b167630c444c97b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">ISO容器绕过MOTW</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">诱导放行安装包</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">请求管理员权限</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1548</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">加壳隐藏程序逻辑</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">入口字节自解密</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ca8e5a8d645c1084d2eee77e146589cc6a28cb9616106f177b167630c444c97b` |
| MD5 | _未记录_ |
| 大小 | 15,357,952 字节（14.6 MB） |
| 类型 | other · `iso` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. ISO容器绕过MOTW

`T1553.005` · 置信度 **高** · 静态

样本为 ISO9660 镜像；挂载后可看到 INSTALL0;1 与 README_1;1。从挂载镜像中打开的文件不携带 Mark-of-the-Web，因此附件/SmartScreen 警告被抑制。

> **证据**：ISO9660 根目录：INSTALL0;1 LBA 25，15,303,168 字节；README_1;1 LBA 7498，762 字节
> 
> **来源**：`ev-000009` · `ref:5a77ef5718`

### 2. 诱导放行安装包

`T1204.002` · 置信度 **高** · 静态

README_1;1 告知用户会出现 SmartScreen 警告，并指示依次点击“More Info”与“Run Anyway”，声称该未签名安装包因作者是小型非营利团队而安全。

> **证据**：README_1;1 文本：'click on "More Info", then "Run Anyway"'
> 
> **来源**：`ev-000009`

### 3. 请求管理员权限

`T1548` · 置信度 **高** · 静态

内嵌应用程序清单将 requestedExecutionLevel 设为 requireAdministrator，因此加壳载荷在用户同意后以提权方式运行。

> **证据**：清单资源类型 24 id 1：requestedExecutionLevel level="requireAdministrator"
> 
> **来源**：`ev-000010` · `ref:b942c4fa41`

### 4. 加壳隐藏程序逻辑

`T1027.002` · 置信度 **高** · 静态

可执行文件包含可写可执行的 .themida 段与熵 7.96 的 .boot 段（入口所在），导入表仅暴露 GetModuleHandleA，原始代码与字符串因此被隐藏。

> **证据**：.themida 特征 0xE0000080（RWX），.boot 熵 7.964 @ RVA 0x11B8000，导入仅 kernel32!GetModuleHandleA
> 
> **来源**：`ref:8de7d54bba` · `ref:8a582ea1ea` · `ref:6ce0a3570f` · `ref:32d9477fcc` · `ref:b942c4fa41`

### 5. 入口字节自解密

`T1140` · 置信度 **高** · 静态

.boot 中的入口 stub 在转移控制前执行逐字节解码循环（mov al,[rsi]; inc rsi; mov [rdi],al; add dl,dl; jne/jae），符合自解密壳 stub 的特征。

> **证据**：RVA 0x11B806F-0x11B80F6 入口解码循环；入口 VA 0x15B8058
> 
> **来源**：`ref:860f2fe816`

### 6. 运行时解析API

`T1027.007` · 置信度 **高** · 静态

在用户态仿真中，stub 调用 LoadLibraryA 加载 user32.dll、advapi32.dll、ntdll.dll、shell32.dll 与 shlwapi.dll，并调用 GetProcAddress 获取 SetLastError/GetLastError，在运行期解析 API 而非通过导入表。

> **证据**：仿真 API 轨迹：LoadLibraryA(user32.dll/advapi32.dll/ntdll.dll/shell32.dll/shlwapi.dll)、GetProcAddress(SetLastError/GetLastError)，位置 PC 0x13F59C1-0x13EDE50
> 
> **来源**：`ref:425ebe4b03` · `ref:05e4e95312`

### 7. 反调试计时检测

`T1622` · 置信度 **高** · 静态

镜像在未命名代码段与 .boot 段均包含基于 rdtsc 的计时检查与 int 2Dh 指令，用于检测调试器/单步执行。

> **证据**：unpack.antidebug：rdtsc @ RVA 0x32CFD 与 0x11EB43B；int 2Dh @ RVA 0x4C8EB 与 0x11D24B6
> 
> **来源**：`ref:acc8a9c0a2`

### 8. 探测虚拟化环境

`T1497.001` · 置信度 **高** · 静态

固定代码位置上的 cpuid 指令用于在载荷执行前进行虚拟机/调试器指纹识别。

> **证据**：cpuid @ RVA 0x1DC51（未命名代码段）与 0x11BC5E2（.boot）
> 
> **来源**：`ref:acc8a9c0a2`

### 9. 伪造厂商版本信息

`T1036.005` · 置信度 **高** · 静态

版本资源冒充某产品身份（'Blur Interactive'/'BlurSoftworks'、OriginalFilename S8035FGRD_SW02CMIP_EDCIP.exe、Copyright 2026），ProductName 为空，编译时间戳位于未来，且没有 Authenticode 签名。

> **证据**：VS_VERSIONINFO 字符串；PE 时间戳 0xDF4BF6AA；安全数据目录 RVA/size = 0
> 
> **来源**：`ev-000010` · `ref:11e093f984` · `ref:b942c4fa41`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `container` | `ISO9660 卷 'S8035FGRD_SW02CMIP_EDCIP_Secure'，包含 INSTALL0;1（PE64，15,303,168 字节）与 README_1;1（762 字节）` | 是 | 静态 |
| `install_privilege` | `requireAdministrator（内嵌清单）` | 是 | 静态 |
| `packer` | `Themida（.themida W^X 段、.boot 入口段、仅一个导入 GetModuleHandleA）` | 否 | 静态 |
| `original_filename` | `S8035FGRD_SW02CMIP_EDCIP.exe` | 是 | 静态 |
| `publisher_identity` | `CompanyName 'Blur Interactive'，LegalTrademarks 'BlurSoftworks'，ProductName 为空` | 否 | 静态 |
| `compile_timestamp` | `0xDF4BF6AA（解码为 2088-09-13，伪造/未来时间）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要指名具体恶意家族（如 Lumma、StealC、Vidar），也不要声称存在凭据/数据窃取：本次未恢复任何配置、窃密字符串、C2 或二阶段载荷。
- 不要声称存在任何 C2 主机、URL 或端口：.boot 载荷已加密，未见明文网络指标。
- 不要把文件偏移 0xA0FBD3 处的 TEA/XTEA delta 常量当作载荷配置加密的证据；它位于加壳区域内，可能属于保护器运行时。
- 尽管 README 声称其未签名只是因为作者是非营利团队，也不要据此判定该安装包为良性。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 未到达 Themida OEP：自动脱壳超出 500,001 条指令预算，用户态仿真在保护器 VM 内执行 8 次 API 调用后停止，载荷主体及其字符串仍处于加密状态。
2. 未恢复任何 C2、互斥体、安装路径、注册表键、服务或 campaign ID；相关字段有意留空，而非猜测填充。
3. 未进行真实沙箱引爆（纯静态档位）。结论依据是容器投放、身份/签名伪造、加壳与反分析代码，而不是观测到的数据外传。
4. 家族归属不确定；当前环境没有可用的厂商引擎或 YARA 匹配结果。
5. 仿真仅覆盖保护器/引导阶段；未观测到载荷层面的 API 行为（文件、注册表、网络）。

## 证据索引

<details>
<summary>展开 14 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000009` | evidence.record | ISO9660/Joliet parsing: volume label, two files (INSTALL0;1, README_1;1), README SmartScreen-bypass text |
| `ev-000010` | evidence.record | PE resource parsing: version info, requireAdministrator manifest, icon, forged timestamp, no signature |
| `ev-000005` | 字符串提取 | ISO string extraction: file names INSTALL0;1 / README_1;1, DOS stub, .themida/.idata section names |
| `ev-000006` | 密码学常量识别 | TEA/XTEA delta 0x9E3779B9 at offset 0xA0FBD3 (inside packed .boot region) |
| `ref:b942c4fa41` | PE 结构解析 | PE64 headers: 6 sections, entry 0x11B8058 in .boot, security directory 0, timestamp 3745914922 |
| `ref:8de7d54bba` | unpack.detect | Themida detection, confidence 0.9; emulate_to_oep strategy |
| `ref:8a582ea1ea` | 节表解析 | Section table and entropy: .themida RWX, .boot 7.964 |
| `ref:6ce0a3570f` | scan.entropy | Whole-file entropy 7.993; three high-entropy sections |
| `ref:32d9477fcc` | 导入表解析 | Single import kernel32!GetModuleHandleA, imphash a56f115ee5ef2625bd949acaeec66b76 |
| `ref:11e093f984` | 哈希与指纹 | MD5 8c6464501df15e894ea8d98feb9c9f39, SHA-256 627dc3ef0c80bac796aa8256847b0d6922c4eab38809da577e9d4ba554243260 |
| `ref:acc8a9c0a2` | unpack.antidebug | rdtsc, int 2Dh and cpuid probes at concrete RVAs in code and .boot |
| `ref:860f2fe816` | disasm.function | Entry stub byte-wise decode loop at RVA 0x11B806F |
| `ref:425ebe4b03` | dyn.run | Emulation API trace: LoadLibraryA/GetProcAddress runtime resolution |
| `ref:4f1f2c4ce0` | unpack.auto | Automatic unpacking failed at instruction budget; no OEP found |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
