---
title: "恶意样本分析：JLI launcher DLL loader（PE · exe · 8cd439c7）"
published: 2026-11-03
draft: false
description: "恶意（置信度低）：JLI launcher DLL loader · loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["JLI", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **JLI launcher DLL loader**（存疑） · 置信度 **低**
> 
> 别名：loader.dll、jli.dll sideload
> 
> 64 位 DLL（内部名 loader.dll）导出 Java 启动器接口 JLI_*；.rdata 与 .data 各嵌入一段约 207 KB / 211 KB 的 URL-safe base64 高熵数据；TLS 回调在入口前解码内嵌密钥常量并向线程 TLS 块写入状态；核心逻辑位于经跳转表平坦化的约 24 KB 函数并经导出 JLI_Launch 触发；代码含 IsDebuggerPresent、rdtsc、cpuid 检测。上述均由反编译与结构取证直接观察到；隔离动态环境中直接投放未观察到载荷执行，故动态行为证据有限。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **JLI launcher DLL loader** · 别名 loader.dll、jli.dll sideload · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader |
| 难度 | hard |
| 首次出现 | 2026-11-02 23:05:45 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/8cd439c7280a220a58cafe479982556ebe8581e53d953684f48a748e2b4b91bc/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装Java启动器导出</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">嵌入双段高熵载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">TLS回调预置密钥</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">反调试与时间检测</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">控制流平坦化</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `8cd439c7280a220a58cafe479982556ebe8581e53d953684f48a748e2b4b91bc` |
| MD5 | _未记录_ |
| 大小 | 725,504 字节（708.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装Java启动器导出

`T1036.005` · 置信度 **高** · 静态

DLL 内部名为 loader.dll，导出表 14 项，其中 7 个具名导出全部为 JLI_*（JLI_Launch 位于 rva 0x46765、JLI_MemAlloc 位于 rva 0x9F70 等），复制 Java jli.dll 的导出面，便于被 java.exe 或其他宿主按名加载/调用。

> **证据**：pe.exports: dll_name=loader.dll, JLI_Launch@rva 0x46765；序号 8–14 为重复的未具名导出
> 
> **来源**：`ref:727d61db92` · `ref:79c1212c90`

### 2. 嵌入双段高熵载荷

`T1027.009` · 置信度 **高** · 静态

.rdata 起始 rva 0x1A000 与 .data 起始 rva 0x6A000 各含一段 URL-safe base64 文本（276131 / 281785 字符），解码后分别为 207096 / 211338 字节、熵 7.993，无 MZ/PK 等结构签名，合计约占文件 58%，符合加密载荷或填充数据特征。

> **证据**：scan.crypto base64url 字母表@off 0x5D6DD；脚本解码 off 0x19200/0x68600 得熵 7.993
> 
> **来源**：`ref:4da3775715` · `ref:4e23308b34` · `ref:d92a09e617`

### 3. TLS回调预置密钥

`T1027` · 置信度 **高** · 静态

PE 的 TLS 回调数组（VA 0x180066C00）注册 tls_callback_0@0x1C70；该回调在进程 attach/detach 时调用 FUN_180001250，用立即数 0xCD366C7249B2043C 起始、每轮递增 0x8AB57BE74F48E1FB 的滚动 XOR 解码 .rdata 0x5E448 的 7 个 qword 及 0x5E494 的 4 个 short，写入当前线程 TLS 块并把 TLS+0x53 置 1。

> **证据**：tls_callback_0@0x1C70 -> FUN_180001250@0x1250；TLS AddressOfCallbacks=0x180066C00（数组首项 0x180001C70）
> 
> **来源**：`ref:9a429899e1` · `ref:52ae289ec2` · `ref:85f908a6ff`

### 4. 反调试与时间检测

`T1622` · 置信度 **高** · 静态

导入 IsDebuggerPresent（运行时在 0xFA83 调用），代码段另含 rdtsc（rva 0x4BBD）与 cpuid（rva 0xC1C2）指令，用于时间差测量与虚拟化/调试环境探测。

> **证据**：unpack.antidebug: IsDebuggerPresent(import), rdtsc@rva 0x4BBD, cpuid@rva 0xC1C2
> 
> **来源**：`ref:14fafe638c` · `ref:7b8758449e`

### 5. 控制流平坦化

`T1027` · 置信度 **中** · 静态

核心函数 FUN_18000330A（rva 0x330A–0x92D5，约 24 KB）以数据段 0x5ED48 等处的 32 位偏移跳转表实现状态机式间接跳转，被 7 处调用（含 JLI_Launch 内 0xB6A1/0xB6B3）；函数内只有 GetProcessHeap/HeapAlloc 为直接 IAT 调用，其余功能通过运行时解析完成。

> **证据**：decompile FUN_18000330A：jmp [&LAB_180005D8A + *(int*)(&DAT_18005E748 + 0x600)]；调用点 0xB6A1/0xB6B3 等 7 处
> 
> **来源**：`ref:79c1212c90` · `ref:e744ee88b4`

### 6. 构造伪模块FkPlX.dll

`T1620` · 置信度 **中** · 静态

FUN_18000B6BF 分配 0x400 字节对象并写入宽字符模块名 "FkPlX.dll"（.rdata rva 0x5E480）及类区段描述字段（Characteristics 0x140012、大小 0x412、名称长度 0x14），用于在内存中登记一个不对应磁盘文件的模块；该函数在平坦化主函数内 0x740D 被调用。

> **证据**：FUN_18000B6BF@0x18000B6BF；utf16 'FkPlX.dll' @off 0x5D680；调用点 0x18000740D
> 
> **来源**：`ref:ce2a42d8ef` · `ref:dc5bfd14d7`

### 7. 仅经导出触发主逻辑

`T1574.002` · 置信度 **高** · 静态

DllMain（entry 0xBC10 -> FUN_18000BAD0）只执行 MSVC CRT 初始化；恶意主逻辑由导出 JLI_Launch（0xB6AD）调用 FUN_18000330A 触发，因此把该 DLL 当可执行文件直接运行或仅加载不会执行载荷。

> **证据**：decompile FUN_18000BAD0/FUN_18000BA70（仅 CRT init）；JLI_Launch -> FUN_18000330A
> 
> **来源**：`ref:5c1ed9628c` · `ref:0edda4837f` · `ref:79c1212c90`


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
| `payload_blob_1` | `.rdata rva 0x1A000：276131 字符 URL-safe base64，解码 207096 字节，熵 7.993（无 MZ/PK 头）` | 是 | 静态 |
| `payload_blob_2` | `.data rva 0x6A000：281785 字符 URL-safe base64，解码 211338 字节，熵 7.993（无 MZ/PK 头）` | 是 | 静态 |
| `fake_module_name` | `FkPlX.dll` | 否 | 静态 |
| `key_material_source` | `TLS 回调 FUN_180001250 用滚动 XOR 解码 .rdata rva 0x5E448 的 7 个 qword 与 0x5E494 的 4 个 short` | 是 | 静态 |
| `encryption_algo` | `unknown（非标准 AES/SHA/CRC 常量；两段载荷解码后仍高熵，算法未还原）` | 是 | 静态 |
| `export_interface` | `JLI_CmdToArgs,JLI_GetStdArgc,JLI_GetStdArgs,JLI_InitArgProcessing,JLI_Launch,JLI_MemAlloc,JLI_MemFree` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得据此判定为勒索软件或 wiper：未发现文件加密、卷影副本删除或勒索提示字符串。
- 不得声称存在已验证的 C2 域名或 IP：动态沙箱未观察到样本自身的外联，网络日志中的域名均来自 Windows 系统组件。
- 不得声称已完成落地或持久化：未观察到文件写入、注册表修改、服务或计划任务创建。
- 不得把两段 base64 块直接等同于已知家族特征：解码结果为高熵不可识别数据，未还原出二级 PE 或配置。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本是 DLL，主逻辑位于导出 JLI_Launch 之后；隔离环境按文件直接执行仅触发 DllMain/CRT，未获得载荷执行行为，故 reproduced=false。
2. 两段 base64 数据解码后熵 7.99 且无 PE/压缩包签名，静态阶段未能还原二级载荷或配置，加密算法未知。
3. 核心逻辑经控制流平坦化与跳转表间接跳转，反编译仅覆盖入口分派，未能完整还原语义。
4. 未观察到 C2、落地路径、互斥体等运行期 IOC，相关字段留空而非推测。
5. 动态时间线中出现的 svchost / MicrosoftEdgeUpdate / SIHClient 流量为系统组件行为，与本样本无关。

## 证据索引

<details>
<summary>展开 19 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:462ef6f66c` | 样本分诊 | 哈希/imphash/分段熵/加壳评分：packing.score=0，0 异常，3 个导入 DLL |
| `ref:d92a09e617` | PE 结构解析 | AMD64 DLL，image_base 0x180000000，entry rva 0xBC10，6 节，TLS/EXPORT/IMPORT 目录 |
| `ref:727d61db92` | pe.exports | dll_name=loader.dll，14 项导出，7 个 JLI_* 具名导出 |
| `ref:7b8758449e` | 导入表解析 | 3 个 DLL / 91 符号，含 VirtualProtect、LoadLibraryA、GetProcAddress、CreateFileW、WriteFile、IsDebuggerPresent、GetSystemTimes |
| `ref:ead6517159` | 字符串提取 | 字符串扫描：loader.dll、JLI_* 导出名、FkPlX.dll、base64 字母表；未发现明文 URL/路径 |
| `ref:79c1212c90` | decompile.function | JLI_Launch@0xB6AD 仅调用 FUN_18000330A(0x330A) |
| `ref:52ae289ec2` | decompile.function | FUN_180001250：滚动 XOR 解码 .rdata 0x5E448 的 7 个 qword 与 0x5E494 的 4 个 short 并写入 TLS |
| `ref:9a429899e1` | decompile.function | tls_callback_0@0x1C70：DLL_PROCESS_ATTACH/DETACH 时调用 FUN_180001250 |
| `ref:ce2a42d8ef` | decompile.function | FUN_18000B6BF：构造含宽字符名 FkPlX.dll 的 0x400 字节模块/区段描述结构 |
| `ref:5c1ed9628c` | decompile.function | FUN_18000BAD0（DllMain）：仅走 CRT 初始化分支 |
| `ref:14fafe638c` | unpack.antidebug | IsDebuggerPresent 导入、rdtsc@0x4BBD、cpuid@0xC1C2 |
| `ref:4da3775715` | 密码学常量识别 | URL-safe base64 字母表 @off 0x5D6DD |
| `ref:4e23308b34` | script | 解码两段 base64：276131→207096 字节、281785→211338 字节，熵均 7.993，无 MZ/PK 签名 |
| `ref:85f908a6ff` | script | 解析 TLS 目录：AddressOfIndex rva 0xB0B94，回调数组首项 VA 0x180001C70 |
| `ref:e744ee88b4` | script | 静态扫描 IAT 调用点：平坦化函数内仅 GetProcessHeap/HeapAlloc 为直接导入调用 |
| `ref:d1f3c8e846` | dyn.run | 仿真仅执行 CRT 初始化，31 个 API，无文件/网络/注册表行为 |
| `ref:7f741255b8` | unpack.detect | 未识别到已知壳，packed=false |
| `ref:2fdf2e5dfb` | 动态分析平台 | 隔离环境投放：532 次轮询、0 个新进程候选、无样本外联，事后回滚 |
| `ref:dc5bfd14d7` | script | 提取 UTF-16 字符串：FkPlX.dll @off 0x5D680，其余为 CRT 区域名/API 集名 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
