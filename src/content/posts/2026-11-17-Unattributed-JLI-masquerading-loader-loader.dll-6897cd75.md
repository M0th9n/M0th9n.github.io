---
title: "恶意样本分析：Unattributed JLI-masquerading loader (loader.dll)（PE · exe · 6897cd75）"
published: 2026-11-17
draft: false
description: "恶意（置信度低）：Unattributed JLI-masquerading loader (loader.dll) · loader/implant · 难度 hard · 静态反编译（动态执行未取得运行时行为）"
tags: ["loader", "implant", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed JLI-masquerading loader (loader.dll)**（存疑） · 置信度 **低**
> 
> 别名：jli.dll hijack loader、loader.dll UPX loader
> 
> 样本是 AMD64 DLL（PE Characteristics=DLL、入口为 DllMain），被 UPX 3.x 加壳后以 .exe 扩展名分发；还原后的内部 DLL 名为 loader.dll，导出名与 Java 启动库 jli.dll 完全一致，但 JLI_Launch 等导出全部是空壳桩，只把控制权交给一个使用常量混淆与查表间接跳转的内部分发函数并返回 0；.data 起始处存放 226,235 字符 base64url 编码、解码后 169,676 字节的高熵数据（熵 7.994），全文件没有任何明文地址、路径或命令。加壳 + 冒充运行时模块 + 加密载荷 + 控制流混淆的组合符合「以 DLL 侧载方式加载后续加密载荷」的加载器形态。由于载荷未解密、DLL 也未被宿主加载，其最终功能尚不能确定，故置信度为中高。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed JLI-masquerading loader (loader.dll)** · 别名 jli.dll hijack loader、loader.dll UPX loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · implant |
| 难度 | hard |
| 首次出现 | 2026-11-13 20:00:27 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/6897cd75ff8b2a4063aa496851af05101ef9d149ac22d3e74df44f5c0f03670a/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX 加壳改名分发</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">伪装 jli.dll 导出</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">导出全部是空壳桩</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">内置 169KB 加密载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">常量混淆的查表跳转</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `6897cd75ff8b2a4063aa496851af05101ef9d149ac22d3e74df44f5c0f03670a` |
| MD5 | _未记录_ |
| 大小 | 441,344 字节（431.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. UPX 加壳改名分发

`T1027.002` · 置信度 **高** · 静态

样本为 441,344 字节的 AMD64 DLL（PE Characteristics=DLL、子系统 GUI、无签名），段表仅有 UPX0/UPX1/UPX2，UPX1 熵 7.999、导入仅 5 个符号；用 UPX 解包器可完整还原出 643,584 字节、包含 .text/.rdata/.data/.pdata/.tls/.reloc 的正常映像，说明外层只是压缩壳。

> **证据**：scan.triage 段表 UPX0/UPX1/UPX2，UPX1 熵 7.999；0x6B8B0 起导入表文件偏移 0x6B890 起的导入表仅 LoadLibraryA/GetProcAddress/VirtualProtect/WaitOnAddress/GetFocus；解包后文件 643,584 字节
> 
> **来源**：`ev-000008` · `ev-000004` · `ev-000002` · `ref:a13c91742b` · `ref:a9378dbeaf`

### 2. 伪装 jli.dll 导出

`T1036.005` · 置信度 **高** · 静态

还原后的 DLL 内部名为 loader.dll，导出表含 7 个具名导出，与 Java 启动库 jli.dll 完全同名（JLI_Launch、JLI_GetStdArgs、JLI_GetStdArgc、JLI_CmdToArgs、JLI_InitArgProcessing、JLI_MemAlloc、JLI_MemFree），其后还有 7 个无名序数导出（8-14）重复指向同一批 RVA——正规 jli.dll 不会出现匿名重复导出。

> **证据**：导出目录 rva 0x617F8；导出名表 file off 0x6B99E: 'loader.dll'、'JLI_CmdToArgs'、'JLI_GetStdArgc' 等；序数 8-14 无名
> 
> **来源**：`ref:f1950f967f` · `ev-000011`

### 3. 导出全部是空壳桩

`T1027` · 置信度 **高** · 静态

JLI_Launch(0x18000AECF)、JLI_GetStdArgs(0x180001982)、JLI_MemAlloc(0x180009E22)、JLI_MemFree(0x180009CE8)、JLI_CmdToArgs(0x180009CFD)、JLI_GetStdArgc(0x18000BC83) 等导出均只做一次状态判断后调用同一内部函数 0x180001A7D 并 return 0；真实的 JVM 加载、命令行解析、内存分配逻辑完全不存在，导出表仅作为被宿主调用时触发内部流程的入口。

> **证据**：decompile JLI_MemAlloc/JLI_MemFree/JLI_CmdToArgs/JLI_GetStdArgc 皆为 FUN_180001a7d; return 0;
> 
> **来源**：`ev-000022` · `ev-000032` · `ev-000033` · `ev-000034` · `ev-000035`

### 4. 内置 169KB 加密载荷

`T1027.013` · 置信度 **高** · 静态

.data 起始（rva 0x64000）是 226,235 字符的 URL-safe base64 串，解码得到 169,676 字节：熵 7.994、无重复 16 字节块、k=1..16 的 IOC 均约 0.004，属加密/压缩数据而非明文；全文件未出现任何 URL、文件路径或命令。紧随其后是 210 条 16 字节记录 (rva|0x80000000, 1, size, 0)，连续覆盖 rva 0x1B000-0x9B3BB 的 .rdata/.data，形似运行时映射/解密区段表。

> **证据**：file off 0x62400 起 226,235 字符 base64url；解码 169,676 字节、熵 7.994；0x997F0 起 210 条区段记录
> 
> **来源**：`ev-000040` · `ev-000021` · `ref:a25f4529f6` · `ref:6aac9a82d6`

### 5. 常量混淆的查表跳转

`T1027` · 置信度 **中** · 静态

分发函数 0x180001A7D 以 (&LAB_180001FAC + 表项) 的方式间接跳转，表项落在 .rdata 0x59294；0x180001FAC 之后的代码反复使用 0x3966C6xx / 0x6CEF76xx 系列常量（0x3966C6D3、0x3966C6F2、0x6CEF76BE 等）与 movsxd/jmp rax 组合做分发，反编译大量报 Could not recover jumptable，属控制流平坦化/自定义解释器。

> **证据**：0x180001A7D: jmp &LAB_180001FAC + *(int*)(&DAT_180059294+0x27C/0x5A0)；0x180001FEC: xor ebx,0x3966C6D3；0x180002206 起同样模式
> 
> **来源**：`ev-000024` · `ref:5c2503b55a` · `ref:390147662c` · `ev-000037`

### 6. TLS 回调参与初始化

`T1497.001` · 置信度 **中** · 静态

PE 的 TLS 目录（rva 0x5EDC0）登记了回调 0x180001A60（tls_callback_0），在 DLL_PROCESS_ATTACH/DETACH 时执行 0x1800018A0，向线程 TLS 模板块 +0x08..+0x25 写入一批常量并把 +0x22 置 1；导出函数随后读取 TLS+0x40、+0x78 处的 32 位标记值决定分支，形成与常规静态视角隔离的早期执行路径。

> **证据**：TLS 目录 rva 0x5EDC0；tls_callback_0 @0x180001A60 → FUN_1800018A0 写 +0x22=1；JLI_Launch 比较 TLS+0x78==0x8CE61C75
> 
> **来源**：`ev-000027` · `ev-000029` · `ref:f713c34dbf` · `ev-000022`

### 7. 探测前台窗口与进程时间

`T1010, T1497.003` · 置信度 **中** · 静态

JLI_Launch 在 TLS 标记命中后调用 GetForegroundWindow / GetFocus / GetWindowRect；JLI_GetStdArgs 调用 GetCurrentProcess / GetThreadId / GetProcessTimes / FileTimeToSystemTime。查询结果被丢弃，实际只用于改变后续分支或填充结构体，具备环境与时间侧信道探测特征（无人值守环境通常没有前台窗口）。

> **证据**：JLI_Launch @0x18000AECF: GetForegroundWindow/GetFocus/GetWindowRect；JLI_GetStdArgs @0x180001982: GetProcessTimes/FileTimeToSystemTime
> 
> **来源**：`ev-000022` · `ev-000023`

### 8. 按宿主侧载形态设计

`T1574.002` · 置信度 **中** · 静态

文件以 .exe 扩展名落地，PE 却是 DLL（入口 DllMain、DllMain 只做 CRT 初始化），内部名 loader.dll 并导出宿主期望的 jli 接口；只要宿主进程（如 java.exe）加载同目录的这个模块并调用任一导出，就会触发 0x180001A7D 的内部流程，符合 DLL 侧载/代理加载的投递形态。

> **证据**：PE Characteristics=DLL + 导出名与 jli.dll 一致 + 全部导出桩转发 0x180001A7D + DllMain 仅调用 __DllMainCRTStartup
> 
> **来源**：`ref:d0eee70122` · `ref:f1950f967f` · `ev-000024` · `ev-000025` · `ev-000030`


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
| `container` | `UPX 3.x 壳（段 UPX0/UPX1/UPX2，UPX1 熵 7.999），可还原为 643,584 字节、6 段的原始 DLL` | 是 | 静态 |
| `internal_dll_name` | `loader.dll` | 是 | 静态 |
| `masquerade_as` | `jli.dll（Java 启动库）导出接口` | 是 | 静态 |
| `embedded_payload` | `URL-safe base64 串，文件偏移 0x62400（rva 0x64000），226,235 字符 → 169,676 字节` | 是 | 静态 |
| `payload_encryption` | `未知自定义/流式加密（熵 7.994；169,676 非 16 字节整数倍；仅检出 base64url 字母表，无 AES/SHA/RC4 常量）` | 是 | 静态 |
| `runtime_range_table` | `file off 0x997F0 起 210 条 16 字节记录 (rva\|0x80000000, 1, size, 0)，连续覆盖 rva 0x1B000-0x9B3BB 的 .rdata/.data` | 否 | 静态 |
| `c2_hosts` | `-` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能据此判定具体恶意功能（远控/窃密/下载/勒索等）：169,676 字节载荷尚未解密，样本内也没有网络、注册表或进程创建相关导入。
- 不能把 JLI_* 导出名或 loader.dll 名称当作「样本是 Java 程序」或家族归属的证据：二进制中没有任何 jvm.dll、JNI、java 相关字符串，导出接口可被伪造。
- 不能声称已观测到 C2、外联或持久化：真实动态沙箱中没有任何与该样本相关的网络请求、子进程或注册表写入。
- 不能依据 IsDebuggerPresent 导入断言存在反调试保护：该导入属静态链接 UCRT 的常规引用，动态仿真中也未观察到调用。
- 不能把 .data 中的 base64 串当作明文配置或可直接读取的 C2 列表，它解码后即为高熵加密数据。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 是（stage2 `419d2b4539de3805c0a77f979ef8ba952be6e310901f27aafe46a8a8cf1f1a12`） |

**局限与待验证**

1. 样本是 DLL（PE Characteristics=DLL、入口为 DllMain），沙箱自动投放后没有产生子进程，也没有任何与该样本相关的网络请求或文件写入，因此最终载荷的功能、C2 与持久化方式均未获得动态确认。
2. 内置载荷 169,676 字节为自定义/流式加密（熵 7.994，非 16 字节整数倍，仅检出 base64url 字母表，无 AES/SHA/RC4 常量），静态无法解密；解密流程位于被混淆的分发器中，纯 CPU 仿真在 TLS 读取处即失败（invalid_mem@0x58，0x180001993）。
3. 样本无数字签名（Security 目录为 0），编译时间戳对应 2026-11-13；没有 YARA 命中、多引擎结论或公开沙箱报告可交叉验证，家族归属仅为候选。
4. 紧随载荷之后的 210 条 (rva|0x80000000, 1, size, 0) 记录，其用途（疑似运行时映射/解密区段表）属推断，未经动态验证。
5. 导出桩在沙箱中从未被调用，因此「调用导出即触发解密」这一链路是基于静态控制流得出的判断，尚缺运行证据。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:d0eee70122` | PE 结构解析 | 原始文件：AMD64 DLL、3 段（UPX0/1/2）、entry rva 0xA3770、无签名 |
| `ev-000008` | 样本分诊 | 加壳可能性 85%：UPX 段名、W^X、导入符号 5 个 |
| `ref:81415375e3` | unpack.detect | 判定 UPX，置信度 0.9 |
| `ref:a9378dbeaf` | upx -d | 还原出 643,584 字节原始 DLL（sha256 419d2b45…） |
| `ref:f1950f967f` | pe.exports | loader.dll 14 个导出，7 个 JLI_* 具名导出 + 7 个匿名重复 |
| `ev-000022` | decompile | JLI_Launch @0x18000AECF：窗口查询后调用 FUN_180001a7d，return 0 |
| `ev-000024` | decompile | FUN_180001a7d：TLS 标记写入 + 查表间接跳转 |
| `ev-000027` | decompile | tls_callback_0 @0x180001A60：ATTACH/DETACH 时执行 FUN_1800018A0 |
| `ev-000040` | script | 提取并解码 .data 中 226,235 字符 base64url → 169,676 字节高熵数据，定位 210 条区段记录 |
| `ref:9ec27e421f` | 密码学常量识别 | 仅检出 URL-safe base64 字母表（rva 0x576DC），无分组密码常量 |
| `ref:810a677e1f` | 动态分析平台 | 真实动态沙箱投放 150 秒：0 个候选进程、0 个内存转储、无样本相关网络请求，客体已回滚 |
| `telemetry:6897cd75` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 97 条；已过滤工具/系统噪声 27 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
