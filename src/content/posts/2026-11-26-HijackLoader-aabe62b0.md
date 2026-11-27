---
title: "恶意样本分析：HijackLoader（PE · exe · aabe62b0）"
published: 2026-11-26
draft: false
description: "恶意（置信度低）：HijackLoader · loader/dropper · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Hijack", "loader", "dropper", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **HijackLoader**（存疑） · 置信度 **低**
> 
> 别名：IDAT Loader、Hijack Loader
> 
> 样本以 UPX 加壳的 64 位 DLL 形态出现，导出表被伪造成 Java 启动器 jli.dll 的 JLI_* 接口（DLL 名为 loader.dll，含重复序号导出），节区中嵌入约 29 万字符的高熵加密数据与 216 项分段描述表，核心逻辑被改造为私有 VM/控制流平坦化并用 XOR 混合栈上密钥解字符串。反编译与仿真显示其加载路径只做 CRT 初始化，真正的载荷在宿主调用 JLI_Launch 时由 VM 解密执行，属于典型的规避检测型加载器。运行窗口内未观测到真实 C2 通信。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **HijackLoader** · 别名 IDAT Loader、Hijack Loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · dropper |
| 难度 | hard |
| 首次出现 | 2026-11-23 17:44:48 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/aabe62b0a4d18efc05b34c30c523081c92c33f116cd6610956e3b50010c6a930/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX 多层加壳</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">伪造 Java 启动器导出</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">内嵌大块加密载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">私有 VM 平坦化混淆</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">动态解析 API 地址</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `aabe62b0a4d18efc05b34c30c523081c92c33f116cd6610956e3b50010c6a930` |
| MD5 | _未记录_ |
| 大小 | 717,312 字节（700.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **7** 条静态可得、**2** 条经动态分析取得。

### 1. UPX 多层加壳

`T1027.002` · 置信度 **高** · 静态

以 UPX0/UPX1/UPX2 三段布局加壳，UPX1 熵 7.755 且可写可执行，导入表仅剩 5 个符号，静态特征与 UPX 一致。

> **证据**：scan.triage: packing.score=0.85，段名 UPX0/UPX1/UPX2，UPX1 熵 7.755；unpack.detect 判定 packer=upx
> 
> **来源**：`ref:f6fe8000a4` · `ref:669ceeb21c` · `ref:9617e8a390`

### 2. 伪造 Java 启动器导出

`T1036.005` · 置信度 **高** · 静态

解包后 DLL 内部名为 loader.dll，导出 14 项 JLI_CmdToArgs/JLI_Launch/JLI_MemAlloc 等 Java 启动器接口，其中序号 8-14 与 1-7 重复，属于构造出的伪装导出表。

> **证据**：pe.exports: dll_name=loader.dll, 14 个符号（7 个具名 + 7 个重复序号），JLI_Launch 仅 5 字节跳转到 0x180001AEE
> 
> **来源**：`ref:77c43da146` · `ref:e3330227d4` · `ref:2b12cca353`

### 3. 内嵌大块加密载荷

`T1027.009` · 置信度 **高** · 静态

在 .rdata 中嵌入 294059 字符的 base64url 密文，经解码为 220544 字节、熵 7.9993；.data 同址段另有 216 项 {指针,长度} 描述表，把整块密文切成 102 个连续段并拼接为 651126 字符的加密流。

> **证据**：.rdata RVA 0x1A000 起 294059 字符；.data RVA 0xC53B0 描述表 216 项；解码/拼接脚本产出 488344 字节、熵 7.9996
> 
> **来源**：`ref:712329baef` · `ref:a1ce9fe891` · `ref:6762535fbd`

### 4. 私有 VM 平坦化混淆

`T1027` · 置信度 **高** · 静态

JLI_Launch 被改为 5 字节入口，跳入 0x180001AEE 的控制流平坦化派发器：从栈上常量表取状态、经跳转表分发，并在 0x180006D81 附近用 XOR 循环按栈上密钥表逐字节处理缓冲区。

> **证据**：decompile 0x180001AEE 显示 jumptable 派发；disasm 0x180006D81 显示 `xor byte ptr [rcx], dl` 循环与二次派发；0x1800097D0 附近出现 0x9E3779B97F4A7C15/0xBF58476D1CE4E5A7/0x94D049BB133111EB 等 PRNG 常量并做 64 字节混洗
> 
> **来源**：`ref:859a0c2a1e` · `ref:8fd803cffa` · `ref:941b99c2da` · `ref:1f54f9259f`

### 5. 运行期解密字符串

`T1140` · 置信度 **中** · 静态

字符串与配置不在静态数据中明文保存，需由 VM 派发器配合栈上密钥表与 PRNG 混洗在运行时解密后使用；静态扫描未见 URL、路径或命令明文。

> **证据**：0x180006D81 的 XOR 解密循环 + 0x1800096B6/0x1800097D0 的哈希混洗；scan.strings 在解包文件上只得到 CRT 语言表与字母表，无网络/路径串
> 
> **来源**：`ref:941b99c2da` · `ref:52a7e91157` · `ref:a1ce9fe891`

### 6. 动态解析 API 地址

`T1027.007` · 置信度 **高** · 动态

UPX 自解压完成后，加载器通过 LoadLibraryA + GetProcAddress 逐个解析并填充 89 个导入函数指针，包括 LoadLibraryA/GetProcAddress/VirtualProtect，而非全部依赖静态导入表。

> **证据**：仿真观测：LoadLibraryA(KERNEL32.DLL) 后连续 GetProcAddress 解析 CloseHandle/CreateFileW/.../VirtualProtect；随后 VirtualProtect(0x180000000,0x1000,0x40)
> 
> **来源**：`ref:ae260b77f0` · `ref:61c52650d2`

### 7. 加载期停留在 CRT

`T1106` · 置信度 **高** · 动态

以 DLL 方式加载时，DllMain 仅执行 CRT 初始化（GetSystemTimeAsFileTime/QueryPerformanceCounter/FlsAlloc/VirtualProtect 等）并返回，未创建文件、线程或网络连接，恶意逻辑需宿主调用导出函数才触发。

> **证据**：仿真观测 31 次 API 调用全部为 CRT 初始化；decompile entry/DllMain 显示 __security_init_cookie + Fls 回调注册；沙箱时间线 0 个新进程、网络监控无样本相关域名
> 
> **来源**：`ref:af4155f9d0` · `ref:554eab6c62` · `ref:83ba3f50dd` · `ref:cfb5ebd132`

### 8. 反调试与 CPU 探测

`T1622` · 置信度 **中** · 静态

导入 IsDebuggerPresent，并在 .text RVA 0xBF72 处使用 cpuid 进行 CPU/虚拟机特征探测，属于反分析检查。

> **证据**：unpack.antidebug: IsDebuggerPresent(import) + cpuid code @ RVA 0xBF72；pe.imports 含 IsDebuggerPresent
> 
> **来源**：`ref:a569efa0f3` · `ref:61c52650d2`

### 9. DLL 形态等待宿主

`T1129` · 置信度 **高** · 静态

文件扩展名为 .exe，但 PE 头 characteristics 为 DLL、DllMain 无恶意动作，实际需由 java.exe 等宿主加载并调用 JLI_Launch 才会进入 VM 载荷路径。

> **证据**：pe.parse: characteristics=DLL、subsystem=GUI、entry 为 DllMainCRTStartup；沙箱直接投放未观察到执行
> 
> **来源**：`ref:6762535fbd` · `ref:554eab6c62` · `ref:cfb5ebd132`


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
| `loader_entry` | `导出 JLI_Launch (RVA 0xA162) -> 0x180001AEE VM 派发器` | 是 | 静态 |
| `embedded_payload` | `.rdata RVA 0x1A000 起 294059 字符 base64url 密文（约 220544 字节，熵 7.999）` | 是 | 静态 |
| `embedded_key_material` | `.data RVA 0x6D000 / 0x6D049 共 180 字符（73+107）base64url 字符串` | 否 | 静态 |
| `segment_table` | `.data RVA 0xC53B0 起 216 项 {ptr,len,0} 描述表，102 段连续覆盖整块密文，合计 651126 字符` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得断言样本已发生 C2 外联：运行窗口内网络监控只记录到 Windows 系统基线流量，没有样本相关域名或 IP。
- 不得断言样本会写入磁盘、创建服务、计划任务或注册表项：未观测到相应文件/注册表/服务事件，且加载期仅执行 CRT 初始化。
- 不得把 JLI_* 导出名当作样本是合法 Java 运行库的证据：导出表只有 14 项且序号 8-14 重复，JLI_Launch 仅 5 字节跳入私有 VM，属伪造。
- 不得依据扫描到的 0x9E3779B9 常量断言使用 TEA/XTEA：该值出现在 0x9E3779B97F4A7C15 这个 SplitMix64/PRNG 常量的低 32 位中。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `b494f10188017a89b472982b3818ce86a74749de501a8ddc44e0da0a4f8054f0`） |

**局限与待验证**

1. 内嵌载荷由私有 VM + PRNG 混洗加密，静态未取得明文 C2/配置；未能还原 294059 字符密文的解密密钥。
2. 样本为 DLL，沙箱直接投放无法触发 JLI_Launch；缺少 java.exe 宿主，DllMain 只做 CRT 初始化，故未获得真实恶意行为与网络会话。
3. 家族判定仅为候选：未取到家族字符串、配置或明文载荷，无法与已知家族一一对应。
4. 对字符串解密例程的手工仿真受 TLS/运行时全局初始化限制，未能完整执行到明文输出阶段。
5. 网络侧仅观察到 Windows 系统基线流量（Windows Update/OCSP 等），不构成样本 C2 证据。

## 证据索引

<details>
<summary>展开 26 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:f6fe8000a4` | 样本分诊 | 哈希/imphash/段熵/加壳评分：packing.score=0.85，UPX0-2，UPX1 熵 7.755，导入 5 个 |
| `ref:9617e8a390` | PE 结构解析 | 原始 PE：AMD64 DLL，3 节，entry RVA 0xCA470，导出 14 项 |
| `ref:77c43da146` | pe.exports | 原始导出表：dll_name=loader.dll，JLI_* 共 14 项，含重复序号 |
| `ref:669ceeb21c` | unpack.detect | 壳检测：packer=upx，confidence 0.9，策略 upx_unpack |
| `ref:64e6e99490` | evidence.record | 静态 upx -d 解包结果与解包产物 sha256 |
| `ref:6762535fbd` | PE 结构解析 | 解包 PE：6 节 .text/.rdata/.data/.pdata/.tls/.reloc，entry RVA 0xB9C0，DLL |
| `ref:e3330227d4` | pe.exports | 解包导出表：loader.dll + 14 项 JLI_*（重复序号） |
| `ref:61c52650d2` | 导入表解析 | 解包导入：89 个符号，KERNEL32/user32/api-ms-win-core-synch |
| `ref:788240d3d0` | 哈希与指纹 | 解包产物 sha256=b494f101...854f0 |
| `ref:eef040bd2c` | scan.entropy | 解包整文件熵 6.549，.rdata 6.251，.data 6.117 |
| `ref:712329baef` | evidence.record | 内嵌密文块/密钥材料/216 项分段表解析结果 |
| `ref:2b12cca353` | decompile.function | JLI_Launch(RVA 0xA162)：5 字节调用 0x180001AEE 后返回 |
| `ref:859a0c2a1e` | decompile.function | 0x180001AEE：栈上密钥常量 + jumptable 平坦化派发 |
| `ref:941b99c2da` | disasm.function | 0x180006D81：XOR 解密循环与状态派发 |
| `ref:1f54f9259f` | disasm.function | 0x1800097D0：SplitMix64/PRNG 常量与 64 字节混洗 |
| `ref:52a7e91157` | decompile.function | 0x1800096B6：状态派发的字符串处理例程 |
| `ref:554eab6c62` | decompile.function | DllMainCRTStartup：security cookie + CRT 初始化 |
| `ref:83ba3f50dd` | decompile.function | 用户 DllMain：Fls 回调注册等 CRT 逻辑，无恶意动作 |
| `ref:a569efa0f3` | unpack.antidebug | 反调试：IsDebuggerPresent 导入 + cpuid @ RVA 0xBF72 |
| `ref:27fe08862d` | 密码学常量识别 | 0x9E3779B9 常量命中（实为 PRNG 常量低 32 位） |
| `ref:af4155f9d0` | dyn.run | 解包 DLL 仿真：31 次 API，全部为 CRT 初始化，无文件/网络 |
| `ref:ae260b77f0` | dyn.run | 原始 PE 仿真：UPX 解包后 LoadLibraryA/GetProcAddress 解析 89 个导入 |
| `ref:bdb1b1b0b4` | emu.run | 从 JLI_Launch 冷启动仿真：TLS 指针缺失于 0x1800019C6 停止 |
| `ref:cfb5ebd132` | 动态分析平台 | 沙箱投放：755 次轮询 0 个候选进程，hollows 仅命中 fakenet.exe，已回滚 |
| `ref:a1ce9fe891` | 字符串提取 | 解包字符串：419 ASCII/90 UTF-16，无 URL/路径/flag 明文 |
| `telemetry:aabe62b0` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 102 条；已过滤工具/系统噪声 22 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
