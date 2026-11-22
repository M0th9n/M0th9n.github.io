---
title: "恶意样本分析：Unclassified PE64 loader (TLS-table decode + API hashing)（PE · exe · c47f0cb5）"
published: 2026-11-21
draft: false
description: "恶意（置信度低）：Unclassified PE64 loader (TLS-table decode + API hashing) · loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unclassified PE64 loader (TLS-table decode + API hashing)**（存疑） · 置信度 **低**
> 
> PE64 DLL 无任何导出，主体只在 TLS 回调与 DllMain/CRT 路径中运行：加载时以滚动加法密钥把 4 张数据表解码进 TLS 存储，并用 54 项有序哈希表做折半查找动态解析 API；导入面仅保留 CRT 与 GetSystemFirmwareTable、IsDebuggerPresent、MessageBoxW 等反分析/指纹调用；.rdata 用随机 base64url 串与英文词序列填充隐藏字符串。该组合是侧加载型装载器/植入组件的典型构造，判定为恶意。本次未恢复出 C2 或第二阶段载荷，故恶意性依据为机制自证而非行为后果。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unclassified PE64 loader (TLS-table decode + API hashing)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader |
| 难度 | hard |
| 首次出现 | 2026-11-19 19:24:54 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/c47f0cb5a0c51d908fbcc38be70ade963762e4f4adca8fb32f33440cb9af4376/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">TLS 回调解码数据表</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">哈希表二分查 API</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">读取 SMBIOS 指纹</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">检测调试器</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">运行期改页属性</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `c47f0cb5a0c51d908fbcc38be70ade963762e4f4adca8fb32f33440cb9af4376` |
| MD5 | _未记录_ |
| 大小 | 663,625 字节（648.1 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **7** 条静态可得、**2** 条经动态分析取得。

### 1. TLS 回调解码数据表

`T1027` · 置信度 **高** · 静态

TLS 回调在 DLL_PROCESS_ATTACH/DETACH 时以滚动加法密钥把 4 张表（26×u64@0x7C6E0、16×u32@0x7C9B0、14×u16@0x7CD64、19×u8@0x7F190）解码到 TLS 块 +0x58…+0x186，并置 +0x185 初始化标志，主体逻辑因此不在常规导入/导出面暴露。

> **证据**：rva 0x7D650 循环：表 + 滚动常量 0x471e43be6bb4579f / 0xd528883b9283d9bf；tls_callback_0@rva 0x45D30
> 
> **来源**：`ref:22dcab34c9` · `ref:f339080e20` · `ref:8a6943122e`

### 2. 哈希表二分查 API

`T1027.007` · 置信度 **中** · 静态

以 54 项递增有序的 32 位哈希表（0x7CACC）配合折半查找动态解析所需 API 地址，避免在导入表中留下敏感函数名。

> **证据**：rva 0xD7DD: mov r11d,0x36; lea rdx,[rip+0x6f23b]=0x7CACC; 折半索引 mov esi,[rdx+rax*4]
> 
> **来源**：`ref:8a6943122e`

### 3. 读取 SMBIOS 指纹

`T1497.001` · 置信度 **高** · 静态

导入并保留 GetSystemFirmwareTable（IAT 0x97320），可读取原始 SMBIOS 固件表用于硬件/虚拟机指纹识别与反分析。

> **证据**：pe_imports: kernel32.dll!GetSystemFirmwareTable, iat_rva=0x97320
> 
> **来源**：`ref:084de1a61c`

### 4. 检测调试器

`T1622` · 置信度 **高** · 静态

导入 IsDebuggerPresent 且 .text 中 0x70A5F 处存在对其 IAT 槽（0x8F120）的间接调用，具备调试器检测能力。

> **证据**：IAT rva 0x8F120; call qword ptr [rip+disp] @rva 0x70A5F
> 
> **来源**：`ref:084de1a61c` · `ref:5d7fc30c92`

### 5. 空导出需宿主加载

`T1574.002` · 置信度 **中** · 静态

PE64 DLL 且导出表为空（export_count=0），入口在 .text 的 DllMain/CRT 路径，只能由宿主进程加载后经内部路径执行，具备侧加载投递形态。

> **证据**：pe_parse: characteristics=DLL, export RVA=0; entry rva 0x79A00
> 
> **来源**：`ref:44e8311ad3` · `ref:c76c197550` · `ref:555982cf02`

### 6. 重写导入表藏 CRT

`T1027` · 置信度 **高** · 静态

导入目录含 116 个 DLL 条目、116 个符号，其中大量为 kernel32.dll 单项重复条目，且 CRT 与 API-set 解析数据并存，符合装载器重打包/导入表重建的形态。

> **证据**：pe_imports: dll_count=116, symbol_count=116, 多个 kernel32.dll 单符号条目
> 
> **来源**：`ref:084de1a61c`

### 7. 随机串填充混淆

`T1027` · 置信度 **高** · 静态

.rdata 0x7D242–0x8C5B0 区域由 base64url 随机串与连贯英文词序列交替填充，作为字符串/配置混淆层并干扰静态检索（扫描器仅命中字母表串）。

> **证据**：0x7D2B0 技术英文串紧邻 base64url 串；0x7E9B8 'find live we three different…'；strings 仅命中 abcdefghijklmnopqrstuvwxyz{|}
> 
> **来源**：`ref:cbf3da05f6` · `ref:dcb7e61b56` · `ref:26b530cd71`

### 8. 运行期改页属性

`T1027` · 置信度 **高** · 动态

用户态仿真窗口内在 pc=0x15FAFAE2CAE 调用 VirtualProtect(0x15FAFB0C000,0x100,PAGE_READONLY)，对 .tls/数据页做保护属性调整。

> **证据**：dyn 观测: kernel32.VirtualProtect args [0x15fafb0c000,0x100,0x2] ret=1
> 
> **来源**：`ref:f7d38e489e`

### 9. 加载期无外联动作

`T1106` · 置信度 **高** · 动态

仿真执行窗口共记录 21 次 API 调用，除 CRT 初始化（FlsAlloc/FlsSetValue/InitializeCriticalSectionEx/GetProcessHeap/VirtualProtect）外，未出现文件、网络或注册表操作，主体逻辑需宿主调用后才可能展开。

> **证据**：dyn 观测: api_count=21, file_access/network_events/registry_access 均为空
> 
> **来源**：`ref:f7d38e489e`


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
| `c2_hosts` | `-` | 是 | 静态 |
| `mutex` | `-` | 否 | 静态 |
| `install_path` | `-` | 否 | 静态 |
| `encryption_algo` | `rolling additive delta over 4 TLS tables (u64/u32/u16/u8), init flag at TLS+0x185; no standard cipher matched (TEA delta constant is only a coincidental 0x9E3779B9 hit)` | 否 | 静态 |
| `api_hash_table` | `54-entry sorted u32 table @rva 0x7CACC, binary-search resolver @rva 0xD7DD` | 是 | 静态 |
| `tls_tables` | `0x7C6E0 (26x8), 0x7C9B0 (16x4), 0x7CD64 (14x2), 0x7F190 (19x1) -> TLS +0x58/+0x128/+0x168/+0x186` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要仅凭内嵌路径 C:\Users\Test\Desktop\jre21in\java.exe 断言其最终投放 Java/JAR 载荷；该路径更可能是编译期残留或打包配置。
- 不要仅凭导入 GetSystemFirmwareTable 断言存在完整反虚拟化判定逻辑；本次只证到导入与可调用面，未观测到判定分支。
- 不要将 .rdata 的随机 base64url 串或英文词序列当成 C2、密钥或活动 ID；本次未取得任何可用网络指标。
- 不要把它判为 ransomware/stealer：未观测到加密、窃密、外联或注册表/服务写入。
- 不要断言已经发生 DLL 侧加载劫持；只能确认其为空导出 DLL、具备被宿主侧加载的形态。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本为无导出 DLL，无法作为独立进程引爆；本次未取得真实沙箱的进程/网络/内存证据，动态结论仅来自用户态仿真。
2. API 哈希表尚未还原为符号名，无法确认其动态解析的具体函数集合。
3. 未提取到配置、C2、互斥体或安装路径；家族归属无法确定，按候选标注 uncertain。
4. .rdata 中大量随机 base64url 串与英文词序列可能为混淆填充，也可能承载加密配置，本次未能解密。

## 证据索引

<details>
<summary>展开 11 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:77f864625a` | 哈希与指纹 | sha256/md5/imphash 基线 |
| `ref:44e8311ad3` | PE 结构解析 | PE64 DLL、无导出、入口 rva 0x79A00、8 个节 |
| `ref:084de1a61c` | 导入表解析 | 116 条目导入表，含 GetSystemFirmwareTable/IsDebuggerPresent/MessageBoxW |
| `ref:cbf3da05f6` | 字符串提取 | 字符串与字母表命中，.rdata 填充特征 |
| `ref:a4b6eccb3f` | 密码学常量识别 | 仅 TEA delta 常量命中（0x9E3779B9） |
| `ref:22dcab34c9` | decompile.function | tls_callback_0 调用 FUN_0x7D650 |
| `ref:f339080e20` | decompile.function | 4 张表的滚动加法解码写入 TLS |
| `ref:8a6943122e` | disasm.function | 解码循环与 54 项哈希表折半查找 |
| `ref:555982cf02` | decompile.function | DllMain/CRT 初始化路径 |
| `ref:f7d38e489e` | dyn.run | 21 次 API 调用，无文件/网络/注册表动作 |
| `ref:dcb7e61b56` | script | 十六进制核对 .rdata 填充结构 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
