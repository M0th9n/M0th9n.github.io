---
title: "恶意样本分析：Unattributed cmutil.dll sideloading loader（PE · exe · c6c20ea1）"
published: 2026-11-10
draft: false
description: "恶意（置信度低）：Unattributed cmutil.dll sideloading loader · loader/injector/dropper · 难度 hard · 静态反编译（动态执行未取得运行时行为）"
tags: ["loader", "injector", "dropper", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed cmutil.dll sideloading loader**（存疑） · 置信度 **低**
> 
> 反编译与用户态仿真共同确认：该文件是伪装成 cmutil.dll 的 x64 加载器，内置 958682 字节加密载荷，经三轮位置加法、整段反转与相邻字节交换还原出完整 PE32+；随后解析 VirtualAllocEx/WriteProcessMemory/CreateRemoteThread/GetThreadContext/SetThreadContext 及 NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection 等注入 API，改写 9 个 MessageBox/DialogBox 函数的内存保护，并安装 WH_CBT 钩子。导出表、版本信息与数字签名均为掩护。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed cmutil.dll sideloading loader** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · injector · dropper |
| 难度 | hard |
| 首次出现 | 2026-11-07 16:32:24 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/c6c20ea175d882477847c3f18d2f9fcf40c12cb83d049c1105f8f4f660586a40/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装cmutil.dll导出</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">伪造版本与签名</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">解密内置PE载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">校验PE头并投放临时文件</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">进程镂空注入载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `c6c20ea175d882477847c3f18d2f9fcf40c12cb83d049c1105f8f4f660586a40` |
| MD5 | _未记录_ |
| 大小 | 1,009,640 字节（986.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装cmutil.dll导出

`T1574.002` · 置信度 **高** · 静态

以 cmutil.dll 为内部名导出 57 个 RAS 连接管理器 API（CmFree/CmMalloc/CmStrStrA/GetOSVersion/IsLogonAsSystem 等），使侧加载宿主解析导入表时不会因缺符号而失败。

> **证据**：pe.exports: dll_name=cmutil.dll, ordinal_base=1, count=57, .edata RVA 0xF9000
> 
> **来源**：`ref:ea68241aec`

### 2. 伪造版本与签名

`T1553.002` · 置信度 **高** · 静态

资源段写入随机公司名 yCYrOmYjqTirgB 与版本 2.7.9[.]214，文件尾部附加 7144 字节 WIN_CERTIFICATE（type=2，DigiCert 时间戳链），用于提升可信度。

> **证据**：StringFileInfo CompanyName/ProductName=yCYrOmYjqTirgB；WIN_CERTIFICATE len=7144 rev=0x200 type=2 @ off 1002496
> 
> **来源**：`ref:59839b43ae` · `ref:07668d641e`

### 3. 解密内置PE载荷

`T1027.009` · 置信度 **高** · 静态

把 .rdata 中 958682 字节数据拷到堆后，用三轮位置加法、整段反转与相邻字节交换还原出完整 PE32+（sha256 deefc7fa…），再交给注入器。

> **证据**：FUN_2783f2200 @0x2783f2200 三轮 add byte[i], i*k+c；由 FUN_2783f4960 @0x2783f4960 调用，密钥 -2/-0x5a/-0x12
> 
> **来源**：`ev-000033` · `ev-000032` · `ref:d8a0f39572`

### 4. 校验PE头并投放临时文件

`T1105` · 置信度 **高** · 静态

校验缓冲区为 MZ/PE、machine=0x8664、optional magic=0x20B 且 SizeOfImage 合法后，取 GetTempPathW，拼出临时文件名（前缀 td），以 0xC0010000 权限 CreateFileW 落盘，再以 CreateProcessW/注入方式执行。

> **证据**：FUN_2783f32c0 @0x2783f32c0：*buf=='M''Z'、buf[e_lfanew+4..5]==0x8664、magic==0x20b、GetTempPathW+GetTempFileNameW+CreateFileW(0xc0010000)
> 
> **来源**：`ev-000031` · `ref:46e1c83b4d`

### 5. 进程镂空注入载荷

`T1055.012` · 置信度 **高** · 静态

解析并调用 NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection/NtQueryInformationProcess/NtWriteVirtualMemory，配合 VirtualAllocEx/WriteProcessMemory/CreateRemoteThread/GetThreadContext/SetThreadContext/ResumeThread，把解出的 PE 写入目标进程并执行。

> **证据**：FUN_2783f2df0 解析 WriteProcessMemory/VirtualAllocEx/CreateRemoteThread/WaitForSingleObject/GetThreadContext/SetThreadContext/TerminateProcess/FlushInstructionCache/LdrLoadDll；FUN_2783f32c0 解析 NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection/NtWriteVirtualMemory/NtQueryInformationProcess/NtClose
> 
> **来源**：`ev-000029` · `ev-000031` · `ref:635123fef6`

### 6. 安装WH_CBT钩子

`T1055` · 置信度 **高** · 静态

动态取 API 后调用 SetWindowsHookExW(5, 回调 0x2783f2440, NULL, GetCurrentThreadId)；回调对类名 #32770 的窗口直接返回 1，其余转 CallNextHookEx。

> **证据**：user32.SetWindowsHookExW(WH_CBT, 0x2783f2440, 0x0, 0x434)，仿真 PC=0x2783f270b；FUN_2783f2440 比较 L"#32770"
> 
> **来源**：`ev-000027` · `ev-000028` · `ref:635123fef6`

### 7. 劫持对话框API

`T1055` · 置信度 **高** · 静态

对 MessageBoxW/A、MessageBoxExW/A、MessageBoxIndirectW/A、DialogBoxParamW/A、SoftModalMessageBox 逐个 VirtualProtectEx 改为 PAGE_EXECUTE_READWRITE 并改写入口，压制弹窗与错误提示以保持静默。

> **证据**：kernel32.VirtualProtectEx(hProcess=-1, lpAddress=MessageBoxW/…, 6, PAGE_EXECUTE_READWRITE, …) 连续 9 次，PC=0x2783f239e
> 
> **来源**：`ev-000030` · `ref:635123fef6`

### 8. 枚举进程定位目标

`T1057` · 置信度 **中** · 静态

字符串表中含 CreateToolhelp32Snapshot/Process32FirstW/Process32NextW/OpenProcess/GetShellWindow/GetWindowThreadProcessId，说明会枚举进程并以 shell 窗口所属进程作为注入候选。

> **证据**：XOR 0x40 解码字符串表 @0x2783f9400：Process32NextW/Process32FirstW/CreateToolhelp32Snapshot/OpenProcess/GetShellWindow/GetWindowThreadProcessId
> 
> **来源**：`ref:c9161d8ec0` · `ev-000029`

### 9. 填充噪声对抗检测

`T1027.001` · 置信度 **高** · 静态

.rdata 用 270KB 线性递推填充（每 2 字节步进 0x16，无任何代码引用）与 582KB 高熵数据把文件撑到近 1MB；第二阶段 .rdata 还塞入大量拼写残缺的伪标识符，干扰字符串与体积启发式。

> **证据**：scan.triage: .rdata 熵 7.999/963072 字节；统计得 0x22200-0x64200 满足 byte[i]-byte[i-2]==0x16；stage2 .rdata 0x7b008 起为 dowstream6hidden/servr_dep 等残缺串
> 
> **来源**：`ev-000005` · `ref:b081f04c8c` · `ev-000034`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%TEMP%\td????.tmp`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `embedded_payload_sha256` | `deefc7fa1918dc94b5ac88865f6a775de4f541009e7517b6865ad3de1f52ce9b` | 是 | 静态 |
| `embedded_payload_format` | `PE32+ x64, 5 sections, entry RVA 0x5f100, no import table, .data 309KB obfuscated` | 是 | 静态 |
| `payload_cipher` | `自定义位置加法密码：3 轮 byte += i*k + c（k=-31/-13/-7，c=0xFE/0xA6/0xEE），期间整段反转并交换相邻字节；非 AES/RC4` | 是 | 静态 |
| `injection_api_set` | `VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, GetThreadContext, SetThreadContext, ResumeThread, VirtualProtectEx, TerminateProcess, FlushInstructionCache, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection, NtWriteVirtualMemory, NtQueryInformationProcess` | 是 | 静态 |
| `hooked_ui_apis` | `MessageBoxW/A, MessageBoxExW/A, MessageBoxIndirectW/A, DialogBoxParamW/A, SoftModalMessageBox` | 是 | 静态 |
| `hook_type` | `SetWindowsHookExW(WH_CBT=5, 回调 0x2783f2440, hMod=NULL, 当前线程)` | 是 | 静态 |
| `c2_hosts` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭 cmutil.dll 导出表、版本信息和数字签名就判定为合法 RAS/微软组件——导出、版本与签名均为可伪造的掩护。
- 本次未观测到任何网络连接、DNS 查询或 HTTP 会话，不能称其为 downloader 或声称存在 C2 服务器。
- 现有证据只覆盖加载、投放与注入，未见窃密、加密勒索、挖矿或横向移动，不应归为 stealer/ransomware/miner。
- 样本是 DLL 且真实沙箱未产生新进程，不能声称已完成持久化或已在宿主进程中成功执行。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 是（stage2 `deefc7fa1918dc94b5ac88865f6a775de4f541009e7517b6865ad3de1f52ce9b`） |

**局限与待验证**

1. 第二阶段为强混淆 x64 PE（无导入表、入口充斥无效指令与 PEB 访问），未完成功能级还原，其 C2、配置与最终载荷类型未知。
2. 真实沙箱中 DLL 无宿主加载，未产生新进程、文件与网络事件；动态结论仅来自用户态仿真与静态推导。
3. 未取得厂商引擎或 YARA 佐证，家族归属只能留空并标注不确定。
4. 临时文件名由运行时 GetTempFileNameW 生成，具体文件名与路径不可静态确定，仅能给出 %TEMP%\td????.tmp 形态。
5. 注入目标进程由运行时进程枚举结果决定，静态无法确定具体 PID 或进程名。

## 证据索引

<details>
<summary>展开 24 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1/size 基线 |
| `ev-000005` | scan.entropy | .rdata 熵 7.999（963072 字节），提示加密或填充数据 |
| `ev-000016` | 字符串提取 | 首层字符串抽取，未见 URL/域名/flag |
| `ev-000017` | decompile.ghidra | DllMain CRT 包装函数 0x2783f101d |
| `ev-000024` | decompile.ghidra | 0x2783f4a50：DisableThreadLibraryCalls + 调用 0x2783f31b0（载荷入口） |
| `ev-000025` | decompile.ghidra | 0x2783f31b0：解析 API、GetModuleHandleA(user32)、调用 0x2783f2740 与 0x2783f2550 |
| `ev-000027` | decompile.ghidra | 0x2783f2550：SetWindowsHookExW(5, 0x2783f2440, 0, tid) |
| `ev-000029` | decompile.ghidra | 0x2783f2df0：解析 WriteProcessMemory/VirtualAllocEx/CreateRemoteThread 等注入 API |
| `ev-000030` | decompile.ghidra | 0x2783f2740：对 user32 对话框/消息框 API 逐个处理 |
| `ev-000031` | decompile.ghidra | 0x2783f32c0：PE 头校验、临时文件落盘与执行/注入 |
| `ev-000032` | decompile.ghidra | 0x2783f4960：拷贝 .rdata 加密块、调用 0x2783f2200 解密、转交 0x2783f32c0 |
| `ev-000033` | decompile.ghidra | 0x2783f2200：三轮位置加法+反转+奇偶交换的自定义密码 |
| `ev-000034` | 字符串提取 | 第二阶段 .rdata 残缺伪标识符串（噪声） |
| `ref:ea68241aec` | pe.exports | cmutil.dll 57 个导出（Cm*/GetOS*/IsLogonAsSystem） |
| `ref:59839b43ae` | decompile.symbols | 资源版本信息 yCYrOmYjqTirgB / 2.7.9[.]214 / cmutil.dll |
| `ref:07668d641e` | manual | WIN_CERTIFICATE type=2 len=7144 与 DigiCert 时间戳链 |
| `ref:c9161d8ec0` | manual | XOR 0x40 解码字符串表：进程枚举/注入/钩子 API 清单 |
| `ref:b081f04c8c` | script | 统计 .rdata 填充区（0x22200-0x64200，byte[i]-byte[i-2]=0x16） |
| `ref:d8a0f39572` | script | 按 FUN_2783f2200 正向变换解出 MZ/PE32+，长度 958682 |
| `ref:46e1c83b4d` | script | 解析第二阶段 PE 头：5 节区、entry 0x5f100、无导入表 |
| `ref:b9183ac6c5` | PE 结构解析 | stage2.bin PE32+ 结构画像（无导入/导出） |
| `ref:635123fef6` | dyn.run | 仿真：解析注入 API、9 次 VirtualProtectEx(MessageBox*)、SetWindowsHookExW(WH_CBT) |
| `ref:2d26d737c2` | 动态分析平台 | 真实沙箱轮询 442 次，0 个新进程与转储，DLL 无宿主未执行 |
| `telemetry:c6c20ea1` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 92 条；已过滤工具/系统噪声 27 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
