---
title: "恶意样本分析：Memu Helper（PE · exe · e522b4df）"
published: 2026-11-24
draft: false
description: "恶意（置信度低）：Memu Helper · spyware/injector · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Memu Helper", "spyware", "injector", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Memu Helper**（存疑） · 置信度 **低**
> 
> 别名：MEmu Helper、Memu.exe
> 
> 该 64 位 PE 未签名，版本资源自称 Memu Helper/Memu Networks Ltd，代码采用控制流平坦化、跳转表、常量加解密与 TLS 指针魔数自校验等强混淆；静态导入包含全局按键查询(GetAsyncKeyState)、焦点/桌面窗口与窗口线程枚举。动态沙箱内样本进程启动后，内存取证在 explorer.exe 中发现无磁盘文件支撑的 64 位 PE 模块及 RWX(MEM_PRIVATE) shellcode 区，注入模块导入前台窗口/类名/窗口矩形查询 API，符合进程注入与窗口/输入监视能力。综合判定为恶意，但注入与样本的直接调用链、C2 与配置明文尚未取得。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Memu Helper** · 别名 MEmu Helper、Memu.exe · _存疑_ |
| 置信度 | **低** |
| 行为类 | spyware · injector |
| 难度 | hard |
| 首次出现 | 2026-11-22 09:43:11 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/e522b4df3aa6528186299cce0a75e01d7a549271873a16426a6fad891f490bc2/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">注入 explorer.exe</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">监控前台窗口</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1010</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">读取全局按键状态</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">内嵌编码数据池</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">混淆控制流与常量</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `e522b4df3aa6528186299cce0a75e01d7a549271873a16426a6fad891f490bc2` |
| MD5 | _未记录_ |
| 大小 | 825,344 字节（806.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **6** 条静态可得、**2** 条经动态分析取得。

### 1. 注入 explorer.exe

`T1055.012` · 置信度 **中** · 动态

样本运行后，内存取证在 explorer.exe 中检出未在模块列表中、无磁盘文件支撑的 64 位 PE 模块以及 MEM_PRIVATE 的 PAGE_EXECUTE_READWRITE shellcode 区（PE 位于区域基址 +0x4000），表明通过进程注入承载后续代码。

> **证据**：explorer.exe pid 4128: implanted_pe=1, has_shellcode=1, protection=0x40, mapping_type=MEM_PRIVATE, unreachable_file=1；注入模块 dump sha256=a49e4767...
> 
> **来源**：`ref:b615d86c7c`

### 2. 监控前台窗口

`T1010` · 置信度 **中** · 动态

注入到 explorer.exe 的模块导入 GetForegroundWindow、GetClassNameW、GetWindowRect 与 IsWindowEnabled，具备枚举前台窗口及其类名/矩形、跟踪用户活动上下文的能力。

> **证据**：注入模块导入表 user32.dll: GetForegroundWindow/GetClassNameW/GetWindowRect/IsWindowEnabled
> 
> **来源**：`ref:b615d86c7c`

### 3. 读取全局按键状态

`T1056.001` · 置信度 **高** · 静态

主程序启动流程调用 GetAsyncKeyState(0x11) 读取 Ctrl 键状态，并静态导入全局按键查询能力，可用于热键判断或键盘监听。

> **证据**：rva 0x122a call GetAsyncKeyState(0x11)（FUN_140001110）；IAT rva 0x77f00
> 
> **来源**：`ref:8ff02b7a2a` · `ref:3f40bbf9e7`

### 4. 内嵌编码数据池

`T1027` · 置信度 **高** · 静态

在 .rdata/.data 中内嵌 212 段由 {ptr,len} 表索引的编码数据，运行时按索引解码/解密，属于典型载荷与配置隐藏方式。

> **证据**：0xc5038 起 {ptr,len} 表（首项 ptr=0x140027000,len=0x9c）；两个数据池起始 rva 0x27000 与 0x7b000
> 
> **来源**：`ref:96c015c6c1` · `ref:4040b411ea`

### 5. 混淆控制流与常量

`T1027` · 置信度 **高** · 静态

关键函数使用控制流平坦化、间接跳转表与常量异或/SPLITMIX64 派生密钥，反编译出现大量不可达分支与加密常量，显著提高静态分析成本。

> **证据**：FUN_140001110 @0x14000128d 间接跳转；FUN_14000c1f0 常量表异或解密；FUN_14000bf70 使用 0x9e3779b97f4a7c15 的混合派生
> 
> **来源**：`ref:8ff02b7a2a` · `ref:3ce190af4b` · `ref:c1b686f810`

### 6. 伪装厂商与版本

`T1036.005` · 置信度 **高** · 静态

资源版本信息自称 Memu Helper / Memu Networks Ltd / 2.9.8.5020 / Memu.exe，但文件无数字签名，且厂商名与已知 MEmu 发行商不符，具有品牌伪装特征。

> **证据**：VS_VERSION_INFO 字符串 @0xc72a0 'Memu Helper'、@0xc735e 'Memu Networks Ltd'；SECURITY 数据目录 size=0
> 
> **来源**：`ref:4040b411ea` · `ref:b18592aada`

### 7. 枚举窗口与进程

`T1010` · 置信度 **高** · 静态

枚举焦点窗口、桌面窗口、其所属线程/进程 ID，并结合 IsIconic/IsZoomed/IsWindowEnabled/GetClientRect 判断窗口状态，为后续监视或覆盖层定位提供信息。

> **证据**：FUN_14000bf70 @rva 0xbf70 调用 GetFocus/GetDesktopWindow/GetWindowThreadProcessId/GetClientRect
> 
> **来源**：`ref:c1b686f810`

### 8. TLS 自校验反分析

`T1497.001` · 置信度 **中** · 静态

通过 TLS 指针偏移处魔数与私钥解码表的校验决定关键分支是否执行，并保留 IsDebuggerPresent 等运行时检查，具备反调试/反沙箱性质。

> **证据**：FUN_14000bf70: *(int*)(TLS+0xb8) == -0x2281050a(-0x2281050a)；FUN_14000c1f0 初始化 TLS 私有表
> 
> **来源**：`ref:c1b686f810` · `ref:3ce190af4b`


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
| `embedded_blob_count` | `212 段 {ptr,len} 索引的编码数据，合计约 583,595 字符，分布于 .rdata(rva 0x27000 起) 与 .data(rva 0x7b000 起) 两个池` | 否 | 静态 |
| `blob_encoding` | `自定义 32 符号字母表(0-9 与部分小写字母，缺 a/f/g/p)，数据间以 '_' 每 44 字符分隔` | 否 | 静态 |
| `crypto_scheme` | `常量表 + SPLITMIX64 风格混合派生密钥，配合异或解密（静态识别，未还原明文）` | 否 | 静态 |
| `c2_hosts` | `未取得（动态窗口内未观察到样本外联）` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭 GetAsyncKeyState 的导入断言已完整记录并回传键盘内容：本次分析未观察到按键日志文件落地，也未观察到网络外发。
- explorer.exe 中注入模块与本样本的直接因果关系尚未由调用链/注入事件证明，存在宿主环境其他组件的可能，只能作为强关联观测。
- 未取得 C2 地址、配置明文或家族专属字符串，不应声称该样本属于某个具体远控/窃密家族。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态窗口内未观察到样本自身的外联（网络监控仅记录系统更新/浏览器更新流量），C2 未取得。
2. explorer.exe 中的注入模块与样本之间的直接调用链未取得（无注入相关 ETW 事件），归属为推断，置信度中等。
3. 212 段编码数据尚未完全解码，其明文用途（界面资源/脚本/配置/载荷）未确认。
4. GetAsyncKeyState 仅见一次 VK_CONTROL 查询，不能据此认定完整键盘记录行为。
5. 样本为 GUI 子系统，自动化环境未进行界面交互，部分界面相关逻辑可能未执行。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与 imphash |
| `ev-000003` | scan.entropy | .text 熵 6.54，各段均 <7.0，无整体加壳特征 |
| `ev-000013` | decompile.ghidra | FUN_140001110 控制流平坦化与 GetAsyncKeyState(0x11) |
| `ev-000014` | decompile.ghidra | FUN_14000bf70 窗口枚举与 SPLITMIX64 派生 |
| `ev-000015` | decompile.ghidra | FUN_14000601f 宽字符路径与 CreateFileW/SetFileTime 封装 |
| `ev-000016` | decompile.ghidra | FUN_14000c1f0 TLS 私有表常量解密 |
| `ev-000017` | decompile.ghidra | FUN_14000c127 NtWriteFile 封装 |
| `call:call_1a329c757c0a41ec8a45c834` | 动态分析平台 | 动态沙箱运行时间线、内存扫描与注入模块证据 |
| `telemetry:e522b4df` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 108 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 22 条 |
| `etw:e522b4df:4480` | 进程事件监控 | 短命进程事件：e522b4df3aa6528186299cce0a75e01d7a549271873a16426a6fad891f490bc2.exe（pid 4480；MD5=659F7FB6F900041C4B80B0261042E981,SHA256=E522B4DF3AA6528186299CCE0A75E01D7A549271873A16426A6FAD891F490BC2,IMPHASH=1D06A1CB5556761EA9E76B9B76D17970） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
