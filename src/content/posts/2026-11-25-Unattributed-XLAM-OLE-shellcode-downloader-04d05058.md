---
title: "恶意样本分析：Unattributed XLAM/OLE shellcode downloader（other · xlam · 04d05058）"
published: 2026-11-25
draft: false
description: "恶意（置信度低）：Unattributed XLAM/OLE shellcode downloader · downloader/loader · 难度 medium · 纯静态分析"
tags: ["downloader", "loader"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed XLAM/OLE shellcode downloader**（存疑） · 置信度 **低**
> 
> 别名：OLE shellcode JS downloader、XLAM downloader
> 
> 在隔离环境中静态拆解 OLE 容器并用 CPU 级指令仿真复现：流内壳码先滚动异或解密二级代码，二级代码经 PEB 遍历动态解析 API，从 Cloudflare R2 公共桶下载 .js 并落到 %APPDATA% 后交给 ShellExecuteW 执行。下载与执行链完整、可复核，判定为恶意下载器/加载器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed XLAM/OLE shellcode downloader** · 别名 OLE shellcode JS downloader、XLAM downloader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | medium |
| 首次出现 | 2026-11-25 14:00:08 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/04d05058662e29b714743fb20525d8da4d1b5a99d9a4184e2bbb67e1b9957773/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装成Excel插件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.008</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">内嵌混淆壳码</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">滚动异或解密二级</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">PEB遍历解析API</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">下载JS到%APPDATA%</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `04d05058662e29b714743fb20525d8da4d1b5a99d9a4184e2bbb67e1b9957773` |
| MD5 | _未记录_ |
| 大小 | 971,264 字节（948.5 KB） |
| 类型 | other · `xlam` |

## 行为分析

共 **6** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装成Excel插件

`T1036.008` · 置信度 **高** · 静态

文件扩展名为 .xlam，但 OLE 复合文档只包含一个 OLe10nAtivE 数据流(961514 字节)和一个随机命名的空存储，没有 Workbook 或 VBA 工程流，不能作为正常 Excel 加载项工作，属于文件类型伪装。

> **证据**：OLE 目录仅含 'OLe10nAtivE'(961514B) 与 'Uhuj49KQMKo68mKF1TW6JHJ'(0B)，无 Workbook/VBA 流
> 
> **来源**：`ref:7b17e225f5` · `ev-000003`

### 2. 内嵌混淆壳码

`T1027` · 置信度 **高** · 静态

OLe10nAtivE 流偏移 0x331 起是跳转混淆的 x86 壳码，使用 call/pop 取得当前地址，并以大量短跳转与死代码掩盖真实控制流。

> **证据**：0x331 jmp 0x415；0x415 call 0x43d；0x43d pop esi；0x353 xor dword [esi],ebx
> 
> **来源**：`ref:4e9b9d27a3` · `ev-000003`

### 3. 滚动异或解密二级

`T1140` · 置信度 **高** · 静态

解密密钥按 state=state*0x69ec269d+0x370eddbb 递推，对 [esi] 逐 DWORD 异或，解密 0x457..0x710 共 0x2b9 字节的二级壳码后跳入执行。

> **证据**：0x385 imul ebx,ebx,0；0x344 add ebx,0x370eddbb；0x976 imul ebx,ebx,0x69ec269d；写入区间 0x457-0x70f
> 
> **来源**：`ev-000003` · `ref:159d85844a`

### 4. PEB遍历解析API

`T1027.007` · 置信度 **高** · 静态

二级壳码读取 fs:[0x30] 指向的 PEB，遍历已加载模块链表定位 kernel32，再用内嵌字符串动态解析 LoadLibraryW、GetProcAddress 等 API，样本静态导入表因此为空。

> **证据**：0x62d mov edx, fs:[0x30]；字符串 kernel32 / LoadLibraryW / GetProcAddress
> 
> **来源**：`ref:d3af40ec29` · `ev-000003`

### 5. 下载JS到%APPDATA%

`T1105` · 置信度 **高** · 静态

调用 ExpandEnvironmentStringsW 展开 %APPDATA%\dimpason.js，再从 UrlMon 解析 URLDownloadToFileW，从 r2.dev 下载 umasonwast.js 到该路径。

> **证据**：0x4e2 UTF-16 '%APPDATA%\dimpason.js'；0x54e UTF-16 下载 URL；0x52a 'URLDownloadToFileW'
> 
> **来源**：`ref:1ae3f2710e` · `ev-000003`

### 6. 执行下载的JS

`T1059.007` · 置信度 **高** · 静态

从 shell32 解析 ShellExecuteW，以 open 方式执行已下载的 %APPDATA%\dimpason.js，随后调用 ExitProcess 结束自身进程。

> **证据**：0x5f2 'ShellExecuteW'；0x619 'ExitProcess'
> 
> **来源**：`ref:1ae3f2710e` · `ev-000003`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://pub-3fba11404095422aba9bf21639f42cff[.]r2[.]dev/umasonwast[.]js` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%APPDATA%\dimpason.js`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `pub-3fba11404095422aba9bf21639f42cff[.]r2[.]dev` | 是 | 静态 |
| `download_url` | `hxxps://pub-3fba11404095422aba9bf21639f42cff[.]r2[.]dev/umasonwast[.]js` | 是 | 静态 |
| `install_path` | `%APPDATA%\dimpason.js` | 是 | 静态 |
| `encryption_algo` | `rolling XOR，密钥 LCG 递推 state=state*0x69ec269d+0x370eddbb` | 否 | 静态 |
| `ole_stream` | `OLe10nAtivE` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要因为 .xlam 扩展名就断言它能被 Excel 打开并执行宏：文件内没有 Workbook/VBA 流，也没有 XLM 宏。
- 不要断言样本已成功联网下载或已上线 C2：本次为静态与 CPU 级仿真，未取得任何真实网络会话。
- 不要把 941527 字节的均匀字母数字区域当作已解密载荷或配置：二级壳码没有引用该区域。
- 不要把它归为窃密或勒索家族：现有证据只到下载并执行 JavaScript，后续载荷类型未知。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态分析与 CPU 级指令仿真，未在真实沙箱引爆，真实下载与执行结果未观测。
2. OLE 结构不含 Workbook/VBA 流，无法由 Excel 直接作为加载项执行，实际投递与加载路径未知。
3. 941527 字节的均匀字母数字数据（熵 5.954）未被二级壳码引用，用途不明，可能是填充或未使用数据。
4. 未取得任何厂商命名或 YARA 特征，家族只能给出描述性候选并标记不确定。
5. 未观察到持久化、注册表、服务、计划任务或互斥体行为。
6. 远端 umasonwast.js 未下载，后续载荷类型与行为未知。

## 证据索引

<details>
<summary>展开 4 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000003` | evidence.record | olefile 提取 OLe10nAtivE 流；自建 x86 CPU 仿真从 0x331 执行壳码，解密 0x457-0x710 并导出二级字符串/API/URL |
| `ref:4e9b9d27a3` | disasm.bytes | 偏移 0x331 起壳码反汇编：jmp/call/pop 与 xor [esi],ebx 解密循环 |
| `ref:1ae3f2710e` | 字符串提取 | 解密后二级代码中的 API、%APPDATA%\dimpason.js 与 r2.dev 下载 URL 字符串 |
| `ref:7b17e225f5` | 字符串提取 | 原始 .xlam 中 OLE 流名 OLe10nAtivE 与 941527 字节字母数字数据 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
