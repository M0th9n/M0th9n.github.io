---
title: "恶意样本分析：Microsoft Windows Biometric Enrollment Host（PE · exe · c9ca5797）"
published: 2026-11-07
draft: false
description: "良性（置信度高）：Microsoft Windows Biometric Enrollment Host · benign · 难度 easy · 动态沙箱 + 静态反编译"
tags: ["PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!NOTE]
> **判定：良性** · 家族 **Microsoft Windows Biometric Enrollment Host** · 置信度 **高**
> 
> 别名：BioEnrollmentHost.exe、Windows Hello 生物识别注册宿主、Biometric Enrollment Host
> 
> 该文件是微软签名的 Windows 组件 BioEnrollmentHost.exe（Biometric Enrollment Host，Windows Hello 生物识别注册 UI 宿主）。按 Authenticode 规范重算的文件摘要（排除 CheckSum、Security 目录项与证书表）为 8f2b2a7ee30ec7f03338a2c4c8b4da44e3c156b7c7d63ef82c4f578dbcba0559，与签名 PKCS#7 中 SpcIndirectDataContent 的摘要逐字节一致，说明文件自微软签名后未被修改；签名校验状态为有效，签名者 CN=Microsoft Windows，时间戳由 Microsoft Time-Stamp Service 签发。静态导入面仅含 WinRT/CRT 与线程/同步 API，不存在网络、文件写入、注册表、服务、计划任务或进程注入相关导入；在隔离动态沙箱中样本被成功启动并加载 Windows.UI.Xaml/wincorlib，进程全程无网络请求、无子进程、无文件落盘，内存扫描未发现挂钩、替换、植入或反射加载。综合判定为误报性质的良性系统组件。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Microsoft Windows Biometric Enrollment Host** · 别名 BioEnrollmentHost.exe、Windows Hello 生物识别注册宿主、Biometric Enrollment Host |
| 置信度 | **高** |
| 行为类 | benign |
| 难度 | easy |
| 首次出现 | 2026-11-04 15:19:02 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/c9ca5797b92076943247208f2159ae169802b159555341b7adeee6f7dd387886/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">校验微软数字签名</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">加载 WinRT XAML 界面</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">启动生物识别注册宿主</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">运行期无网络外联</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">无持久化与文件落盘</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `c9ca5797b92076943247208f2159ae169802b159555341b7adeee6f7dd387886` |
| MD5 | _未记录_ |
| 大小 | 508,456 字节（496.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **6** 条行为，每条都挂了证据；其中 **2** 条静态可得、**4** 条经动态分析取得。

### 1. 校验微软数字签名

`N/A` · 置信度 **高** · 静态

文件内嵌证书表（偏移 0x725C0，长度 0x9C28）为 PKCS#7 签名；按 Authenticode 规范重算的 PE 摘要与签名内 SpcIndirectDataContent 摘要完全一致，签名校验状态为有效，签名者 CN=Microsoft Windows（指纹 D8FB0CC66A08061B42D46D03546F0D42CBC49B7C），并带 Microsoft Time-Stamp Service 时间戳。

> **证据**：证书表 off=0x725C0 size=0x9C28；重算摘要 8f2b2a7ee30ec7f03338a2c4c8b4da44e3c156b7c7d63ef82c4f578dbcba059 与 PKCS#7 摘要一致；签名状态 Valid
> 
> **来源**：`ref:13713a5d44` · `ref:3f62c32dfd` · `ref:53a6b5f75c`

### 2. 加载 WinRT XAML 界面

`N/A` · 置信度 **高** · 静态

导入 wincorlib.DLL 及 Windows.UI.Xaml/Windows.Foundation 相关 WinRT 接口，字符串中存在 Windows.UI.Xaml.Window、Windows.UI.Xaml.Controls.Frame、BioEnrollment.Host.HostFrame 等类型名，表明进程用于承载 Windows Hello 生物识别注册的 XAML 用户界面。

> **证据**：导入 wincorlib.DLL（62 个符号）；UTF-16 字符串 0x515D8 'Windows.UI.Xaml.Window'、0x51878 'BioEnrollment.Host.HostFrame'
> 
> **来源**：`ref:9bb83ed89c` · `ref:a5bab6ceda` · `ref:d8f1b6885b`

### 3. 启动生物识别注册宿主

`N/A` · 置信度 **高** · 动态

在隔离动态沙箱中投放后，样本进程（PID 8056）正常创建并持续存活，加载 ntdll/kernel32/combase/wincorlib/Windows.UI.Xaml/ws2_32 等系统模块，运行期间未派生子进程，行为与普通 XAML 宿主一致。

> **证据**：沙箱时间线 PID 8056，模块列表含 C:\Windows\System32\wincorlib.DLL 与 Windows.UI.Xaml.dll；候选进程仅 1 个
> 
> **来源**：`ref:ed806a0db5` · `ref:1a0582157f` · `ref:520a2dc405`

### 4. 运行期无网络外联

`N/A` · 置信度 **高** · 动态

该进程在动态观测窗口内没有任何 DNS/TCP/UDP 请求；网络监控日志中会发起请求的均为系统更新、搜索、浏览器等既有进程。静态导入表同样不含 socket/wininet/winhttp/WinHTTP 等网络 API。

> **证据**：网络监控日志按进程名/ PID 过滤，无 c9ca5797…/8056 的请求记录；导入表 27 个 DLL 中无网络 API
> 
> **来源**：`ref:ed806a0db5` · `ref:9bb83ed89c` · `ref:5c29d01de3`

### 5. 无持久化与文件落盘

`N/A` · 置信度 **高** · 动态

导入表不含 RegCreateKey/RegSetValue、CreateFileW、WriteFile、CreateService、schtasks 等注册表、文件写入、服务或计划任务 API；动态观测中该进程未创建任何文件。

> **证据**：导入符号 217 个，无 Reg*/文件写/服务/计划任务 API；沙箱转储记录该 PID 的文件数为 0
> 
> **来源**：`ref:9bb83ed89c` · `ref:1a0582157f`

### 6. 内存无注入或挂钩

`N/A` · 置信度 **高** · 动态

对运行中的样本进程进行内存扫描，共检查 29 个模块，结果为 0 个被挂钩、0 个被替换、0 个 PE 头被修改、0 个 IAT 挂钩、0 个植入模块；对全网进程的 hollowing 扫描同样为 0 个可疑项。

> **证据**：PE 扫描 SUMMARY: Total scanned 29, Hooked 0, Replaced 0, Hdrs Modified 0, IAT Hooks 0, Implanted 0, Total suspicious 0
> 
> **来源**：`ref:ed806a0db5` · `ref:520a2dc405`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

- **未恢复任何主机 IOC。**

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得仅因样本位于隔离目录或出现在恶意样本投递源中，就将其判定为恶意软件——签名摘要与文件内容逐字节一致，证明它是未被修改的微软原始二进制。
- 不得把 Windows Hello/Face/Iris/Fingerprint/SecurityKey 等字符串解读为窃取生物特征或凭据的后门功能——这些是系统自带生物识别注册 UI 的视图模型与控件名。
- 不得把进程加载 ws2_32.dll 视为 C2 通信证据——该模块由 XAML/系统组件间接加载，进程自身无任何网络请求，静态导入表也无网络 API。
- 不得声称该样本具有持久化、进程注入、下载或横向移动行为——导入面与动态观测均无相应证据。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 离线环境未查询证书吊销状态（CRL/OCSP）；但文件摘要与签名内摘要完全一致、签名链为 Microsoft Windows Production PCA 2011 → Microsoft Root Certificate Authority 2010，且本机签名校验返回有效。
2. 动态观测仅覆盖单次约 2 分钟的引爆窗口，未模拟交互式生物识别注册流程；无网络请求与无文件落盘的结论基于该窗口内的行为与网络监控日志。
3. 该组件依赖 Windows Hello/生物识别 broker 才能完成完整业务流程，沙箱中未触发指纹/面部/安全密钥的实际注册交互，因此无法评估其在真实 Windows Hello 业务流程中的全部 UI 行为。
4. 样本为 AppContainer/WinRT 应用，部分扩展行为可能由系统 broker 进程代为执行，本次观测只覆盖直接启动的进程。

## 证据索引

<details>
<summary>展开 11 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:15cb599287` | 样本分诊 | 哈希/imphash/Rich header/段熵/导入统计，packing.score=0，anomaly_count=0 |
| `ref:99ac563635` | PE 结构解析 | AMD64 GUI PE，6 段，entry rva=0x4C9F0，签名目录 rva=0x725C0 size=39976，含 APPCONTAINER/GUARD_CF/DYNAMIC_BASE |
| `ref:9bb83ed89c` | 导入表解析 | 27 个 DLL/217 个符号，仅 WinRT/CRT/线程同步 API；无网络、文件写、注册表、服务、注入相关导入 |
| `ref:a5bab6ceda` | 字符串提取 | ASCII 947 条 / UTF-16 239 条，含 BioEnrollmentHost.pdb、Windows.UI.Xaml、BioEnrollment.* 视图模型字符串；无 C2/URL/flag 命中 |
| `ref:13713a5d44` | script (bash) | 按 Authenticode 规范重算摘要 8f2b2a7ee30ec7f03338a2c4c8b4da44e3c156b7c7d63ef82c4f578dbcba059，与 PKCS#7 摘要一致 |
| `ref:3f62c32dfd` | script (bash) | openssl smime -verify 成功；本机签名校验 Status=Valid，签名者 CN=Microsoft Windows，指纹 D8FB0CC6…，时间戳由 Microsoft Time-Stamp Service 签发 |
| `ref:21dc7c77fd` | script (bash) | 版本资源：CompanyName=Microsoft Corporation、FileDescription=Biometric Enrollment Host、OriginalFilename=BioEnrollmentHost.exe、FileVersion=10.0.19041.4355 |
| `ref:37ddb42aef` | script (bash) | 字符串/调试路径：shellcommon\shell\auth\enrollment\bio\app\host\App.xaml.cpp、BioEnrollmentHost.pdb、BioEnrollment.Face/Iris/Fingerprint/SecurityKey 类型名 |
| `ref:ed806a0db5` | 动态分析平台 | 隔离动态沙箱投放：进程 PID 8056 创建并存活，加载 wincorlib/Windows.UI.Xaml；内存扫描 29 个模块 0 可疑；hollowing 全扫 0；无文件产出 |
| `ref:1a0582157f` | 动态分析平台 | 时间线：仅 1 个候选进程，未派生子进程，dump 记录文件数 0，插件进程无网络相关事件 |
| `ref:5c29d01de3` | 动态分析平台 | 网络监控日志：请求方为 svchost/SearchApp/msedge 等系统与浏览器进程，无样本 PID 8056 的请求 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
