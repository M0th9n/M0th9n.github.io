---
title: "恶意样本分析：未归属的商品化 Loader（Wilow/Salor 活动）（PE · exe · da5e896d）"
published: 2026-11-01
draft: false
description: "恶意（置信度低）：未归属的商品化 Loader（Wilow/Salor 活动） · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **未归属的商品化 Loader（Wilow/Salor 活动）**（存疑） · 置信度 **低**
> 
> 样本为 64 位 C++ 加载器：静态侧存在 AES 表与高熵 .rdata、WinHTTP/注册表/WMI 导入以及 payload.exe 落地逻辑；真实动态执行时加载 wbemprox/wbemsvc/fastprox（WMI 调用发生），并在自身进程内存中发现解密后的下载地址 hxxp://107[.]175[.]82[.]242:9000/wilow/salor[.]bin 与 MSFT_MpPreference.Add 的 ExclusionPath/ExclusionExtension/AttackSurfaceReductionOnlyExclusions 类型信息；反编译确认其将下载内容写入磁盘后 CreateProcessA 启动。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **未归属的商品化 Loader（Wilow/Salor 活动）** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-01 11:35:51 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/da5e896dddab566d7db265b5e8945d71820f991ac03a806f409470608dad23f7/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置配置</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">WMI 添加杀软排除</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">下载远程载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">落盘后启动载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">按 URL 取文件名落地</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `da5e896dddab566d7db265b5e8945d71820f991ac03a806f409470608dad23f7` |
| MD5 | _未记录_ |
| 大小 | 205,312 字节（200.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **5** 条静态可得、**2** 条经动态分析取得。

### 1. 解密内置配置

`T1027` · 置信度 **高** · 静态

程序内置 AES 正向 S-box 与多组 T 表，.rdata 熵 7.75，运行时在堆内存中出现明文的下载 URL 与路径，说明配置/字符串经 AES 解密后使用。

> **证据**：AES S-box @ file off 0x15400；.rdata 熵 7.75；堆内存 0x1F896 处明文 URL
> 
> **来源**：`ref:f17cdbb0a4` · `ref:3581c89291` · `ev-000021`

### 2. WMI 添加杀软排除

`T1562.001` · 置信度 **高** · 动态

通过 WMI 调用 MSFT_MpPreference.Add，向 Defender 添加 ExclusionPath、ExclusionExtension 以及 AttackSurfaceReductionOnlyExclusions（ASR）排除项，并用 .sys/.dll/.ps1/.bat/.cmd 扩展名与 C:\Windows\Temp、C:\Users\Public 等目录扩大放行范围。

> **证据**：动态加载 wbemprox.dll/wbemsvc.dll/fastprox.dll；内存类型信息 MSFT_MpPreference/ExecMethod/ExclusionPath；明文串 root\Microsoft\Windows\Defender
> 
> **来源**：`ref:5c12eb99bd` · `ev-000021` · `ref:2a46bae45a`

### 3. 下载远程载荷

`T1105` · 置信度 **中** · 动态

内置 URL hxxp://107[.]175[.]82[.]242:9000/wilow/salor[.]bin，配合 WinHTTP 导入与写盘/执行函数，形成下载-落地-启动链路；本次执行未观测到实际 HTTP 请求。

> **证据**：内存 0x1F896 处 URL；imports WinHttpOpenRequest(WINHTTP.dll)；FUN_140005050 写盘后调用 FUN_140004f64
> 
> **来源**：`ev-000021` · `ref:2a46bae45a` · `ref:5c12eb99bd`

### 4. 落盘后启动载荷

`T1106` · 置信度 **高** · 静态

FUN_140005050 用 CreateFileA(CREATE_ALWAYS) 写入下载缓冲区，WriteFile 成功后直接 CreateProcessA 启动该文件，启动参数为空且不等待退出。

> **证据**：0x140005050: CreateFileA/WriteFile -> FUN_140004f64；0x140004f64: CreateProcessA(param_1, NULL, ...)
> 
> **来源**：`ref:dcc183def3` · `ref:ac907c6e99`

### 5. 按 URL 取文件名落地

`T1036` · 置信度 **中** · 静态

FUN_140004e11 截取 URL 最后一个 '/' 之后的文件名；为空时回退为固定字符串 payload.exe，因此落盘文件名可来自远端控制。

> **证据**：0x140004e11 返回 "payload.exe" 或 URL 末段；字符串 payload.exe @ file off 0x152FA
> 
> **来源**：`ref:366065b05d` · `ref:ccddbbde37`

### 6. 空参数批量调用 API

`T1497.001` · 置信度 **中** · 静态

0x140009260 处的函数按序对 WinHTTP、WMI、注册表、加密、GDI 截屏、网络枚举、证书库等 20 余个导入函数执行零参数调用，属干扰/探测性调用序列，不能据此判定真实功能。

> **证据**：0x140009260–0x140009450 连续 call [thunk]（ecx/edx/r8/r9 清零）
> 
> **来源**：`ref:ac746cb9b1`

### 7. 时间差与 PEB 反分析

`T1497.003` · 置信度 **中** · 静态

代码含 rdtsc 时间差检测与 gs:[0x60] PEB 直接访问，用于判断调试/虚拟化环境。

> **证据**：rdtsc 序列 @ rva 68521 (.text)；PEB 访问 @ rva 4147
> 
> **来源**：`ref:d95cc49527`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://107[.]175[.]82[.]242:9000/wilow/salor[.]bin` | 9000 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%APPDATA%`
- `%LOCALAPPDATA%`
- `%TEMP%`
- `C:\Windows\Temp`
- `C:\Users\Public`
- `payload.exe`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `107.175.82[.]242:9000` | 是 | 动态 |
| `payload_url` | `hxxp://107[.]175[.]82[.]242:9000/wilow/salor[.]bin` | 是 | 动态 |
| `drop_filename` | `payload.exe（URL 末段为空或不可用时回退）` | 是 | 静态 |
| `install_dirs` | `%APPDATA%; %LOCALAPPDATA%; %TEMP%; C:\Windows\Temp; C:\Users\Public` | 否 | 静态 |
| `encryption_algo` | `AES（内置 S-box 与 T 表，配置/字符串在运行时解密）` | 是 | 静态 |
| `defense_evasion` | `WMI root\Microsoft\Windows\Defender: MSFT_MpPreference.Add(ExclusionPath, ExclusionExtension, AttackSurfaceReductionOnlyExclusions)` | 是 | 动态 |
| `campaign_id` | `-` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要判定为勒索软件或窃密器：未发现文件加密、卷影删除、浏览器凭据库/SQLite 读取或 CryptUnprotectData 调用链，样本下载的是可执行载荷而非加密受害者文件。
- 不要因导入 BitBlt/EnumWindows/GetAdaptersInfo/CertOpenSystemStoreA 就断言具备截屏监控、窗口枚举或证书窃取：这些 API 集中出现在一处零参数“API 冲量”函数中，未见真实调用链。
- 不要断言本次已完成外联或下载：动态期间未观测到对 107[.]175[.]82[.]242:9000 的任何 TCP/HTTP 请求，也无子进程创建；C2 与下载阶段仍需复核。
- 不要断言存在持久化或进程注入：仅导入 RegSetValueExA，未观测注册表写入；未导入 WriteProcessMemory/VirtualAllocEx/CreateRemoteThread。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次动态执行只观测到 WMI 防御规避与配置解密，未触发实际下载/落地/执行；下载地址、payload.exe 落地与 CreateProcessA 链路属静态反编译 + 运行时内存证据，标为待动态复核。
2. 未取得第二阶段 salor.bin，无法判断其家族、加密方式与最终目的。
3. 样本对配置做了 AES 加密且部分路径在运行时拼接，未能穷举全部配置键与持久化开关。
4. 未观测到注册表写、服务、计划任务等持久化行为，相关结论为空不代表不具备该能力。
5. 仅进行一次短时引爆（约 2 分钟观测），未验证长时驻留、重启后的行为。

## 证据索引

<details>
<summary>展开 15 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:ed3b912079` | PE 结构解析 | AMD64 PE，8 段，entry rva 0xBB64，无结构异常，导入 23 个 DLL |
| `ref:3714b0d91c` | 哈希与指纹 | sha256/imphash 基线 |
| `ref:2a46bae45a` | 导入表解析 | WinHTTP/WMI(OLE)/注册表/CryptoAPI/GDI/网络枚举/证书库导入面 |
| `ref:3581c89291` | 样本分诊 | .rdata 熵 7.75，无壳信号；逐段熵与哈希 |
| `ref:f17cdbb0a4` | 密码学常量识别 | AES 正向 S-box @ 0x15400 |
| `ref:ccddbbde37` | 字符串提取 | payload.exe 等明文字符串 |
| `ref:68a3929a54` | unpack.detect | packed=false，无需脱壳 |
| `ref:d95cc49527` | unpack.antidebug | rdtsc 时间差与 PEB 访问 |
| `ref:5c12eb99bd` | 动态分析平台 | 真实引爆 pid 2416，进程存活、无子进程；内存转储与模块清单 |
| `ev-000021` | evidence.record | 内存转储检索：URL、WMI Exclusions 类型信息、宿主目录与进程名 |
| `ref:dcc183def3` | decompile.function | FUN_140005050 写盘后 CreateProcessA |
| `ref:ac907c6e99` | decompile.function | FUN_140004f64 CreateProcessA 启动落地文件 |
| `ref:366065b05d` | decompile.function | FUN_140004e11 从 URL 取文件名，回退 payload.exe |
| `ref:ac746cb9b1` | disasm.function | 0x9260 零参数批量调用导入 API（干扰序列） |
| `ref:b3e848c68a` | dyn.run | 仿真仅执行 CRT 初始化，未触达主体（动态以真实沙箱为准） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
