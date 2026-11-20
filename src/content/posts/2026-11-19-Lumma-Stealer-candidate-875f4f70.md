---
title: "恶意样本分析：Lumma Stealer (candidate)（PE · exe · 875f4f70）"
published: 2026-11-19
draft: false
description: "恶意（置信度低）：Lumma Stealer (candidate) · stealer/loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Lumma", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Lumma Stealer (candidate)**（存疑） · 置信度 **低**
> 
> 别名：LummaC2、policyuntaxed[.]cc campaign
> 
> 样本为空导入表的 32 位 GUI PE，入口自行遍历 PEB 并以 MurmurHash3 哈希动态解析 API；静态字符串经 0x5A 异或后暴露 logins、SQLite format 3、passwordValue、chrome-extension:// 等浏览器凭据取数特征；真实 Windows 沙箱中样本以 pid 976 运行，向 8.8.8[.]8/8.8.4[.]4/1.1.1[.]1/1.0.0[.]1 的 443 端口发送 DoH POST /dns-query，先后解析 object[.]policyuntaxed[.]cc 与 telegra[.]ph，并在进程内存中留下运行期解密的 C2/主机标识配置。伪装合法音频服务、隐蔽解析 C2 与浏览器凭据窃取能力共同支持恶意判定。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Lumma Stealer (candidate)** · 别名 LummaC2、policyuntaxed[.]cc campaign · _存疑_ |
| 置信度 | **低** |
| 行为类 | stealer · loader |
| 难度 | hard |
| 首次出现 | 2026-11-18 00:45:41 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/875f4f7091850c5e47950f0c13f86f5e4194fc81d99b9ad14d6aa6ee85094fa7/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装音频服务组件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">空导入哈希解析API</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">异或解密内置字符串</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解析浏览器登录库</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">DoH查询隐藏C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `875f4f7091850c5e47950f0c13f86f5e4194fc81d99b9ad14d6aa6ee85094fa7` |
| MD5 | _未记录_ |
| 大小 | 726,528 字节（709.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **7** 条静态可得、**1** 条经动态分析取得。

### 1. 伪装音频服务组件

`T1036.005` · 置信度 **高** · 静态

PE 清单与版本资源将自身描述为 Realtek.Audio.RtkAudioService / RtkAudioService.exe / Realtek HD Audio Background Service，文件名、厂商与描述均指向合法音频组件，属于典型的系统组件伪装。

> **证据**：版本资源位于文件偏移 0xab04c 起；OriginalFilename=RtkAudioService.exe；assemblyIdentity name=Realtek.Audio.RtkAudioService
> 
> **来源**：`ref:88c4d56d11` · `ref:37f5a8c685`

### 2. 空导入哈希解析API

`T1027.007` · 置信度 **高** · 静态

导入目录为空（0 个 DLL、0 个导入符号）。入口点先调用 0x431070，函数内通过 fs:[0x30] 读取 PEB；0x4016eb 起使用 MurmurHash3（常量 0x5BD1E995）对 API 名做哈希，随后按哈希动态解析所需函数，静态不可见真实 API 面。

> **证据**：pe_parse 的 IMPORT rva=0/size=0；entry 0x401000 -> 0x431070；0x431078 mov eax, fs:[0x30]；rva 0x16eb 起出现 0x5BD1E995 常量
> 
> **来源**：`ref:6c9cdb3a11` · `ref:0d2607d987` · `ref:23f34883a0` · `ref:d80b304765`

### 3. 异或解密内置字符串

`T1140` · 置信度 **高** · 静态

敏感字符串在 .rdata 中以单字节 0x5A 异或保存。按该规则解码后得到 logins、SQLite format 3、password、passwordValue、passwords、chrome-extension:// 与 NtCreateProcess 等明文。

> **证据**：文件偏移 0x7d979 起 XOR 0x5A 得到 logins；0x7d981 SQLite format 3；0x7d9e9 passwordValue；0x7db69 chrome-extension://；0x7ff21 NtCreateProcess
> 
> **来源**：`ref:b87d3159df` · `ref:997ecd18c4`

### 4. 解析浏览器登录库

`T1555.003` · 置信度 **中** · 静态

解码出的 logins、SQLite format 3、passwordValue、passwords、chrome-extension:// 表明样本具备读取 Chromium/Firefox 登录数据库（logins 表）及扩展数据的能力，目标为浏览器保存的账号口令。动态窗口内未捕获实际文件读取或外传。

> **证据**：0x7d979 logins；0x7d981 SQLite format 3；0x7d9e9 passwordValue；0x7da29 passwords；0x7db69 chrome-extension://
> 
> **来源**：`ref:b87d3159df`

### 5. DoH查询隐藏C2

`T1071.004` · 置信度 **高** · 动态

样本进程向 8.8.8[.]8、8.8.4[.]4（dns[.]google）与 1.1.1[.]1、1.0.0[.]1（cloudflare-dns[.]com）的 443 端口发送 POST /dns-query（application/dns-message），先查询 object[.]policyuntaxed[.]cc，随后查询 telegra[.]ph。以公共 DNS over HTTPS 服务替代常规 DNS，隐藏真实 C2 域名解析。

> **证据**：网络监控记录 pid 976：TCP 8.8.8[.]8:443、8.8.4[.]4:443、1.1.1[.]1:443、1.0.0[.]1:443；DoH 报文 qname=object[.]policyuntaxed[.]cc、telegra[.]ph
> 
> **来源**：`ref:6e7c3cf8d0` · `ref:94c16a582e` · `ref:b87d3159df`

### 6. 读取机器码作标识

`T1082` · 置信度 **高** · 静态

运行期解密的配置包含 Registry Machine Software Microsoft Cryptography 路径、MachineGuid、FallbackGUID 与 COMPUTERNAME=，说明样本读取主机 MachineGuid（缺失时回退到全零 GUID）并拼入主机标识/回连参数。

> **证据**：内存配置区 dump+0x5b1fd 处出现 Machine Software Microsoft Cryptography；+0x5b23d MachineGuid；+0x5b255 FallbackGUID；+0x5b3b5 COMPUTERNAME=
> 
> **来源**：`ref:94c16a582e` · `ref:b87d3159df`

### 7. 准备ETW规避

`T1562.006` · 置信度 **中** · 静态

运行期配置同时出现 EtwEventWrite 与 AddVectoredExceptionHandler，说明样本定位 ETW 事件写入函数并注册向量化异常处理，用于阻断遥测与承接反调试/异常控制流。

> **证据**：内存配置区 dump+0x5b1b9 EtwEventWrite；+0x5b1d1 AddVectoredExceptionHandler
> 
> **来源**：`ref:94c16a582e` · `ref:b87d3159df`

### 8. 注入目标指向记事本

`T1055.012` · 置信度 **低** · 静态

配置保留 System32 notepad.exe 路径，且内置解码字符串含 NtCreateProcess 等原生进程 API，提示其可能以系统记事本作为进程注入/进程镂空宿主；本次动态运行未捕获到 notepad 子进程，注入是否执行未证实。

> **证据**：内存配置区 dump+0x5b19b System32 notepad.exe；0x7ff21 解码为 NtCreateProcess
> 
> **来源**：`ref:94c16a582e` · `ref:b87d3159df`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| dns | `object.policyuntaxed[.]cc` | 443 | c2 | 静态 | ⏳ 未观测 |
| dns | `telegra[.]ph` | 443 | dead-drop | 静态 | ⏳ 未观测 |

### 主机

**注册表**

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `object.policyuntaxed[.]cc` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_protocol` | `DNS over HTTPS: POST /dns-query, Content-Type: application/dns-message` | 是 | 静态 |
| `doh_resolvers` | `8.8.8[.]8, 8.8.4[.]4 (dns[.]google), 1.1.1[.]1, 1.0.0[.]1 (cloudflare-dns[.]com)` | 是 | 静态 |
| `dead_drop_host` | `telegra[.]ph` | 否 | 静态 |
| `bot_id_source` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid` | 是 | 静态 |
| `fallback_guid` | `00000000-0000-0000-0000-000000000000` | 否 | 静态 |
| `campaign_token` | `a2a756bbd8e014767d241a3b2df56734` | 否 | 静态 |
| `http_headers` | `Accept; Content-Type; Content-Length; Host` | 是 | 静态 |
| `inject_target` | `%WINDIR%\System32\notepad.exe` | 否 | 静态 |
| `string_obfuscation` | `单字节 XOR 0x5A` | 是 | 静态 |
| `api_resolution` | `MurmurHash3 哈希 API 名后动态解析` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得据 logins/SQLite 字符串断言本次运行已实际窃取浏览器口令——动态窗口内只观测到 DoH 解析与配置解密，未看到登录库文件读取或凭据外传。
- 不得把 comsvcs.t0.dmp 解读为对 lsass 的凭据转储——该文件是进程 minidump，内容仅含模块列表，未见 lsass 访问或 MiniDumpWriteDump 行为。
- 不得把 telegra[.]ph 直接当作恶意 C2 服务器——它是被滥用的合法发布服务，本次仅见 DoH 查询，未见内容下载。
- 不得声称已成功回连 C2——公共 DoH 在沙箱内未返回可用地址，未出现 object[.]policyuntaxed[.]cc 的完整请求/响应。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. C2 地址由运行期解密并在内存中确认，但公共 DoH 在沙箱内未返回有效 A 记录，未观察到对 object[.]policyuntaxed[.]cc 的完整请求/响应；C2 按静态/待动态复核记录。
2. 浏览器凭据窃取能力由隐藏字符串与 SQLite 相关字符串推断，动态窗口内未捕获实际文件读取或外传。
3. notepad.exe 注入目标来自配置字符串，未捕获子进程或注入行为，注入链未证实。
4. 样本导入表为空且配置在运行期解密，静态无法完整还原调用链；API 解析依赖运行时哈希，未逐项还原全部 API。
5. comsvcs.t0.dmp 为进程 minidump，不是 comsvcs.dll 模块，未发现 lsass 访问证据。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小，确认与题面哈希一致 |
| `ev-000007` | 样本分诊 | 分诊：0 导入符号、5 个节、未见高熵加壳信号 |
| `ev-000008` | 字符串提取 | ASCII/UTF-16 字符串抽取，含 Realtek 伪装资源文本 |
| `ev-000009` | 字符串提取 | 较长字符串抽取，展示伪装音频服务相关文案 |
| `ev-000010` | 密码学常量识别 | TEA/XTEA delta 0x9E3779B9 常量（作为哈希/常量线索） |
| `ev-000014` | 字符串提取 | 进程内存配置区字符串：object[.]policyuntaxed[.]cc、MachineGuid、FallbackGUID、COMPUTERNAME=、campaign token、notepad.exe 等 |
| `ev-000015` | evidence.record | 脚本解码 0x5A 字符串并解析内存配置/动态网络日志的结果 |
| `ref:6e7c3cf8d0` | 动态分析平台 | 真实 Windows 沙箱引爆记录：样本 pid 976 启动、DoH 网络请求与内存转储产物 |
| `ref:0d2607d987` | disasm.function | 入口 0x401000 调用 0x431070 |
| `ref:23f34883a0` | disasm.function | 0x431070 读取 PEB 并对 API 进行哈希解析的入口逻辑 |
| `ref:d80b304765` | disasm.function | rva 0x16eb 附近的 MurmurHash3（0x5BD1E995）实现 |
| `telemetry:875f4f70` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 96 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:875f4f70:976` | 进程事件监控 | 短命进程事件：875f4f7091850c5e47950f0c13f86f5e4194fc81d99b9ad14d6aa6ee85094fa7.exe（pid 976；MD5=78EC9BADE8CDDE43CBC5A3A2F27C199C,SHA256=875F4F7091850C5E47950F0C13F86F5E4194FC81D99B9AD14D6AA6EE85094FA7,IMPHASH=00000000000000000000000000000000） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
