---
title: "恶意样本分析：Unattributed NSIS downloader（PE · exe · 85c35b2d）"
published: 2026-10-28
draft: false
description: "恶意（置信度低）：Unattributed NSIS downloader · downloader/dropper · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["downloader", "dropper", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed NSIS downloader**（存疑） · 置信度 **低**
> 
> PE32 NSIS 3.06 Unicode 安装器在隔离 Windows 沙箱中真实运行：进程内加载 winhttp/wininet/urlmon/dnsapi/ws2_32，解析 x0[.]at 并以伪造的 Firefox 157 UA 对 hxxps://x0[.]at/Kp7v.bin 发起 HTTPS GET，约 100 秒内重试 11 次；镜像带自签名伪证书（CN=Squamify）与随机字典词版本信息；安装包内 1.4 MB 文件为常量填充诱饵，唯一高熵块无可执行头。动态观测到远程载荷拉取与隐藏目录落盘，静态观测到伪装与规避构造，故判定恶意下载器/投放器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed NSIS downloader** · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · dropper |
| 难度 | medium |
| 首次出现 | 2026-10-28 10:54:58 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/85c35b2dd5fa36ab0ae8943b6673e9655d66427b7c84b3792fc7c046bdb622bf/) |

## 攻击链

<svg viewBox="0 0 720 226" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="150" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="38" fill="currentColor" font-weight="600" font-size="14">配置解密</text>
<text x="250" y="38" fill="currentColor" fill-opacity="0.65" font-size="12.5">AES 解密内置配置</text>
<text x="250" y="56" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="92" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="92" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="96" fill="currentColor" font-weight="600" font-size="14">伪装落地</text>
<text x="250" y="96" fill="currentColor" fill-opacity="0.65" font-size="12.5">复制到 %LocalAppData%</text>
<text x="250" y="114" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<rect x="586" y="81" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="96" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="150" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="150" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="154" fill="currentColor" font-weight="600" font-size="14">连接 C2</text>
<text x="250" y="154" fill="currentColor" fill-opacity="0.65" font-size="12.5">原始 TCP 到硬编码 C2</text>
<text x="250" y="172" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="139" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="154" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `85c35b2dd5fa36ab0ae8943b6673e9655d66427b7c84b3792fc7c046bdb622bf` |
| MD5 | _未记录_ |
| 大小 | 552,632 字节（539.7 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **4** 条静态可得、**4** 条经动态分析取得。

### 1. 伪装丹麦语计算软件

`T1036.005` · 置信度 **高** · 静态

样本是 NSIS 3.06 (Unicode) 自解压安装器，界面与安装目录伪装成丹麦语能源计算工具（Energiteknik / kalkulationsformlerne），版本信息使用随机词典词（CompanyName=communalising、InternalName=sanders blodhvnens.exe、ProductName=fugledderkops sadomasochismen nednormeret）。

> **证据**：pe.parse: subsystem GUI, 5 sections, entry rva 0x34C5; NSIS header at file off 0x3C810 (magic NullsoftInst), version string 'Nullsoft Install System v3.06'; script string '%PROGRAMFILES%\Energiteknik\kalkulationsformlerne\upknit'
> 
> **来源**：`ref:d8c0ce8dc6` · `ref:6cfa65711f` · `ref:4eca17e8b7`

### 2. 使用自签名伪证书

`T1553.002` · 置信度 **高** · 静态

PE 安全目录附带 Authenticode 签名，但证书自签名（subject=issuer=CN=Squamify, C=GB），有效期 2026-09-08 至 2027-09-08，用于制造“已签名安装包”的假象。

> **证据**：file off 0x85BE8 WIN_CERTIFICATE (type 2, 4816 B); PKCS#7 signer cert: subject=C=GB, O=Squamify, OU=slantways Illiannas Remodification , CN=Squamify; issuer identical
> 
> **来源**：`ref:ae7bba0517`

### 3. 释放常量填充诱饵文件

`T1027.001` · 置信度 **高** · 静态

NSIS 包内 5 个“数据文件”合计约 1.4 MB，其中 4 个为单一字节常量填充（0x4E/0x17/0x56/0xD9，熵 0.16），Mimmest 为高熵块（7.67）且仅含大量重复 4 字节模式、无 MZ/PE 头；这些文件不构成可执行载荷，属体积膨胀/检测干扰。

> **证据**：section entropy .text 6.495 / whole 7.369; extracted: baglande.roe 0x4E x230678, benelux.per 0x17 x304506, coequalness.for 0x56 x630262, fordjelsens.rak 0xD9 x649348; Mimmest entropy 7.67, 0 MZ at page starts
> 
> **来源**：`ref:67780c0084` · `ref:6b2969295f`

### 4. 写入隐藏模板目录

`T1036.005` · 置信度 **高** · 动态

运行时将文件释放到 %APPDATA%\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit，而非常规 Program Files；内存中捕获到完整释放路径及“djelsens.rak... 100%”的安装进度串。

> **证据**：process minidump @0x6CDEE27 UTF-16 'C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit\Desmosis\Lejevrdiberegningsreglens\'; @0x6F5ADCF 'djelsens.rak... 100%'
> 
> **来源**：`ref:aba1498190` · `ref:43dc74ac8d`

### 5. 内置下载远程载荷

`T1105` · 置信度 **高** · 动态

运行中的样本进程解析 x0[.]at 并向 hxxps://x0[.]at/Kp7v.bin 发起 HTTPS GET，请求头使用伪造的 Firefox 157 User-Agent 与 Cache-Control: no-cache，属进程内下载第二阶段。

> **证据**：网络监控: 'Received A request for domain x0.at' (23:40:07) + 'GET /Kp7v.bin HTTP/1.1' / 'Host: x0.at' / 'User-Agent: ...rv:157.0...Firefox/157.0'; minidump @0x6CFFC1F & @0x6D2B127 'hxxps://x0.at/Kp7v.bin'
> 
> **来源**：`ref:9051288944` · `ref:f55b194d99` · `ref:ddab4c4c7d`

### 6. 每十秒重试下载

`T1105` · 置信度 **高** · 动态

同一 URL 在约 100 秒内被请求 11 次（约每 10 秒一次，23:40:08 至 23:41:49），说明下载结果未被接受并进入重试循环。

> **证据**：网络监控日志中 'GET /Kp7v.bin HTTP/1.1' 共 11 条，间隔 10-11 s；同一 pid 6064 持续发起 TCP 192.0.2[.]123:443
> 
> **来源**：`ref:9051288944` · `ref:2bc6cccbca`

### 7. 进程内加载网络组件

`T1071.001` · 置信度 **高** · 动态

样本进程在运行中加载 winhttp.dll、wininet.dll、urlmon.dll、dnsapi.dll、ws2_32.dll、IPHLPAPI.DLL，网络访问全部在自身进程完成；未观测到子进程创建。

> **证据**：进程模块扫描（65 个模块）含 winhttp/wininet/urlmon/dnsapi/ws2_32/IPHLPAPI；进程表仅样本 pid 6064 存活，其余为系统进程
> 
> **来源**：`ref:dd10aae79a` · `ref:512e1b78e5` · `ref:cb96860fc2`

### 8. 伪造版本元数据

`T1036.005` · 置信度 **高** · 静态

版本资源声明 FileVersion/ProductVersion 3.3.0[.]0，但公司名、产品名、内部名均为随机英/丹词典词组合，与 NSIS 3.06 实际外壳不一致，用于降低启发式可疑度。

> **证据**：version info: FileDescription='hammerers inkassoen stegersers', InternalName='sanders blodhvnens.exe', LegalCopyright='medisterplsen', ProductName='fugledderkops sadomasochismen nednormeret'
> 
> **来源**：`ref:6cfa65711f` · `ref:d8c0ce8dc6`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://x0[.]at/Kp7v.bin` | 443 | download | 动态 | 已观测 |

### 主机

**落地路径**

- `%APPDATA%\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit\`
- `%APPDATA%\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit\Desmosis\Lejevrdiberegningsreglens\fordjelsens.rak`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `download_url` | `hxxps://x0[.]at/Kp7v.bin` | 是 | 动态 |
| `install_path` | `%APPDATA%\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit` | 是 | 动态 |
| `http_user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0` | 否 | 动态 |
| `installer_framework` | `Nullsoft Install System v3.06 (Unicode, deflate)` | 否 | 静态 |
| `code_signing` | `self-signed Authenticode, C=GB, O=Squamify, OU=slantways Illiannas Remodification, CN=Squamify (2026-09-08..2027-09-08)` | 否 | 静态 |
| `decoy_payloads` | `Mimmest (272220 B, entropy 7.67), baglande.roe (233016 B, 0x4E filler), Gnaskeriet (157965 B), Desmosis\benelux.per (307508 B, 0x17 filler), Desmosis\coequalness.for (636578 B, 0x56 filler), Desmosis\Lejevrdiberegningsreglens\fordjelsens.rak (655728 B, 0xD9 filler)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得因存在高熵块或自签名证书就断言其为勒索软件/窃密程序：动态仅观测到下载与落盘，未见加密、凭据访问或数据外传。
- 不得把 x0[.]at 描述为 C2 面板/回连地址：它是载荷托管点，样本仅做一次性下载重试，无心跳或指令交互。
- 不得断言存在持久化（Run 键/服务/计划任务）：本次动态未观测到注册表或服务写入，静态仅见路径字符串。
- 不得把 NSIS 内的常量填充文件当作被执行的可执行体：这些文件无 PE 头，且运行期未产生子进程。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 第二阶段 Kp7v.bin 未取得：网络监控以假响应替代真实站点，下载器 11 次重试均未进入执行流程，故无法确认家族与最终载荷类型。
2. 未获得文件/注册表写入的逐条遥测，持久化与自启动项未能证实，故 host_iocs.registry/services/tasks 留空。
3. 样本为 32 位 GUI 安装器，依赖向导交互；动态观测到的释放与下载发生在交互后约 1 分钟，未覆盖安装完成后的全部路径。

## 证据索引

<details>
<summary>展开 15 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:d8c0ce8dc6` | PE 结构解析 | PE32 GUI, 5 sections, entry rva 0x34C5, image base 0x400000, 7 imported DLLs, 0 exports |
| `ref:cb96860fc2` | 导入表解析 | 165 imports / 7 DLLs, imphash 6e7f9a29f2c85394521a08b9f31f6275; no static socket/WinINet imports |
| `ref:6b2969295f` | scan.entropy | whole-file entropy 7.369; .text 6.495; .rdata 5.014; .data 4.156; .rsrc 5.912 |
| `ref:4eca17e8b7` | 字符串提取 | ev-000001: 896 ASCII / 51 UTF-16 strings; NSIS integrity messages and no embedded flag/URL |
| `ref:6cfa65711f` | archive listing (static) | NSIS 3.06 Unicode, deflate, headers 15716 B; extracted file inventory and fake version metadata |
| `ref:67780c0084` | archive extraction (static) | 6 data files + 3 NSIS plugins + bitmap; per-file sha256 and constant-byte filler statistics |
| `ref:ae7bba0517` | certificate parsing (static) | self-signed Authenticode cert: CN=Squamify, C=GB, subject==issuer, SHA256, valid 2026-09-08..2027-09-08 |
| `ref:2bc6cccbca` | 动态分析平台 | real Windows sandbox detonation: 33 polls, pid 6064, 6 detonator dumps, no child process, auto-revert |
| `ref:f55b194d99` | 字符串提取 | ev-000002: network-monitor log strings, 367 ASCII entries incl. HTTP requests |
| `ref:9051288944` | log analysis | 11x 'GET /Kp7v.bin' with Host: x0.at, Firefox/157.0 UA, 10 s retry interval |
| `ref:ddab4c4c7d` | memory forensics | process minidump: UTF-16/ASCII 'hxxps://x0.at/Kp7v.bin' at 0x6CFFC1F/0x6D2B127 and HTTP request headers |
| `ref:aba1498190` | memory forensics | process minidump: UTF-16 install path under %APPDATA%\Microsoft\Windows\Templates\...\upknit |
| `ref:dd10aae79a` | module scan | 65 modules in sample process; 1 modified (ntdll patch), 0 injected PE/shellcode |
| `ref:512e1b78e5` | process enumeration | only sample pid 6064 alive; svchost/监控组件/system otherwise; no spawned child |
| `c2_evidence:85c35b2d` | 连接证据提取 | 动态网络监控记录到 14 次到 x0[.]at:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
