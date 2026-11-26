---
title: "恶意样本分析：AnyDesk RAT (tech support scam deployment)（PE · exe · 20b0dfbd）"
published: 2026-11-25
draft: false
description: "恶意（置信度中）：AnyDesk RAT (tech support scam deployment) · rat/dropper · 难度 easy · 动态沙箱 + 静态反编译"
tags: ["AnyDesk", "rat", "dropper", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **AnyDesk RAT (tech support scam deployment)**（存疑） · 置信度 **中**
> 
> 别名：AnyDesk abuse、Remote access tool abuse、Soporte Online scam、RemoteAdmin.AnyDesk
> 
> 样本是无签名的 WinRAR 自解压(SFX)封装，文件尾附加 RAR5 归档，归档注释携带静默安装指令（Path=C:\SOPORTE ONLINE、Setup=AnyDesk.exe、Silent=1、Overwrite=1、Update=U）。真实动态环境中，样本进程自行写出 C:\SOPORTE ONLINE\Anydesk.exe 并以 --local-service / --local-control 启动该 AnyDesk 客户端，反复解析 boot[.]net[.]anydesk[.]com 并向 443/80/6568 发起连接，形成可被第三方远程接管的通道。结合西语“在线支持”话术与静默、无交互的安装方式，判定为借合法远程控制软件实施未授权远程访问的恶意投递。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **AnyDesk RAT (tech support scam deployment)** · 别名 AnyDesk abuse、Remote access tool abuse、Soporte Online scam、RemoteAdmin.AnyDesk · _存疑_ |
| 置信度 | **中** |
| 行为类 | rat · dropper |
| 难度 | easy |
| 首次出现 | 2026-11-25 00:23:13 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/20b0dfbd5078bcec058e44295d27b2e26b044bcd546e51802982e0d08fcfce19/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">内嵌RAR载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">静默释放AnyDesk</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">启动远程控制客户端</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">派生服务与控制进程</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">连接AnyDesk中继</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `20b0dfbd5078bcec058e44295d27b2e26b044bcd546e51802982e0d08fcfce19` |
| MD5 | _未记录_ |
| 大小 | 5,967,951 字节（5.7 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **3** 条静态可得、**4** 条经动态分析取得。

### 1. 内嵌RAR载荷

`T1027.009` · 置信度 **高** · 静态

外层 PE 为 WinRAR 自解压存根（资源中含 “WinRAR self-extracting archive” 与安装/解压向导字符串），文件尾偏移 0x4FC00 起附加 RAR5 归档，归档注释携带自动解压指令：Path=C:\SOPORTE ONLINE、Setup=AnyDesk.exe、Silent=1、Overwrite=1、Update=U。

> **证据**：0x4FC00 RAR5 头；注释文本 'Path=C:\SOPORTE ONLINE / Setup=AnyDesk.exe / Silent=1'；.rsrc 中 'WinRAR self-extracting archive'
> 
> **来源**：`ref:3686049d34` · `ref:87b03789a1` · `ref:d8512f933c`

### 2. 静默释放AnyDesk

`T1105` · 置信度 **高** · 动态

样本进程在无用户交互情况下写出 C:\SOPORTE ONLINE\Anydesk.exe（5,656,872 字节，与归档内条目一致），目录由样本自行创建。

> **证据**：进程创建遥测: pid 1464 (样本) -> File created C:\SOPORTE ONLINE\Anydesk.exe；内存扫描显示模块路径 C:\SOPORTE ONLINE\Anydesk.exe
> 
> **来源**：`ref:292dbb8687` · `ref:69694ad529`

### 3. 启动远程控制客户端

`T1219` · 置信度 **高** · 动态

以 "C:\SOPORTE ONLINE\AnyDesk.exe"（FileVersion 9.0.5、Company AnyDesk Software GmbH）启动主进程（pid 5668），工作目录 C:\SOPORTE ONLINE，即进入 AnyDesk 客户端运行态。

> **证据**：进程创建遥测 pid 5668: Image=C:\SOPORTE ONLINE\Anydesk.exe, CommandLine="C:\SOPORTE ONLINE\AnyDesk.exe"
> 
> **来源**：`ref:3b88b9183b` · `ref:292dbb8687`

### 4. 派生服务与控制进程

`T1219` · 置信度 **高** · 动态

主进程随后派生 "--local-service"（pid 5040）与 "--local-control"（pid 3756）两个子进程，进入可接受远程会话的服务与控制模式。

> **证据**：进程创建遥测: pid 5040 CommandLine="C:\SOPORTE ONLINE\AnyDesk.exe" --local-service；pid 3756 CommandLine="C:\SOPORTE ONLINE\AnyDesk.exe" --local-control
> 
> **来源**：`ref:3b88b9183b` · `ref:292dbb8687`

### 5. 连接AnyDesk中继

`T1571` · 置信度 **高** · 动态

运行期反复解析 boot[.]net[.]anydesk[.]com（分析窗口内 15 次）并向 443、80、6568 发起 TCP 连接；内存中的运行时配置为 ad.anynet.boot_addrs=boot[.]net[.]anydesk[.]com、ad.anynet.conn_methods=connect:443;connect:80;socks:443;direct:443;direct:80;direct:6568。

> **证据**：DNS 遥测: Anydesk.exe (pid 5040) QueryName=boot[.]net[.]anydesk[.]com；网络监控: Anydesk.exe -> 443/80/6568；内存字符串 ad.anynet.conn_methods=...
> 
> **来源**：`ref:306a7a2185` · `ref:2c741353ae` · `ref:292dbb8687`

### 6. 滥用官方代码签名

`T1553.002` · 置信度 **高** · 静态

内层 Anydesk.exe 带 AnyDesk Software GmbH 的有效代码签名（DigiCert Trusted G4 Code Signing 链，2024 时间戳证书），而外层 SFX 投递器未签名；运行期系统还对其证书发起 OCSP/CRL 校验。借合法签名降低查杀命中与用户警惕。

> **证据**：签名校验 Status=Valid, Signer=CN=AnyDesk Software GmbH；外层 Status=NotSigned；网络监控见 ocsp[.]digicert[.]com / crl*.digicert.com 查询
> 
> **来源**：`ref:8f2214a302` · `ref:a04be79c51` · `ref:306a7a2185`

### 7. 伪装在线支持入口

`T1204.002` · 置信度 **高** · 静态

归档注释使用西语 “El comentario siguiente contiene secuencias de órdenes para auto extracción”，安装目录取名 C:\SOPORTE ONLINE（在线支持），并借助 SFX 的安装向导界面与 “Install” 按钮诱导用户执行，属社会工程学投递。

> **证据**：RAR 注释西语文本；资源字符串 'Install'/'Extraction progress'/'WinRAR self-extracting archive'
> 
> **来源**：`ref:3686049d34` · `ref:d8512f933c`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `boot[.]net[.]anydesk[.]com` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\SOPORTE ONLINE\`
- `C:\SOPORTE ONLINE\Anydesk.exe`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `install_path` | `C:\SOPORTE ONLINE` | 是 | 静态 |
| `setup_command` | `Setup=AnyDesk.exe` | 是 | 静态 |
| `silent` | `1` | 是 | 静态 |
| `overwrite` | `1` | 否 | 静态 |
| `update_mode` | `U` | 否 | 静态 |
| `payload_name` | `Anydesk.exe` | 是 | 静态 |
| `payload_sha256` | `12c8bece29b5d0ce88f8e0d0cc339f6f90803e1ad80898c658e188f50b6f997e` | 是 | 静态 |
| `payload_version` | `AnyDesk 9.0.5[.]0` | 否 | 静态 |
| `payload_signer` | `CN=AnyDesk Software GmbH, O=AnyDesk Software GmbH, C=DE (DigiCert 代码签名, 状态 Valid)` | 否 | 静态 |
| `c2_hosts` | `boot[.]net[.]anydesk[.]com` | 是 | 静态 |
| `c2_port` | `443;80;6568` | 否 | 静态 |
| `network_methods` | `connect:443;connect:80;socks:443;direct:443;direct:80;direct:6568` | 否 | 静态 |
| `archive_format` | `RAR5 SFX, 归档起始偏移 0x4FC00, 方法 v6:8M:m3` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得声称存在进程注入或镂空：内存扫描仅见模块头对齐差异（REALIGNED 转储），模块路径即磁盘上的 C:\SOPORTE ONLINE\Anydesk.exe，未见替换/植入 PE 或 shellcode。
- 不得把内层 AnyDesk 判定为定制木马或后门变种：其为 AnyDesk Software GmbH 官方签名 9.0.5 客户端，未发现被修改的代码段或自有配置注入。
- 不得报告勒索、窃密或持久化行为：未观察到文件加密、凭据读取、数据打包外传，也未观察到服务安装、Run 键或计划任务创建。
- 不得声称已与攻击者 C2 建立会话：仅见对 AnyDesk 官方引导服务器 boot[.]net[.]anydesk[.]com 的 DNS 查询与 TCP 连接尝试，未取得完整请求/响应。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `12c8bece29b5d0ce88f8e0d0cc339f6f90803e1ad80898c658e188f50b6f997e`） |

**局限与待验证**

1. 动态观测窗口约 2 分钟，未观察到完整 AnyDesk 会话：无 relay-*.net.anydesk.com 解析、无完整 TLS 交互，因此 C2 会话能力未验证，相关项保留 pending_dynamic_verify。
2. 未捕获 %APPDATA%\AnyDesk 下的配置文件写入，无法确认是否预置 AnyDesk ID 或无人值守口令；内存中仅见默认 boot_addrs / conn_methods。
3. 未观察到服务安装、Run 键、计划任务等持久化机制，不能排除在更长运行时间或用户交互后出现。
4. 外层 SFX 中的 IsDebuggerPresent、PEB 访问与 cpuid 属 CRT/SFX 常规代码，未观察到针对性反调试或反虚拟机逻辑，故不作为反分析结论。
5. 内层签名经系统校验为 Valid（证书链与时间戳均通过），未额外做签名摘要的人工复算。

## 证据索引

<details>
<summary>展开 21 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:5f945d0345` | 样本分诊 | 外层 PE 哈希/imphash/熵/加壳评分 0，6 个节，无异常 |
| `ref:f7cbe1aff3` | PE 结构解析 | 外层 PE32 GUI，入口 RVA 0x20780，SizeOfImage 487424，文件 5.97MB，存在大体积 overlay |
| `ref:4aca8d6961` | 导入表解析 | 仅 KERNEL32/OLEAUT32/gdiplus 共 155 个导入，符合 SFX 存根特征 |
| `ref:3686049d34` | bash (overlay carve) | 偏移 0x4FC00 处为 RAR5 头，注释含 Path=C:\SOPORTE ONLINE / Setup=AnyDesk.exe / Silent=1 / Overwrite=1 / Update=U |
| `ref:87b03789a1` | bash (archive list) | RAR5 归档含 1 个文件 Anydesk.exe，5,656,872 字节，条目时间 2025-04-24 |
| `ref:72447ee329` | bash (archive extract + hash) | 解出 Anydesk.exe，sha256=12c8bece29b5d0ce88f8e0d0cc339f6f90803e1ad80898c658e188f50b6f997e |
| `ref:7fc12ca22f` | PE 结构解析 | 内层 PE32 GUI，8 节，含 SECURITY 目录（Authenticode），无导入表（自解析） |
| `ref:a04be79c51` | openssl pkcs7 | 签名证书链: AnyDesk Software GmbH <- DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 <- DigiCert Trusted Root G4，含 DigiCert Timestamp 2024 |
| `ref:8f2214a302` | Get-AuthenticodeSignature | 内层 Status=Valid，Signer=CN=AnyDesk Software GmbH；外层 Status=NotSigned |
| `ref:e7c1f80b60` | bash (version resource) | 程序集版本 9.0.5[.]0，描述 AnyDesk screen sharing and remote control software |
| `ref:d8512f933c` | bash (resource strings) | 资源含 WinRAR self-extracting archive、Install、Extraction progress 等 SFX 向导字符串 |
| `ref:a43de593f0` | 动态分析平台 | 真实动态引爆完成：39 次轮询，1 个候选进程，10 个内存转储文件，产物 zip 已归档并回滚 |
| `ref:292dbb8687` | telemetry (process/file/DNS) | 样本 pid 1464 创建 C:\SOPORTE ONLINE\Anydesk.exe；AnyDesk 以空参/--local-service/--local-control 启动；持续查询 boot[.]net[.]anydesk[.]com |
| `ref:3b88b9183b` | telemetry (process create) | pid 5668/5040/3756 的完整命令行与工作目录，均指向 C:\SOPORTE ONLINE |
| `ref:69694ad529` | memory scan | 三个 Anydesk.exe 进程的 main_image_path=C:\SOPORTE ONLINE\Anydesk.exe，无 PE 替换/植入，仅头对齐差异 |
| `ref:306a7a2185` | network monitor | boot[.]net[.]anydesk[.]com 解析 15 次；Anydesk.exe 向 443/80/6568 各发起 5 次连接；另见 ocsp/crl[.]digicert[.]com |
| `ref:2c741353ae` | memory forensics | 运行时配置 ad.anynet.boot_addrs=boot[.]net[.]anydesk[.]com，conn_methods=connect:443;connect:80;socks:443;direct:443;direct:80;direct:6568，代理未启用 |
| `ref:0595b470af` | unpack.antidebug | 仅见 IsDebuggerPresent/PEB 访问/cpuid 等 CRT/SFX 常规代码，无针对性反分析 |
| `ref:c5a1c399c1` | telemetry (defender/amsi) | Defender 与 AMSI 均无相关事件；系统服务变化仅来自网络监控组件自身 |
| `telemetry:20b0dfbd` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 1 条；监控组件 进程/文件事件 134 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 22 条 |
| `etw:20b0dfbd:1464` | 进程事件监控 | 短命进程事件：20b0dfbd5078bcec058e44295d27b2e26b044bcd546e51802982e0d08fcfce19.exe（pid 1464；MD5=FA8012510E5487AD37FFAE0D202996CF,SHA256=20B0DFBD5078BCEC058E44295D27B2E26B044BCD546E51802982E0D08FCFCE19,IMPHASH=0AE9E38912FF6BD742A1B9E5C003576A） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
