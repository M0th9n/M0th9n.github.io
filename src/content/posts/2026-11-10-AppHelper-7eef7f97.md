---
title: "恶意样本分析：AppHelper（PE · exe · 7eef7f97）"
published: 2026-11-10
draft: false
description: "恶意（置信度高）：AppHelper · stealer/rat · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["AppHelper", "stealer", "rat", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **AppHelper** · 置信度 **高**
> 
> 别名：Stealerium、AppCore、LimerBoy Stealer
> 
> 样本为 .NET 信息窃取器：反编译 IL 可见 AppHelper.Config 内嵌 CRYPTED: 配置、StringsCrypt 用 PBKDF2-SHA1(1000)+AES-256-CBC 解密，Collector/KeyLog/Swapper 模块覆盖浏览器凭据、Windows Vault、键盘记录、剪贴板钱包替换；在隔离 Windows 沙箱中真实执行（进程 1772），监控组件 内存转储中恢复出完整配置与 Telegram/Discord/AnonFiles 外传代码。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **AppHelper** · 别名 Stealerium、AppCore、LimerBoy Stealer |
| 置信度 | **高** |
| 行为类 | stealer · rat |
| 难度 | medium |
| 首次出现 | 2026-11-10 12:16:15 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/7eef7f970e715511722f09a3af6e503432e376542faa9386da6693ea2fb78f0a/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置配置</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">检测调试与虚拟机</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001, T1622</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">创建单实例互斥体</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Telegram外传报告</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1567, T1102</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Discord Webhook外传</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1567, T1102</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `7eef7f970e715511722f09a3af6e503432e376542faa9386da6693ea2fb78f0a` |
| MD5 | _未记录_ |
| 大小 | 185,856 字节（181.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解密内置配置

`T1140` · 置信度 **高** · 静态

AppHelper.Config 的 .cctor 将 Telegram/Discord/AnonFiles/钱包地址以 CRYPTED: 前缀内嵌；StringsCrypt.Decrypt 用 Rfc2898DeriveBytes(cryptKey,saltBytes,1000) 派生 AES-256-CBC 密钥在启动时解密。

> **证据**：Config::.cctor @rva 0x0C0B0 (49328) stsfld TelegramAPI; StringsCrypt::Decrypt @rva 0x13E6C (81516) set_KeySize(256)/set_BlockSize(128)/Rfc2898DeriveBytes/RijndaelManaged
> 
> **来源**：`ev-000008`

### 2. 检测调试与虚拟机

`T1497.001, T1622` · 置信度 **高** · 静态

EnvCheck 模块枚举 36 个分析进程(procmon/x64dbg/fakenet 等)、8 个沙箱 DLL(SbieDll/cmdvrt 等)、虚拟化平台/VirtualBox/QEMU 注册表与 BIOS/GPU 特征，命中硬特征即退出；软特征仅记录。

> **证据**：EnvCheck::.cctor @rva 0x10D9C 字符串表 'processhacker','x64dbg','fakenet','SbieDll','vmware','virtualbox'; VmArtifacts/Debugger/Emulator 方法
> 
> **来源**：`ref:707878d0db` · `ev-000006`

### 3. 创建单实例互斥体

`T1480` · 置信度 **中** · 静态

以配置中的 Mutex 值 abb688d8ca89c08e610c7b9ce42819db 创建互斥体，避免同一受害机上重复运行。

> **证据**：Config::.cctor stsfld Mutex; AppHelper.Core.MutexControl 类; 内存字符串 'Global\'
> 
> **来源**：`ev-000008` · `ref:707878d0db`

### 4. Telegram外传报告

`T1567, T1102` · 置信度 **高** · 静态

通过 api[.]telegram[.]org/bot<token> 的 sendMessage/sendDocument/sendPhoto/editMessageText 接口把系统信息、凭据归档、截图与键盘记录发送到 chat_id -5360484904，并用 getUpdates 轮询指令。

> **证据**：字符串 'hxxps://api[.]telegram[.]org/bot','/sendDocument','/getUpdates?timeout=25&offset=','{"chat_id":"'; Telegram::SendReport/SendDocument
> 
> **来源**：`ev-000008` · `ref:707878d0db` · `ev-000006`

### 5. Discord Webhook外传

`T1567, T1102` · 置信度 **高** · 静态

通过配置中的 Discord webhook 发送 JSON 文本与 multipart 文件（report.png、压缩包），作为 Telegram 之外的备用外传通道。

> **证据**：字符串 '{"content":"","username":"AppHelper"}','application/json','files[0]','report.png'; AppHelper.DiscordWebhook 类
> 
> **来源**：`ev-000008` · `ref:707878d0db`

### 6. 窃取浏览器凭据

`T1555.003` · 置信度 **高** · 静态

收集 Chromium/Edge/Firefox 的 Login Data、Web Data、Cookies、History、Bookmarks，用 DPAPI/AES-GCM(app_bound)/NSS PK11SDR 解密口令、Cookie 与信用卡数据。

> **证据**：Collector.Chromium::Crypto/Cookies/Passwords, Collector.Firefox::Decryptor(NSS_Init/PK11SDR_Decrypt), 字符串 'Login Data','Local State','logins.json','app_bound_encrypted_key'
> 
> **来源**：`ref:707878d0db` · `ev-000006`

### 7. 窃取Windows凭据

`T1555.004` · 置信度 **高** · 静态

调用 CredEnumerateW、VaultGetItem_WIN7/WIN8 枚举 Windows 凭据管理器与 IE/Edge Vault 条目，配合 CryptUnprotectData 还原明文口令。

> **证据**：字符串 'CredEnumerateW','VaultGetItem_WIN7','VaultGetItem_WIN8','CryptUnprotectData'; Collector.InternetExplorer::VaultCli / CredentialManager
> 
> **来源**：`ref:707878d0db` · `ev-000006`

### 8. 键盘记录

`T1056.001` · 置信度 **高** · 静态

SetWindowsHookEx(WH_KEYBOARD_LL) 低级键盘钩子持续记录按键，按日期写入 logs\keylogger 并打包发送 Telegram。

> **证据**：字符串 'WHKEYBOARDLL','LowLevelKeyboardProc','logs\\keylogger\\'; KeyLog::SetHook/HookCallback/StartKeyLog
> 
> **来源**：`ref:707878d0db` · `ev-000006`

### 9. 截屏与摄像头采集

`T1113` · 置信度 **高** · 静态

DesktopScreenshot 通过 GDI 抓取桌面保存 Desktop.jpg；WebcamScreenshot 用 capCreateCaptureWindowA 抓取摄像头（本配置 WebcamScreenshot=0 关闭）。

> **证据**：字符串 'capCreateCaptureWindowA','\\Desktop.jpg','\\Webcam.jpg','WebcamScreenshot : Camera screenshot failed'; Config::.cctor WebcamScreenshot='0'
> 
> **来源**：`ev-000008` · `ref:707878d0db` · `ev-000006`

### 10. 替换剪贴板钱包地址

`T1115` · 置信度 **高** · 静态

Swapper 监视剪贴板中的 btc/eth/xlm/ltc/bch 地址并替换为攻击者钱包，劫持转账目标。

> **证据**：Config::.cctor SwapperAddresses 的 5 个 decrypt 后钱包地址; Swapper::Clipboard/EventManager/RegexPatterns
> 
> **来源**：`ev-000008` · `ref:707878d0db`

### 11. 植入开机自启动

`T1547.001, T1053.005` · 置信度 **高** · 静态

Startup 模块向 HKCU\...\CurrentVersion\Run 写入 MicrosoftEdgeUpdateCore，并创建同名计划任务与启动文件夹快捷方式 MicrosoftEdgeUpdateCore.lnk，伪装成 Edge 更新。

> **证据**：字符串 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','MicrosoftEdgeUpdateCore','MicrosoftEdgeUpdateCore.lnk','/C schtasks /Create /F /TN MicrosoftEdgeUpdateCore'; Startup::Install/CreateTask/CreateStartupShortcut
> 
> **来源**：`ref:707878d0db` · `ev-000006`

### 12. Telegram远程控制

`T1059.003, T1105` · 置信度 **高** · 静态

RemoteControl 轮询 getUpdates 解析 /cmd、/download、/grab、/screenshot、/camera、/keylogs、/report、/uninstall，执行 shell、下载并运行文件、打包回传与自毁。

> **证据**：字符串 '/getUpdates?offset=-1','/cmd <command> - run shell command','cmd.exe','/download <url> - download + run','uninstalling, bye'; AppHelper.RemoteControl 16 个方法
> 
> **来源**：`ref:707878d0db` · `ev-000006`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot8813953757:AAHbLwK_WJwDWt5jEZATB71y6LCG7lcW2hY` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://discord[.]com/api/webhooks/1568282257024614400/nDixFRFIsi4Km2okO7_L_1a64TRdnNhhBoDYUed-_knUfChzlztu7hSfGrKpqt6iHfk9` | 443 | exfil | 静态 | ⏳ 未观测 |
| http | `hxxps://api[.]anonfilesnew[.]com/upload?key=AFuoJboasAXaRNSEPMB2XxHztd80488b` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `abb688d8ca89c08e610c7b9ce42819db`

**落地路径**

- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\MicrosoftEdgeUpdateCore.lnk`

**注册表**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeUpdateCore`

**计划任务**

- `MicrosoftEdgeUpdateCore`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org, discord[.]com, api[.]anonfilesnew[.]com` | 是 | 静态 |
| `telegram_bot_token` | `8813953757:AAHbLwK_WJwDWt5jEZATB71y6LCG7lcW2hY` | 是 | 静态 |
| `telegram_chat_id` | `-5360484904` | 是 | 静态 |
| `discord_webhook` | `hxxps://discord[.]com/api/webhooks/1568282257024614400/nDixFRFIsi4Km2okO7_L_1a64TRdnNhhBoDYUed-_knUfChzlztu7hSfGrKpqt6iHfk9` | 是 | 静态 |
| `anonfiles_api_key` | `AFuoJboasAXaRNSEPMB2XxHztd80488b` | 否 | 静态 |
| `mutex` | `abb688d8ca89c08e610c7b9ce42819db` | 是 | 静态 |
| `version` | `1.5` | 是 | 静态 |
| `build_id` | `build 2026-11-06 0726` | 是 | 静态 |
| `encryption_algo` | `AES-256-CBC + PBKDF2-SHA1(1000, salt 16B) for embedded config; DPAPI/AES-GCM/NSS for browser secrets` | 是 | 静态 |
| `wallet_swap_addresses` | `btc=bc1qq60adlr3hgkhtrdtfssyhtc3le2nnzyl0ttsfn; eth=0x413c0bD3328D0d0ED060212d67dEa94035d757d7; xlm=GAKBKOBKFX3GFPT3RXWHKBACLZPZEHZBV2GX34X7AO3MDUEVPNEOUGFT; ltc=LgpHxu9igHZyy2EUrFXSpHgTKakrTLv2se; bch=qrlmd760p6weruha00ljypkqkaqly0ndcgv2zdemqt` | 否 | 静态 |
| `second_stage_url` | `--- (disabled)` | 否 | 静态 |
| `module_flags` | `EnvCheck=1,Autorun=1,StartDelay=1,StayAwake=1,KeyLogModule=1,SwapperModule=1,WebcamScreenshot=0` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 样本不是勒索软件：AES/BCrypt 仅用于解密内嵌配置与浏览器/凭据数据，未发现文件加密或勒索提示。
- 样本不是纯下载器/投放器：SecondStageUrl 配置为 '---'(禁用)，主体为完整信息窃取器；不能因存在 SecondStage 类就断定其执行了二阶段下载。
- 字符串命中 'z0{0|0}' 是该程序字符表/键盘布局数据的一部分，不是 flag，不应作为 IOC 或答案。
- 本次运行未观测到 Telegram/Discord/AnonFiles 的请求或会话；不得声称 C2 已上线或数据已外传。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. C2/外传配置经静态解密恢复（AES-256-CBC），非动态会话；动态侧未观察到任何 Telegram/Discord/AnonFiles DNS 或 HTTP 请求，按规则标 static + pending_dynamic_verify。
2. 运行期 telemetry 的 Run 键、服务、计划任务前后一致，未观测到自启动项真正写入；Autorun/计划任务/启动快捷方式为静态代码证据。
3. WebcamScreenshot 在配置中关闭，键盘记录/截图/剪贴板替换是否实际产出文件未在本次运行中观测到。
4. 家族命名存在口径差异：样本产品名为 AppHelper，代码模块与 Stealerium 开源家族高度一致，已以别名列出。

## 证据索引

<details>
<summary>展开 18 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=7eef7f...78f0a; md5=77c0461e5d6c4bbd72c822755dbf0a41 |
| `ev-000004` | 样本分诊 | 2 节区, 0 导入, 加壳可能性 0.25 |
| `ev-000002` | scan.entropy | .text 熵 5.773（未加壳） |
| `ev-000006` | 字符串提取 | 抽取 1462 ASCII/1094 UTF-16 字符串，含 AppHelper/Collector/Telegram/Discord/Vault 等 |
| `ev-000005` | 字符串提取 | 'z0{0\|0}' 命中为字符表片段，非 flag |
| `ev-000007` | decompile.function | Main @0x14001066c 为 CIL，Ghidra 无法还原（仅确认 .NET 托管代码） |
| `ev-000008` | evidence.record | dnfile/dncil 静态解析 IL 并解密 CRYPTED 配置，得到 Telegram/Discord/AnonFiles/钱包/互斥体 |
| `ref:ad8dd73ad4` | 样本分诊 | M1 分诊：无导入、无导出、.text/.rsrc 两节 |
| `ref:ae0e6610bf` | PE 结构解析 | AMD64 .NET GUI，image base 0x140000000，入口 0x140000000，仅 .text/.rsrc |
| `ref:707878d0db` | decompile.symbols | 536 个具名函数：Config/StringsCrypt/Collector/KeyLog/Swapper/Telegram/RemoteControl/Startup/EnvCheck |
| `ref:410b576bd0` | unpack.detect | 未加壳（confidence 0.45，仅导入极少信号） |
| `ref:c427626ee0` | unpack.antidebug | 静态反调试特征 0（反分析逻辑在托管 EnvCheck 中，非原生） |
| `ref:bdf95c4503` | 动态分析平台 | 样本已投放至隔离 win10 客体自动引爆目录 |
| `ref:046671c19f` | 动态分析平台 | 进程 1772 运行 C:\dyn\samples\...exe，网络监控/监控组件 在线 |
| `ref:a73bad2313` | 内存转储 | 监控组件 定点转储 PID 1772，得到 184MB 内存与 .NET 模块 |
| `ref:2ab362c722` | 动态产物收集 | 收集 网络监控/ETW/telemetry/监控组件 产物（zip 158MB） |
| `telemetry:7eef7f97` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 4 条；监控组件 进程/文件事件 99 条；ETW 短命进程事件 1 条；系统服务事件 4 条；已过滤工具/系统噪声 27 条 |
| `etw:7eef7f97:1772` | 进程事件监控 | 短命进程事件：7eef7f970e715511722f09a3af6e503432e376542faa9386da6693ea2fb78f0a.exe（pid 1772；MD5=77C0461E5D6C4BBD72C822755DBF0A41,SHA256=7EEF7F970E715511722F09A3AF6E503432E376542FAA9386DA6693EA2FB78F0A,IMPHASH=00000000000000000000000000000000） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
