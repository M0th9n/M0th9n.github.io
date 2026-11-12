---
title: "恶意样本分析：ChickenStealer（PE · exe · 859af3d0）"
published: 2026-11-11
draft: false
description: "恶意（置信度高）：ChickenStealer · stealer · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Chicken", "stealer", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ChickenStealer** · 置信度 **高**
> 
> 别名：ChickenStl、Disco、LummaStealer（个别引擎命名，未采用）
> 
> 样本为 x64 C++ 编写的全功能窃密木马：静态可见浏览器凭据/Cookie/信用卡/自动填充/历史窃取、钱包与 VPN/SSH 配置收集、剪贴板读取、桌面截屏、ZIP 打包，以及 Telegram Bot 外传；动态沙箱中实际观测到 IP 探测请求、Telegram sendMessage/sendPhoto/sendDocument 三个外传请求、PowerShell 添加 Defender 排除路径的子进程，以及对 127.0.0[.]1:8080 的回连尝试。静态与动态行为一致，判定为恶意窃密软件。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ChickenStealer** · 别名 ChickenStl、Disco、LummaStealer（个别引擎命名，未采用） |
| 置信度 | **高** |
| 行为类 | stealer |
| 难度 | medium |
| 首次出现 | 2026-11-10 12:11:57 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/859af3d02dbe7bc7ce1fba0396539b1fd37149615293c92e18def55e566b3294/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">反调试延迟启动</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口建互斥体</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">加 Defender 排除项</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注入浏览器取密钥</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">窃取浏览器凭据</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `859af3d02dbe7bc7ce1fba0396539b1fd37149615293c92e18def55e566b3294` |
| MD5 | _未记录_ |
| 大小 | 695,296 字节（679.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **9** 条静态可得、**2** 条经动态分析取得。

### 1. 反调试延迟启动

`T1622` · 置信度 **高** · 静态

启动后先 Sleep 8 秒，再依次用 IsDebuggerPresent、CheckRemoteDebuggerPresent、PEB.BeingDebugged/NtGlobalFlag 与 NtQueryInformationProcess(ProcessDebugPort=7、ProcessDebugFlags=0x1e) 检测调试器；命中则弹窗 'Im sorry but you cant debug this application!' 并 ExitProcess。

> **证据**：0x140019210 反编译：Sleep(8000)、IsDebuggerPresent、CheckRemoteDebuggerPresent、GetProcAddress(ntdll!NtQueryInformationProcess)、MessageBoxA/ExitProcess
> 
> **来源**：`ev-000014`

### 2. 隐藏窗口建互斥体

`T1564.003` · 置信度 **高** · 静态

隐藏控制台窗口并创建全局互斥体 Global\WinHost_SysUpdate_88492019，若已存在（ERROR_ALREADY_EXISTS）则直接退出，实现单实例驻留。

> **证据**：0x140019210：GetConsoleWindow/ShowWindow(hwnd,0)/FreeConsole；0x19325 CreateMutexA('Global\\WinHost_SysUpdate_88492019')，GetLastError==0xB7 分支
> 
> **来源**：`ev-000014`

### 3. 加 Defender 排除项

`T1562.001` · 置信度 **高** · 动态

检查自身是否以管理员权限运行；若是，则通过 CreateProcessA 启动隐藏窗口的 PowerShell，执行 Add-MpPreference -ExclusionPath 将自身路径加入 Defender 排除列表。动态中确实观察到该 PowerShell 子进程（PID 5480），但收尾时排除列表为空，未能确认写入成功。

> **证据**：0x140009dc0：OpenProcessToken/GetTokenInformation(TokenElevation) → CreateProcessA('powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath @(\'<自身路径>\')"')；动态 监控组件 子进程 PID 5480
> 
> **来源**：`ev-000013` · `ev-000028`

### 4. 注入浏览器取密钥

`T1055` · 置信度 **高** · 静态

在挂起状态下 CreateProcessW 启动目标浏览器进程，向其中写入 0x330 字节 shellcode 与 0x8a8 字节参数块，CreateRemoteThread 执行后 ReadProcessMemory 取回 32 字节结果；该路径用于调用 IElevator COM 接口解密 Chrome app_bound_encrypted_key（App-Bound Encryption）。

> **证据**：0x14002f3c0：LoadLibraryA(ole32/oleaut32)、GetProcAddress(CoInitializeEx/CoCreateInstance/CoSetProxyBlanket)、CreateProcessW(CREATE_SUSPENDED)、VirtualAllocEx、WriteProcessMemory(FUN_14002b660 shellcode)、CreateRemoteThread、ReadProcessMemory、TerminateProcess
> 
> **来源**：`ev-000021`

### 5. 窃取浏览器凭据

`T1555.003` · 置信度 **高** · 静态

遍历 Chrome/Edge/Brave/Opera/Vivaldi/Yandex/360/QQ 等 Chromium 系与 Firefox/Waterfox/LibreWolf 配置目录，导出 Login Data 口令、Cookies、信用卡、自动填充与历史记录，并按 Netscape 格式落地为 Cookies.txt/Logins.txt/BankCards.txt/Autofills.txt/History.txt。

> **证据**：0x140031d20 扫描 User Data\<Profile>\Login Data、Local State、Cookies；SQL 'SELECT origin_url, username_value, password_value FROM logins'、'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, cvc_encrypted FROM credit_cards'；字符串 @0x86d80/0x86e70/0x87060
> 
> **来源**：`ev-000026` · `ev-000010`

### 6. 收集钱包与配置

`T1005` · 置信度 **高** · 静态

搜索 wallet.dat、Exodus/Electrum/Atomic 等桌面钱包数据，以及 MetaMask/Phantom/Rabby 等浏览器扩展的 Local Extension Settings；同时收集 VPN/代理（WireGuard、OpenVPN、Clash、v2rayN）、云与开发凭据（.aws、.azure、.kube、.docker、.git-credentials、.npmrc）及 SSH/RDP 客户端会话。

> **证据**：字符串区 0x8b288–0x8b630（wallets/wallet.dat/MetaMask/Exodus/扩展 ID）、0x86048–0x86138（.aws/.kube/.docker/.git-credentials/.npmrc）、0x885f8（Terminal Server Client）；由 CryptoModule/AdminDevModule 分发执行
> 
> **来源**：`ev-000010`

### 7. 截屏并读剪贴板

`T1113` · 置信度 **中** · 静态

通过 GDI 创建兼容位图并 BitBlt 抓取桌面，经 GDI+ 保存为 screenshot.jpg；同时读取剪贴板文本写入 Clipboard.txt，随报告一并外传。

> **证据**：导入 GDI32!CreateCompatibleDC/CreateCompatibleBitmap/BitBlt 与 gdiplus!GdipCreateBitmapFromHBITMAP/GdipSaveImageToFile；0x14000ad90 调用 OpenClipboard/GetClipboardData/CloseClipboard；字符串 'screenshot.jpg'@0x858c0、'Clipboard.txt'@0x850c8
> 
> **来源**：`ev-000010` · `ev-000016`

### 8. 打包日志为 ZIP

`T1560.001` · 置信度 **高** · 静态

在 %TEMP% 下按 PID+时间戳创建暂存目录，收集各模块输出后打包为 ChickenLogs.zip，并生成 Summary.txt/Information.txt 报告。

> **证据**：0x1400033a0 调 GetTempPathA 并用 '~tmp_' 前缀+PID+TickCount 组目录；0x14000c370 汇总 Brute.txt/Tokens.txt/Cookies.txt/History.txt 等并写 'ChickenLogs.zip'（字符串 @0x858e8/0x855e0）
> 
> **来源**：`ev-000027` · `ev-000016`

### 9. Telegram 外传数据

`T1567.002` · 置信度 **高** · 动态

用内置 bot token 与 chat_id 调用 Telegram Bot API：sendMessage 发送受害主机概况（HTML 格式），sendPhoto 发送桌面截图，sendDocument 发送 ChickenLogs.zip。

> **证据**：0x140010cc0 拼 'hxxps://api[.]telegram[.]org/bot<token>/sendMessage'；0x140010810 '/sendPhoto'；0x140010360 '/sendDocument'（application/zip）；动态网络监控记录三个 POST 请求
> 
> **来源**：`ev-000020` · `ev-000024` · `ev-000028`

### 10. 回连 HTTP 网关

`T1071.001` · 置信度 **中** · 静态

将 ZIP 以 multipart/form-data 形式 POST 到配置中的 hxxp://127.0.0[.]1:8080/gate 与 /api/gate（构建期占位地址）；沙箱内仅观察到对 127.0.0[.]1:8080 的 TCP 连接尝试，未建立 HTTP 会话。

> **证据**：0x14000fe70/0x1400100f0 → 0x1400116b0（----WebKitFormBoundary multipart POST，application/zip）；配置由 0x1400031b0 写入；动态仅见 'requested TCP 127.0.0[.]1:8080'
> 
> **来源**：`ev-000012` · `ev-000023` · `ev-000028`

### 11. 枚举主机与游戏信息

`T1082` · 置信度 **高** · 静态

收集计算机名/用户名/HWID(注册表 MachineGuid)/CPU/GPU/内存/磁盘/电源/主板/BIOS、已安装软件、Wi-Fi 配置（WLAN API 取 keyMaterial）、USB/便携设备、进程列表，以及 Steam/Epic/Riot/Minecraft/米哈游等游戏账号数据。

> **证据**：0x140019210 依序实例化 SystemInfoModule→BrowserModule→MessengerModule→ScreenshotModule→AIModule→CryptoModule→SoftwareModule→GamesModule→WifiModule→AdminDevModule；字符串 0x8b020–0x8b1c0（hwid/cpu/bios/ProductKey）与 0x8b630 WLAN API 导入
> 
> **来源**：`ev-000014` · `ev-000010`


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
| telegram | `hxxps://api[.]telegram[.]org/bot8919186852:AAEjTtp7vwrqRVtKiiHSVe2vCXiqQJX8sDc/sendDocument` | 443 | exfil | 动态 | 已观测 |
| http | `hxxp://127[.]0[.]0[.]1:8080/gate` | 8080 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxp://127[.]0[.]0[.]1:8080/api/gate` | 8080 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://api[.]ipify[.]org；hxxps://ipv4[.]icanhazip[.]com；hxxps://checkip[.]amazonaws[.]com；hxxps://api64[.]ipify[.]org；hxxps://icanhazip[.]com` | 443 | other | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `Global\WinHost_SysUpdate_88492019`

**落地路径**

- `%TEMP%\~tmp_<pid>_<tick>\`
- `%TEMP%\~sys_<pid>_<tick>\`
- `%TEMP%\ChickenLogs.zip`
- `%TEMP%\screenshot.jpg`
- `%TEMP%\<staging>\Browsers\`
- `%TEMP%\<staging>\Wallets\`
- `%TEMP%\<staging>\Games\`
- `%TEMP%\<staging>\Wifi_Networks.txt`
- `%TEMP%\<staging>\Clipboard.txt`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxp://127[.]0[.]0[.]1:8080/gate; hxxp://127[.]0[.]0[.]1:8080/api/gate（构建期占位地址）` | 是 | 静态 |
| `telegram_bot_token` | `8919186852:AAEjTtp7vwrqRVtKiiHSVe2vCXiqQJX8sDc` | 是 | 静态 |
| `telegram_chat_id` | `8980143221` | 是 | 静态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0[.]0 Safari/537.36` | 否 | 静态 |
| `mutex` | `Global\WinHost_SysUpdate_88492019` | 是 | 静态 |
| `staging_dir` | `%TEMP%\~tmp_ 或 %TEMP%\~sys_ + <pid>_<tick>` | 否 | 静态 |
| `archive_name` | `ChickenLogs.zip` | 否 | 静态 |
| `credential_decryption` | `浏览器 Local State/app_bound_encrypted_key 经进程注入调用 IElevator COM 解出 32 字节密钥，再用 BCrypt(AES-GCM) 解 Login Data/Cookies；Firefox 使用 logins.json 与 key4.db` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不是勒索软件或擦除器：未发现文件加密、卷影删除、勒索信或破坏性写入逻辑，所有收集行为均为窃取。
- 未观察到持久化：未见服务创建、计划任务或 Run/RunOnce 注册表写入，唯一的驻留机制是全局互斥体（单实例），不要报为持久化后门。
- 127.0.0[.]1:8080 是构建期占位（环回）地址，不能当作真实互联网 C2；沙箱内仅有 TCP 连接尝试，无 HTTP 会话。
- 不能因 CreateRemoteThread/VirtualAllocEx 就称其为通用进程注入器：注入目标为浏览器进程，用途是取 App-Bound Encryption 密钥。
- 动态中虽启动 Add-MpPreference 命令，但收尾时 Defender ExclusionPath 为空，不能断言排除项已成功写入。
- 不能称其为 LummaStealer：样本自证为 ChickenStealer，仅个别引擎给出 Lumma 命名。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 内置 C2（127.0.0[.]1:8080/gate、/api/gate）为回环占位地址，沙箱内只看到 TCP 连接尝试，没有 HTTP 请求/响应，故按静态恢复处理并保留动态待验证标记。
2. Telegram 的 HTTP 响应由沙箱假网络合成，只能证明样本发出携带 bot token 的外传请求，无法证明真实攻击者收到数据。
3. Defender 排除命令确实被启动，但收尾时排除列表为空，无法确认排除项写入成功。
4. 本次分析客体内没有真实浏览器凭据、钱包或 VPN 配置，未能观测到实际被窃取的数据内容与数量。
5. 未观察到持久化、横向移动、提权漏洞利用或勒索行为，不能据此扩展结论。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | SHA256/MD5/SHA1 与文件大小 695296 |
| `ev-000002` | scan.imphash | imphash=34ff47a53573aada51bd1f365b715f07 |
| `ev-000010` | 字符串提取 | 抽取配置、浏览器/钱包/Telegram 等字符串及地址 |
| `ev-000012` | decompile.ghidra | 0x1400031b0 拼接 gate URL、Telegram token、chat_id、UA |
| `ev-000013` | decompile.ghidra | 0x140009dc0 提权判断并启动 Add-MpPreference 排除路径 |
| `ev-000014` | decompile.ghidra | 0x140019210 反调试、互斥体与十个窃密模块分发 |
| `ev-000016` | decompile.ghidra | 0x14000c370 汇总各类日志并生成报告 |
| `ev-000020` | decompile.ghidra | 0x140010360 Telegram sendDocument 上传 ZIP |
| `ev-000021` | decompile.ghidra | 0x14002f3c0 启动浏览器进程并注入 shellcode 取回 32 字节密钥 |
| `ev-000023` | decompile.ghidra | 0x14000fe70 将 ZIP 以 multipart 上传至配置 URL |
| `ev-000024` | decompile.ghidra | 0x140010cc0 Telegram sendMessage 外传主机概况 |
| `ev-000026` | decompile.ghidra | 0x140031d20 遍历浏览器配置与 Login Data/Local State |
| `ev-000027` | decompile.ghidra | 0x1400033a0 在 %TEMP% 以 ~tmp_+PID+Tick 建立暂存目录 |
| `ev-000028` | evidence.record | 动态沙箱观测：DNS/IP 探测、Telegram 三接口 POST、PowerShell Add-MpPreference、127.0.0[.]1:8080 连接尝试 |
| `c2_evidence:859af3d0` | 连接证据提取 | 动态网络监控记录到 3 次到 api[.]telegram[.]org:443 的连接尝试；未捕获完整会话 |
| `telemetry:859af3d0` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 116 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:859af3d0:3412` | 进程事件监控 | 短命进程事件：859af3d02dbe7bc7ce1fba0396539b1fd37149615293c92e18def55e566b3294.exe（pid 3412；MD5=3FFE9B94FDD07511C2C8A92D0BF2E8CF,SHA256=859AF3D02DBE7BC7CE1FBA0396539B1FD37149615293C92E18DEF55E566B3294,IMPHASH=34FF47A53573AADA51BD1F365B715F07） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
