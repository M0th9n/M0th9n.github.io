---
title: "恶意样本分析：Menace Hub（PE · exe · 6fe7a4ec）"
published: 2026-11-25
draft: false
description: "恶意（置信度中）：Menace Hub · stealer/rat/backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Menace Hub", "stealer", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Menace Hub** · 置信度 **中**
> 
> 别名：MenaceAgent、MENACE HUB v3.5、Menace Stealer/RAT
> 
> 反编译确认样本具备完整的窃密与远控能力：启动早期还原 ntdll .text、改写 AMSI 与 ETW 函数、以 NtSetInformationThread 隐藏线程；通过 Discord Bot API 轮询指令并回传文件；窃取浏览器 Cookie/口令/信用卡、Discord 与 Roblox 令牌及多种加密钱包；具备键盘记录、截屏、摄像头与麦克风采集；并写 Run 键与 ONLOGON 计划任务实现自启。该样本在隔离 Windows 10 沙箱中成功执行（PID 2860），但因未携带 MNC2 配置尾部（无 webhook/bot token）未产生外联；恶意意图与能力证据充分。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Menace Hub** · 别名 MenaceAgent、MENACE HUB v3.5、Menace Stealer/RAT |
| 置信度 | **中** |
| 行为类 | stealer · rat · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-25 11:07:49 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/6fe7a4eca94dde26b24d00d6e7688dba77c855b17bd65d553d4f4096252a7d23/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">瘫痪AMSI与调试检测</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001, T1622</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">读取并解密内置配置</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">轮询Discord指令</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">远程Shell与文件收发</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001, T1059.003, T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">沙箱内单进程运行</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `6fe7a4eca94dde26b24d00d6e7688dba77c855b17bd65d553d4f4096252a7d23` |
| MD5 | _未记录_ |
| 大小 | 1,933,312 字节（1.8 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **10** 条静态可得、**2** 条经动态分析取得。

### 1. 瘫痪AMSI与调试检测

`T1562.001, T1622` · 置信度 **高** · 静态

启动早期从 System32 读取 ntdll.dll 并覆盖内存中的 .text 段以清除用户态 hook；定位并改写 amsi!AmsiScanBuffer 为 mov eax,0x80070005; ret，改写 ntdll!EtwEventWrite 为 xor eax,eax; ret，并调用 NtSetInformationThread(ThreadHideFromDebugger=0x11) 隐藏线程；同时以 FNV-1a 哈希动态解析 API 规避导入表痕迹。

> **证据**：FUN_140135e00 @0x135e00（ntdll .text 还原、AMSI/ETW 补丁）；0x136048 mov edx,0x11 + call NtSetInformationThread；哈希解析循环使用 0x14650fb0739d0383 基值
> 
> **来源**：`ev-000015` · `ev-000019`

### 2. 读取并解密内置配置

`T1140` · 置信度 **高** · 静态

通过 GetModuleFileNameW 取得自身路径并以 CreateFileW 读取整个文件，校验文件尾部 4 字节是否等于魔数 'MNC2'（0x32434e4d）及其前置长度字段；使用 xorshift32(seed=0xf975b183) 解出 28 字节默认 API 基址 hxxps://discord[.]com/api/v10，并允许环境变量 MENACE_API_BASE 覆盖。本样本尾部无 MNC2，因此未加载 webhook/bot token。

> **证据**：配置加载器 0x13641b cmp dword,0x32434e4d；GetModuleFileNameW@0x64d00；CreateFileW@0x2ee7d；解密函数 FUN_1400632c0 @0x632c0；密文 rva 0x1529c0
> 
> **来源**：`ev-000016` · `ev-000019`

### 3. 轮询Discord指令

`T1071.001` · 置信度 **高** · 静态

以 'Authorization: Bot <token>' 头轮询 Discord 的 /channels/<channel_id>/messages?limit=25&after=<id>，解析 author/content 下发命令；支持 !sh、!ps、!ls、!cat、!find、!rm、!get、!put、!dl、!zip、!kill、!shot、!cam、!mic、!play、!wall、!keylog、!grab 等指令，并以 multipart（payload_json + files[0]）回传结果与文件。

> **证据**：字符串 /messages?limit=25&after= (0x13d05a)、Content-Disposition: form-data; name="payload_json" (0x13d5a8)、命令表 0x140076-0x140bca；WinHttpSendRequest@0x43ba0；'Bot ' 前缀 0x140999
> 
> **来源**：`ev-000014` · `ev-000019`

### 4. 远程Shell与文件收发

`T1059.001, T1059.003, T1105` · 置信度 **高** · 静态

通过 CreateProcessW 启动 cmd.exe /c（chcp 65001）或 powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File <临时 .ps1>，把输出截断/超时后回传；支持上传（!put 从 URL 下载写入）、下载（!get 读取文件）、目录列举、打包 zip 与按 PID 终止进程。

> **证据**：CreateProcessW 调用点 0x31124 / 0x3cb8e / 0x4f382；字符串 cmd.exe /c chcp 65001>nul & (0x13e950)、powershell.exe -NoProfile -NonInteractive ... -File (0x13e9f0)、mh_%lu_%d.ps1
> 
> **来源**：`ev-000014` · `ev-000019`

### 5. 采集主机与安软信息

`T1082, T1016, T1552.001` · 置信度 **高** · 静态

枚举 WTS 会话，读取注册表 Windows 版本、CPU/GPU 描述、已安装软件、Defender 实时保护与排除路径，执行 netsh advfirewall 与 netsh wlan show profile name=... key=clear 获取防火墙状态和 WiFi 明文口令，并访问 hxxps://ipwho.is/ 获取公网 IP 与国家/时区，生成 recon 报告。

> **证据**：字符串 $ErrorActionPreference='SilentlyContinue'; Get-CimInstance ... AntiVirusProduct (0x13ec78)、cmd.exe /c chcp 65001>nul & netsh wlan show profile name= (0x13eef8)、hxxps://ipwho.is/ (0x13d106)；WTSEnumerateSessionsW / WTSQuerySessionInformationW 导入
> 
> **来源**：`ev-000014` · `ev-000019`

### 6. 窃取浏览器凭据钱包

`T1555.003, T1555, T1539` · 置信度 **高** · 静态

对 Chrome、Edge、Brave、Chromium、Vivaldi、Yandex、Opera 的 Cookies、Login Data、Web Data 执行 SQLite 查询，使用 DPAPI 与 BCrypt AES-GCM 解密 cookies/logins/credit_cards；遍历 Exodus、Electrum、Atomic、Coinomi、Bitcoin/Litecoin/Dogecoin/Ethereum/Monero/Zcash、Guarda、Binance、Coinbase Wallet、Ledger Live、Trezor Suite、Phantom、Solflare 及 MetaMask 等扩展目录，将钱包文件打包为 zip。

> **证据**：SELECT host_key,name,encrypted_value... (0x13dad0)；CryptUnprotectData@0x4c651；钱包路径 utf16 0x13f870-0x13fe28；No known wallet files 提示 0x1404f8
> 
> **来源**：`ev-000014` · `ev-000019`

### 7. 窃取聊天与游戏令牌

`T1528, T1539` · 置信度 **高** · 静态

扫描 %APPDATA% 下 discord/discordptb/discordcanary 的 Local Storage\leveldb 中 .ldb/.log，提取 token 候选并调用 /users/@me 校验有效性；读取 .ROBLOSECURITY Cookie，并请求 hxxps://users[.]roblox[.]com/v1/users/authenticated 判定账号活跃/封禁状态。

> **证据**：utf16 0x13d788 Local Storage\leveldb、0x13d49d .ROBLOSECURITY、0x141228 hxxps://users[.]roblox[.]com/v1/users/authenticated；ascii 0x13d350 /users/@me、0x140388 no discord token in LevelDB
> 
> **来源**：`ev-000014` · `ev-000019`

### 8. 键盘记录按键

`T1056.001` · 置信度 **高** · 静态

调用 SetWindowsHookExW 安装低级键盘钩子，并配合 GetAsyncKeyState 记录按键，转换为 [TAB]/[BKSP]/[ESC]/[CAPS]/[DEL]/方向键等标记后写入 .keys 日志；支持 !keylog start/stop/dump/clear 远程控制。

> **证据**：SetWindowsHookExW 调用点 0x46827；GetAsyncKeyState 调用点 0x65025；字符串 [TAB] (0x13f094)、hook installed - keys land in .keys (0x140620)
> 
> **来源**：`ev-000019` · `ev-000014`

### 9. 截屏录音与摄像头

`T1113, T1125, T1123` · 置信度 **高** · 静态

使用 GetDC+BitBlt 抓取屏幕并用 GDI+ 编码为 PNG；通过 Media Foundation（MFEnumDeviceSources/MFCreateSourceReaderFromMediaSource）采集摄像头单帧；通过 waveInOpen/waveInStart 录制 RIFF/WAV 音频，结果以 multipart 上传。

> **证据**：BitBlt 调用点 0x36ed7；waveInOpen 调用点 0x2f1eb；GdipSaveImageToStream / GdipGetImageEncoders 导入；字符串 webcam unavailable (0x14032d)、no input device / mic blocked (0x1402e5)
> 
> **来源**：`ev-000019` · `ev-000014`

### 10. 拷贝自身并开机自启

`T1547.001, T1053.005` · 置信度 **高** · 静态

把自身复制为 %LOCALAPPDATA%\MENACE_HUB\MenaceAgent.exe 与 %APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe；向 HKCU\Software\Microsoft\Windows\CurrentVersion\Run 写入 MENACE_UPDATER 与 EdgeUpdateCore 值，并执行 schtasks /Create /F /SC ONLOGON /TN <name>；当 MENACE_PERSIST_DRYRUN 非空时跳过注册表与计划任务。

> **证据**：FUN_140057b90 @0x57b90 中 RegCreateKeyExW(Run) + RegSetValueExW；FUN_140066510 @0x66510 拼接 'schtasks /Create /F /SC ONLOGON /TN '；字符串 EdgeUpdateCore/MENACE_UPDATER (utf16 0x13cf6c)
> 
> **来源**：`ev-000017` · `ev-000018`

### 11. 沙箱内单进程运行

`T1204.002` · 置信度 **高** · 动态

该样本在隔离 Windows 10 沙箱中被投放并以原文件名启动（PID 2860，进程创建事件 2026-11-25 18:08:56 UTC），整个观察窗口内只出现这一个候选进程，未创建子进程。

> **证据**：动态监控时间线 events[0] pid=2860、name=<sha256>.exe；系统进程创建事件 CommandLine="C:\dyn\samples\<sha256>.exe"；PE 内存扫描未发现注入/hollowing
> 
> **来源**：`ev-000020`

### 12. 运行期无网络外联

`T1071.001` · 置信度 **高** · 动态

观察窗口 02:08:57–02:11:59 内，该 PID 未产生任何 DNS/HTTP/HTTPS 请求，未连接 discord[.]com；与样本未携带 MNC2 配置（无 webhook/bot token）一致，说明此构建在缺少配置时不会建立 C2。

> **证据**：网络监控日志在该时间段无 pid 2860 的请求记录；遥测中 Run 键/服务/计划任务无 MenaceAgent/MENACE_UPDATER/EdgeUpdateCore 新增
> 
> **来源**：`ev-000020`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://discord[.]com/api/v10` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://discord[.]com/api/webhooks/<webhook_id>/<webhook_token>（由 MNC2 配置提供，本样本未包含）` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `Local\MenaceAgentV2`

**落地路径**

- `%LOCALAPPDATA%\MENACE_HUB\MenaceAgent.exe`
- `%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`
- `%LOCALAPPDATA%\MENACE_HUB\.agent`
- `%LOCALAPPDATA%\MENACE_HUB\.agent_cursor`
- `%LOCALAPPDATA%\MENACE_HUB\.jobs`
- `%APPDATA%\.keys`
- `%TEMP%\mh_<pid>_<n>.db`
- `%TEMP%\mh_<pid>_<n>.ps1`
- `%TEMP%\mh_play_<n>.wav`
- `%TEMP%\mh_wall_<n>.png`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MENACE_UPDATER`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EdgeUpdateCore`

**计划任务**

- `MENACE_UPDATER`
- `EdgeUpdateCore`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_api_base` | `hxxps://discord[.]com/api/v10` | 是 | 静态 |
| `c2_webhook` | `由 exe 尾部 MNC2 配置提供；本样本尾部无 MNC2，未包含` | 是 | 静态 |
| `bot_token` | `由 exe 尾部 MNC2 配置提供；本样本未包含` | 是 | 静态 |
| `config_container` | `exe 尾部：4 字节大端长度 + 配置体 + 魔数 'MNC2'（0x32434e4d）` | 是 | 静态 |
| `mutex` | `Local\MenaceAgentV2` | 是 | 静态 |
| `install_path` | `%LOCALAPPDATA%\MENACE_HUB\MenaceAgent.exe` | 是 | 静态 |
| `persistence_shadow` | `%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` | 是 | 静态 |
| `encryption_algo` | `浏览器机密用 DPAPI(CryptUnprotectData) + BCrypt AES-GCM；API 基址使用 xorshift32(seed=0xf975b183) 单字节异或流加密` | 否 | 静态 |
| `runtime_switches` | `MENACE_API_BASE / MENACE_PERSIST_DIR / MENACE_PERSIST_SHADOW_DIR / MENACE_NO_PERSIST / MENACE_PERSIST_DRYRUN / MENACE_CFG_ONLY / MENACE_NO_NET / MENACE_NO_WAKE / MENACE_NO_FAKE / MENACE_HEARTBEAT_S / MENACE_AGENT_TTL` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能因为本次运行没有产生网络流量就认定样本无害：代码具备完整的 Discord 远控、窃密、键盘记录与自启能力。
- 不能把 hxxps://discord[.]com/api/v10 当作已确认在线的 C2 会话；该样本未携带 MNC2 配置，观察窗口内没有任何请求/响应。
- 不能仅凭使用 BCrypt/DPAPI 就判定为勒索软件；加密仅用于解密浏览器保存的凭据与配置，未见文件加密或勒索信。
- 不能把版本资源中的 Microsoft Corporation / RuntimeHost / 2.4.1[.]0 当作真实签名或来源；文件无数字签名，该信息为伪装。
- 不能把钱包路径清单判定为已成功窃取；这只是代码具备的收集与打包能力，本次运行未观察到落地文件。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本未附加 MNC2 配置尾部，运行时没有 webhook/bot token，导致沙箱内未观察到任何 C2 外联；C2 能力仅由静态解密与代码路径确认，标为 static + pending_dynamic_verify。
2. 进程创建瞬间取得的内存转储未包含后续堆中的配置/令牌；无法确认运营商频道 ID、webhook 与 bot token。
3. 动态观察窗口约 3 分钟且未产生外联，不能排除更长时间心跳、重连或在具备配置环境下的持久化行为。
4. 持久化代码存在 MENACE_PERSIST_DRYRUN 等跳过开关；本次遥测未见 Run 键/计划任务落地，不能据此否认其在真实主机上的自启能力。
5. 分析环境未提供真实 Discord 侧响应，未能验证命令解析与文件回传的端到端行为。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小（1,933,312 字节） |
| `ev-000014` | 字符串提取 | 字符串抽取：ASCII 2874 条/UTF16 230 条，flag 命中 0；含品牌与配置线索 |
| `ev-000015` | decompile.ghidra | FUN_140135e00：ntdll .text 还原、AMSI/ETW 补丁、NtSetInformationThread 隐藏线程 |
| `ev-000016` | decompile.ghidra | FUN_1400632c0：MENACE_API_BASE 读取与 xorshift32 解密默认 Discord API 基址 |
| `ev-000017` | decompile.ghidra | FUN_140057b90：拷贝自身、HKCU Run 键 MENACE_UPDATER/EdgeUpdateCore、DRYRUN 开关 |
| `ev-000018` | decompile.ghidra | FUN_140066510：拼接并执行 schtasks /Create /SC ONLOGON /TN |
| `ev-000019` | 脚本化取证 | 自写脚本：尾部无 MNC2、解密 API 基址、关键字符串/偏移与 API 调用点（自述） |
| `ev-000020` | evidence.record(manual) | 人工审阅动态产物：PID 2860 单进程、无网络请求、无持久化键、内存扫描无注入（自述） |
| `telemetry:6fe7a4ec` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 103 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 22 条 |
| `etw:6fe7a4ec:2860` | 进程事件监控 | 短命进程事件：6fe7a4eca94dde26b24d00d6e7688dba77c855b17bd65d553d4f4096252a7d23.exe（pid 2860；MD5=07D9EFEE2DCFC88DA7EA6A56F183B4B7,SHA256=6FE7A4ECA94DDE26B24D00D6E7688DBA77C855B17BD65D553D4F4096252A7D23,IMPHASH=1A4B4585C0B8C28A05E9E73E9C52F883） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
