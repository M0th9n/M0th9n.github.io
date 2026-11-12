---
title: "恶意样本分析：ClipBanker（PE · exe · fb09d0e5）"
published: 2026-11-11
draft: false
description: "恶意（置信度中）：ClipBanker · stealer/injector/backdoor · 难度 hard · 静态反编译（动态执行未取得运行时行为）"
tags: ["ClipBanker", "stealer", "injector", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ClipBanker**（存疑） · 置信度 **中**
> 
> 别名：Mikey、Trojan.Win64.ClipBanker、Win64.MalwareX-gen
> 
> 反编译确认其为多功能窃密木马：内置 https[:]//doxbin[.]cy:2083 后端地址与 /init、/upload 协议，读取 HARDWARE\DESCRIPTION\System\BIOS 的 SystemBiosVersion 进行反虚拟机判断，使用硬编码的 BTC/ETH/TRX/LTC/SOL 地址替换剪贴板钱包地址，并具备浏览器凭据/Cookie、Discord token 抓取与传播、Discord/Exodus 客户端代码注入、BIP39 助记词与钱包文件扫描、截屏与主机指纹采集、%LOCALAPPDATA%\WindowsRecovery\Update.exe 自复制与 HKCU Run 自启动、wss:// 远程控制通道等完整模块。静态证据直接来自反编译的函数逻辑与内联字符串常量，恶意意图明确。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ClipBanker** · 别名 Mikey、Trojan.Win64.ClipBanker、Win64.MalwareX-gen · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · injector · backdoor |
| 难度 | hard |
| 首次出现 | 2026-11-10 17:24:00 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/fb09d0e5393ebb9060ea26c2050d7ff3bd6efee340a7d1173be94a44d07be51f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">回连硬编码后端</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">篡改剪贴板钱包</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1115</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">窃取浏览器凭据</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">抓取Discord令牌</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1528</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Discord蠕虫传播</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1534</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `fb09d0e5393ebb9060ea26c2050d7ff3bd6efee340a7d1173be94a44d07be51f` |
| MD5 | _未记录_ |
| 大小 | 3,322,880 字节（3.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 回连硬编码后端

`T1071.001` · 置信度 **高** · 静态

启动后以 https[:]//doxbin[.]cy:2083 为默认后端，通过动态解析的 WinHTTP 接口请求 /?action=init 拉取配置/授权，请求头携带 X-License-Key；后端不可用或未配置许可证时按错误路径退出。

> **证据**：FUN_1400422c0 @0x1400422c0 内联构造 'hxxps://doxbin[.]cy:2083'；0x42ea6 '?action=init'；0x43c35 'X-License-Key: '；0x74b3d 动态解析 winhttp.dll
> 
> **来源**：`ev-000020` · `ev-000025`

### 2. 篡改剪贴板钱包

`T1115` · 置信度 **高** · 静态

按 BTC/ETH/TRX/LTC/SOL/DOGE 正则识别剪贴板中的钱包地址，命中后替换为内置攻击者地址；通过 OpenClipboard/GetClipboardData/SetClipboardData 实现，并记录 'Crypto clipper: Success'。

> **证据**：FUN_140082f30 @0x140082f30 按币种写入替换地址；0x823b6 起为 BTC/ETH/TRX/LTC/SOL 地址；0x82864 'Crypto clipper: Success'；0x399b 起为地址正则
> 
> **来源**：`ev-000021` · `ev-000025`

### 3. 窃取浏览器凭据

`T1555.003` · 置信度 **高** · 静态

面向 Chrome/Edge/Brave/Opera/Opera GX/Vivaldi/Yandex/Firefox 等浏览器，提取 Cookies、Login Data 口令、Web Data 自动填充/银行卡/IBAN 以及刷新令牌，并使用 DPAPI 与 App-Bound Encryption 绕过逻辑解密。

> **证据**：0x65fcd '\Google\Chrome\User Data'；0x1e9d12 '\Network\Cookies/\Login Data/\Web Data'；0x1f1cb3 'SELECT guid, value_encrypted FROM local_stored_c...'；0x6d1e9 'Ciphertext too short for AES-GCM decryption'
> 
> **来源**：`ev-000025`

### 4. 抓取Discord令牌

`T1528` · 置信度 **高** · 静态

扫描 Discord/DiscordPTB/DiscordCanary 本地 leveldb 与会话文件，提取并校验用户令牌，汇总为 'Discord Tokens.txt' 后上传。

> **证据**：0x8ad01 'discord/discordcanary/discordptb'；0x865b8 'leveldb'；0x84f14 'Discord grabber:'；0x9bf28 'Discord injection: Success'
> 
> **来源**：`ev-000025`

### 5. Discord蠕虫传播

`T1534` · 置信度 **高** · 静态

利用窃取的令牌调用 /api/v9/users/@me/channels 与公会频道接口，向私信/频道联系人批量发送后端下发的 worm_message，实现账号级自我传播，并处理 429 限速与失效令牌。

> **证据**：0x8e850 'Discord spread:'; 0x964ce '/api/v9/users/@me/channels'; 0x9740d '/api/v9/guilds/'; 0x92917 'X-RateLimit-Bucket'; 0x45d4c 'spread_*' 配置键
> 
> **来源**：`ev-000025`

### 6. 注入Discord与Exodus

`T1554` · 置信度 **高** · 静态

改写 Discord 安装目录 modules/discord_desktop_core/index.js 注入远程控制 JS；同时解包 Exodus 的 app.asar，修改 wallet.html 的 CSP 与 main/index.js 后重新打包，以便劫持钱包交互。

> **证据**：0x993ee '\modules\discord_desktop_core'；0x9975d '\index.js'；0x9a81a 'LICENSE_PLACEHOLDER'；0xa67ea 'src/app/main/index.js'；0xa6f83 'CSP tag not found in wallet.html'；0xa8503 'Failed to write patched app.asar'
> 
> **来源**：`ev-000025`

### 7. 建立WSS远控通道

`T1071.001` · 置信度 **高** · 静态

以 wss://<backend_host>/stream?token= 建立 WebSocket 长连接，接收并执行 list_drives/list_dir/download_file/upload_file/exec/run_exe/kill/delete/mkdir/rename/file_stat 等指令，构成完整远程控制能力。

> **证据**：FUN_14010c200 @0x14010c200 内联 'wss://' 并解析端口（缺省 0x1bb=443）；0x10c459 '/stream?token='；0x102907 'cmdcommandexec_resultoutput'；0x10a547 'Remote control: Connected'
> 
> **来源**：`ev-000024` · `ev-000025`

### 8. 采集指纹并截屏

`T1082, T1113` · 置信度 **高** · 静态

收集计算机名、用户名、卷序列号、磁盘序列号、BIOS/主板序列号、GPU、MAC、Windows 标识、屏幕分辨率、时区与内存信息，并使用 GDI/GDI+ 截取屏幕以 JPEG 上传。

> **证据**：0x6c03d 'username'；0x70ab6 'SYSTEM\CurrentControlSet\Services\disk\Enum'；0x6b8c9 'screen_r'；0xc7da1 'GdiplusStartup failed for memory screenshot'；0x7696a 'image/jpeg'
> 
> **来源**：`ev-000025`

### 9. 扫描助记词与钱包

`T1005` · 置信度 **高** · 静态

递归扫描磁盘、桌面、下载、文档与 OneDrive 目录，按 BIP39 词表识别助记词，并匹配 seed/secret/passphrase 关键字；同时打包 Exodus、Electrum、Electrum-LTC、Armory、Bytecoin、Jaxx、Ethereum、Guarda、Coinomi、Monero 等钱包文件。

> **证据**：0xceb83 'BIP39_Phrases.txt'；0xb0586 'secret/passphrase'；0x78574 '\Exodus\exodus.wallet'；0x7886b 'backupselectrumElectrum'；0x78e09 'Bytecoin'；0x7ab51 'Wallets/'
> 
> **来源**：`ev-000025`

### 10. 自复制并开机自启

`T1547.001` · 置信度 **高** · 静态

将自身复制到 %LOCALAPPDATA%\WindowsRecovery\Update.exe 并置为隐藏，写入 HKCU\Software\Microsoft\Windows\CurrentVersion\Run 实现登录自启；使用 Global\WindowsRecoveryInstance 互斥体保证单实例，并用 Global\WindowsRecoveryExit 事件通知退出。

> **证据**：FUN_1400e7d90 @0x1400e7d90 调用 CreateDirectoryW、SetFileAttributesW(0x80)、写入 HKCU Run；0xe8420 内联 'Global\WindowsRecoveryInstance'；0xe14f0 内联 'Global\WindowsRecoveryExit'；0xe84xx 'Autostart installed (HKCU Run)'
> 
> **来源**：`ev-000023` · `ev-000025`

### 11. 反虚拟机并杀分析工具

`T1497.001, T1562.001` · 置信度 **高** · 静态

读取 HARDWARE\DESCRIPTION\System\BIOS 的 SystemBiosVersion，若包含 vbox/vmware/virtual/qemu 则判定为虚拟机；枚举进程并终止 IDA、x64dbg、WinDbg、Ghidra、Fiddler、Wireshark、Process Hacker、监控组件、监控组件/HollowsHunter 等分析工具。

> **证据**：FUN_140056140 @0x140056140 读取 BIOS 版本并匹配 vbox/vmware/virtual/qemu；0x56b5d-0x59e27 工具名单；0x5a154 'OpenProcess...TerminateProcess'；导入 CreateToolhelp32Snapshot/OpenProcess/TerminateProcess
> 
> **来源**：`ev-000022` · `ev-000025` · `ev-000003`

### 12. 捆绑替换宿主EXE

`T1027` · 置信度 **中** · 静态

内置 Binder/EXE Replacer：可在宿主 EXE 尾部追加带 'BND!' 标记的载荷、替换图标组与资源后再运行，用于把木马与正常程序捆绑并伪装。

> **证据**：0x62300 'EXE Replacer: Starting Runtime Binding'；0x5cb1c 'EXE Replacer'；0x61620 'bnd.exe'；0x61afb 'Binder: failed to start bound application'；导入 FindResourceExW/UpdateResourceW/EndUpdateResourceW
> 
> **来源**：`ev-000025` · `ev-000007`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://doxbin[.]cy:2083` | 2083 | c2 | 静态 | ⏳ 未观测 |
| other | `wss://<backend_host>/stream?token=` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://discord[.]com/api/v9` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `Global\WindowsRecoveryInstance`

**落地路径**

- `%LOCALAPPDATA%\WindowsRecovery\Update.exe`
- `%LOCALAPPDATA%\WindowsRecovery`
- `%APPDATA%\Exodus\exodus.wallet`
- `%APPDATA%\Exodus\backups`
- `%APPDATA%\Electrum\wallets`
- `%APPDATA%\Telegram Desktop\tdata`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `backend_url` | `hxxps://doxbin[.]cy:2083` | 是 | 静态 |
| `c2_hosts` | `doxbin[.]cy` | 是 | 静态 |
| `c2_port` | `2083` | 是 | 静态 |
| `init_endpoint` | `/?action=init` | 是 | 静态 |
| `upload_endpoint` | `/?action=upload&type=` | 是 | 静态 |
| `license_header` | `X-License-Key（无内置明文许可证，需运行时提供/由后端下发）` | 是 | 静态 |
| `mutex` | `Global\WindowsRecoveryInstance` | 否 | 静态 |
| `kill_event` | `Global\WindowsRecoveryExit` | 否 | 静态 |
| `install_path` | `%LOCALAPPDATA%\WindowsRecovery\Update.exe` | 是 | 静态 |
| `autostart_registry` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | 是 | 静态 |
| `encryption_algo` | `AES-GCM (BCrypt) 用于上传数据加密` | 否 | 静态 |
| `remote_control_endpoint` | `wss://<backend_host>/stream?token=` | 否 | 静态 |
| `wallet_replacement_addresses` | `BTC bc1q88sfcjthknff8ljm7l4vjr83f3z0waezcr92; ETH 0x80EB1438CF1F93f368113c54E56684c41cDc68; TRX TTdzBZaLn9chv8sJriT7PknrhfG3xCWP; LTC LXKh6UNfsUigqWJ3woUtFP9AE6eYtNyb; SOL 6Gk84SVN1rZFTHyvu6Smsk1HFigxvCNUcNFb6RQVzkJzSOLDMKeWh37sD8zUUMu4gPsbnMtpok3LNmb` | 否 | 静态 |
| `features` | `exe_replace, exodus_inject, discord_inject, discord_grabber, bip39, screenshot, systeminfo, extensions, wallets, keywords, telegram, desktop_apps, firefox, vs_projects, remote_desktop, worm_enabled, anti_vm` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭出现 AES-GCM/BCrypt 就判定为勒索软件：该加密仅用于上传数据，未发现文件加密或勒索信逻辑。
- 不能声称已真实外连成功：本次沙箱运行未从该进程观测到任何 DNS/HTTP/WSS 请求，全部 C2 均为静态恢复，需后续动态验证。
- 不能声称已写入 HKCU Run 或已落地 WindowsRecovery\Update.exe：动态遥测中 Run 键无变化、未发现该路径，相关行为来自代码逻辑。
- 不能把本样本当作纯 dropper/loader：未发现从网络下载并执行外部载荷的观测，内置的是 Binder/EXE Replacer 能力。
- 不能把 VirusTotal 标签当作唯一依据：样本未上传，VT 仅提供哈希级外部佐证。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 两次真实沙箱投放均未观测到恶意行为：进程创建后立即被监控挂起并尝试早停转储（early dump 为 0 字节），随后消失；网络监控中没有来自该进程的 DNS/HTTP/WSS 记录，遥测 Run 键与文件系统亦无相关变化，因此 reproduced=false。
2. 分析客体运行在 VMware 虚拟化平台（BIOS/CPUID/驱动均可见 VMware 特征），样本的 anti-VM 逻辑（FUN_140056140）会命中 'vmware' 并可能直接退出；同时样本依赖后端 /init 与许可证，二进制中未见明文 license key，后端不可达时同样会退出，两者都可能解释了动态静默。
3. 上传加密使用 AES-GCM，但密钥/派生方式未在本文件中恢复；运行时 59 字节 XOR 常量（FUN_140082f30）未能解出可读明文，可能为二次配置/标识。
4. Binder/EXE Replacer 的捆绑载荷未在样本文件内发现（无 overlay、无嵌入 PE 资源），其 stage2 内容未知；资源区仅含版本信息。
5. C2、持久化、注入、剪贴板替换等均为静态反编译/字符串证据，尚未经真实会话或内存取证确认。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 3322880 |
| `ev-000002` | 哈希与指纹 | imphash=96c988111beae19d6f75f54b89a75585 |
| `ev-000003` | scan.rich | Rich header 14 条 MSVC 工具链记录 |
| `ev-000004` | scan.entropy | .text 熵 6.526，未发现高熵加密段 |
| `ev-000011` | 字符串提取 | ASCII/UTF-16 字符串抽取（8691/284 条） |
| `ev-000018` | 密码学常量识别 | CRC32 常量（非核心） |
| `ev-000019` | 密码学常量识别 | 标准 base64 字母表 |
| `ev-000020` | decompile.ghidra | FUN_1400422c0 反编译：内联构造 hxxps://doxbin[.]cy:2083 默认后端 |
| `ev-000021` | decompile.ghidra | FUN_140082f30 反编译：内置多链钱包地址与剪贴板替换逻辑 |
| `ev-000022` | decompile.ghidra | FUN_140056140 反编译：BIOS SystemBiosVersion 反虚拟机检测 |
| `ev-000023` | decompile.ghidra | FUN_1400e7d90 反编译：复制到 WindowsRecovery\Update.exe/HKCU Run 自启动 |
| `ev-000024` | decompile.ghidra | FUN_14010c200 反编译：wss:// 远程控制通道与端口解析 |
| `ev-000025` | evidence.record | 自写脚本还原内联字符串常量：IOC/端点/功能开关/钱包地址/互斥体 |
| `ref:a8687de8e9` | 动态分析平台 | 动态沙箱轮询：样本进程 4008 创建后被挂起转储，未产生子进程或网络行为 |
| `ref:7bf986ca22` | 动态产物收集 | 第二次投放后收产物：网络监控 日志与遥测，Run 键未变化、无 C2 会话 |
| `ref:95747d741e` | 动态分析平台 | 客体进程表：样本进程已退出，无残留子进程 |
| `telemetry:fb09d0e5` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 3 条；监控组件 进程/文件事件 59 条；系统服务事件 3 条；已过滤工具/系统噪声 25 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
