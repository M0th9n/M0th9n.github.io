---
title: "恶意样本分析：Telegram Filecryptor (unnamed/custom builder)（PE · exe · 0e9b7cf7）"
published: 2026-11-11
draft: false
description: "恶意（置信度中）：Telegram Filecryptor (unnamed/custom builder) · ransomware/stealer · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Telegram Filecryptor", "ransomware", "stealer", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Telegram Filecryptor (unnamed/custom builder)**（存疑） · 置信度 **中**
> 
> 别名：Filecryptor、Trojan.Stealer/FileCryptor
> 
> 静态反编译与真实动态引爆互相印证：程序用 BCrypt 生成 32 字节随机密钥并以 AES-256-GCM 加密用户文件、追加 .locked 后缀并删除原文件，在各用户目录投放 RESTORE_FILES.txt 勒索说明；同时读取 MachineGuid、查询公网 IP、调用 PowerShell 打包用户文件，并通过 Telegram Bot 接口先回传受害者信息与 AES 密钥、再上传 loot 压缩包。加密、外传、勒索说明三类行为均在隔离沙箱中实际观测到。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Telegram Filecryptor (unnamed/custom builder)** · 别名 Filecryptor、Trojan.Stealer/FileCryptor · _存疑_ |
| 置信度 | **中** |
| 行为类 | ransomware · stealer |
| 难度 | medium |
| 首次出现 | 2026-11-10 12:11:46 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/0e9b7cf7b38ec7d33278e3b5c883636871b53ce987ebcc298acdc26a0fd44268/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">AES-GCM加密用户文件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">追加.locked并删除原件</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">投放勒索说明文件</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">读取MachineGuid</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">查询出口公网IP</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `0e9b7cf7b38ec7d33278e3b5c883636871b53ce987ebcc298acdc26a0fd44268` |
| MD5 | _未记录_ |
| 大小 | 357,888 字节（349.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **3** 条静态可得、**8** 条经动态分析取得。

### 1. AES-GCM加密用户文件

`T1486` · 置信度 **高** · 动态

逐个读取目标文件，使用 BCrypt 的 AES-256-GCM（32 字节随机密钥、每文件 12 字节随机 nonce、16 字节 tag）加密后写出。

> **证据**：0x1400074c0 BCryptOpenAlgorithmProvider(L"AES") + BCryptSetProperty(ChainingModeGCM) + BCryptGenerateSymmetricKey(0x20 字节); 动态生成 readme.txt.locked（119 字节，含 12B nonce+16B tag）
> 
> **来源**：`ref:34bcadd392` · `ref:426064d3d6` · `ref:447836ca34`

### 2. 追加.locked并删除原件

`T1486` · 置信度 **高** · 动态

加密成功后把目标路径拼接 .locked 作为新文件名写入，随后删除原始文件。

> **证据**：FUN_1400082b0 @0x1400082b0 构造 path+".locked"; 0x14000a8e6 call DeleteFileW; 动态创建 readme.txt.locked 与 desktop.ini.locked
> 
> **来源**：`ref:426064d3d6` · `ref:2aefb8e8b6` · `ref:25f931dd21`

### 3. 投放勒索说明文件

`T1486` · 置信度 **高** · 动态

在 Desktop/Documents/Downloads/Pictures 等用户目录写入 RESTORE_FILES.txt，声明文件已被 AES-256-GCM 加密、给出唯一受害者 ID，并要求用该 ID 联系操作者索取密钥。

> **证据**：0x14003bc10 起为勒索文本（"YOUR FILES HAVE BEEN ENCRYPTED"/"Unique ID : %s"）; 动态 notes 01-05 均为 390 字节 RESTORE_FILES.txt，监控组件 记录 File created
> 
> **来源**：`ref:4d563570d9` · `ref:447836ca34` · `ref:25f931dd21`

### 4. 读取MachineGuid

`T1082` · 置信度 **高** · 动态

打开 HKLM\SOFTWARE\Microsoft\Cryptography 并读取 MachineGuid 作为受害者 HWID；读取失败时回退为 HWID_ERROR。

> **证据**：0x140009cf9 RegOpenKeyExA、0x140009d54 RegQueryValueExA("MachineGuid"); 动态外传消息含 HWID : 77d8973f-8f36-43c7-9edf-d99185783224
> 
> **来源**：`ref:42db61fe74` · `ref:c1c1afa599`

### 5. 查询出口公网IP

`T1016` · 置信度 **高** · 动态

用 WinHTTP 以 GET 访问 hxxps://api[.]ipify[.]org 获取出口公网 IP，请求 UA 为 Mozilla/5.0，失败则回退 IP_ERROR。

> **证据**：0x1400092b4 WinHttpConnect(L"api[.]ipify[.]org", 443) + WinHttpOpenRequest("GET"); 动态 DNS 查询与 Host: api[.]ipify[.]org 的 GET / 请求
> 
> **来源**：`ref:569f9a8f45` · `ref:c1c1afa599`

### 6. PowerShell打包用户文件

`T1560.001` · 置信度 **高** · 动态

调用 CreateProcessW 执行隐藏窗口的 powershell -NoProfile -WindowStyle Hidden -Command "Compress-Archive ..."，把 Desktop/Documents/Downloads 等目录内容打包为 loot_<id>.zip。

> **证据**：0x140007fea call CreateProcessW; 0x14003c4f0 起宽字符 Compress-Archive 模板; 动态 监控组件 记录 powershell Compress-Archive 进程
> 
> **来源**：`ref:f166ef27ab` · `ref:7574a78609` · `ref:f1fed79be3`

### 7. Telegram回传密钥

`T1041` · 置信度 **高** · 动态

把受害者 ID、HWID、IP、主机名与 32 字节 AES 密钥组成 JSON，POST 到 api[.]telegram[.]org/bot<token>/sendMessage，完成密钥外带（攻击者据此持有解密能力）。

> **证据**：动态 POST /bot9071041436:AAFixB0iY_3HenM0N9P-aJ8izhd6Owoos7g/sendMessage，正文含 "chat_id":"8931808726" 与 "Key : d0866707..."
> 
> **来源**：`ref:c1c1afa599` · `ref:bb35413b54` · `ref:42db61fe74`

### 8. Telegram上传窃取包

`T1567` · 置信度 **高** · 动态

以 multipart/form-data POST 到 /bot<token>/sendDocument，上传 loot_<victim_id>.zip，caption 为 "Loot - ID <id>"，包内含 Desktop/Documents 下的用户文件。

> **证据**：动态请求 filename="loot_732e5a567793aa1ada5f.zip"，zip 内含 Desktop\待办.txt、Documents\工作记录.txt、Documents\通讯录.csv 等
> 
> **来源**：`ref:c1c1afa599` · `ref:30cd423271`

### 9. 枚举固定磁盘与目录

`T1083` · 置信度 **高** · 静态

用 GetDriveTypeW 判断 DRIVE_FIXED(3) 的盘符并拼接 <盘>:\，同时用 SHGetFolderPathW 定位 Desktop/Documents/Downloads/Pictures/Videos/Music 六类目录作为加密范围。

> **证据**：0x14000afac call GetDriveTypeW 后 cmp eax,3; 0x1400079a6/0x14000a93f SHGetFolderPathW; 0x14003caa8 起目录名宽字符串
> 
> **来源**：`ref:06059cfea5` · `ref:f166ef27ab` · `ref:65fdb4eaa5`

### 10. 递归遍历用户文件

`T1083` · 置信度 **中** · 静态

使用 std::filesystem recursive_directory_iterator 递归遍历目标目录，对每个文件调用单文件加密例程，实现批量加密。

> **证据**：0x14003db48/0x14003db88 recursive_directory_iterator 相关字符串; FUN_1400082b0 @0x1400082b0 为单文件加密实现
> 
> **来源**：`ref:2a82d1a73f` · `ref:426064d3d6`

### 11. 混淆硬编码C2凭据

`T1027` · 置信度 **高** · 静态

把 Bot Token 与 chat_id 先做 base64 再逐字符 +1 硬编码；启动时逐字节 -1 后 base64 解码恢复明文，逃避简单字符串检索。

> **证据**：0x140001000/0x1400010f0 静态初始化器写入常量; FUN_140008de0 @0x140008de0 执行 c-1 后 base64 解码; 常量位于 0x14003bb70/0x14003bbb8
> 
> **来源**：`ref:f41d2c932d` · `ref:a9055f531b` · `ref:ae66f0e235` · `ref:bb35413b54`


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
| telegram | `hxxps://api[.]telegram[.]org/bot9071041436:AAFixB0iY_3HenM0N9P-aJ8izhd6Owoos7g/sendMessage` | 443 | c2 | 动态 | 已观测 |
| telegram | `hxxps://api[.]telegram[.]org/bot9071041436:AAFixB0iY_3HenM0N9P-aJ8izhd6Owoos7g/sendDocument` | 443 | exfil | 动态 | 已观测 |
| http | `hxxps://api[.]ipify[.]org/` | 443 | other | 动态 | 已观测 |

### 主机

**落地路径**

- `%USERPROFILE%\Desktop\RESTORE_FILES.txt`
- `%USERPROFILE%\Documents\RESTORE_FILES.txt`
- `%USERPROFILE%\Downloads\RESTORE_FILES.txt`
- `%USERPROFILE%\Pictures\RESTORE_FILES.txt`
- `%USERPROFILE%\Videos\RESTORE_FILES.txt`
- `%USERPROFILE%\Music\RESTORE_FILES.txt`
- `%USERPROFILE%\Downloads\*.locked`
- `%TEMP%\loot_<victim_id>.zip`

**注册表**

- `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid (仅读取)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org` | 是 | 动态 |
| `bot_token` | `9071041436:AAFixB0iY_3HenM0N9P-aJ8izhd6Owoos7g` | 是 | 动态 |
| `chat_id` | `8931808726` | 是 | 动态 |
| `ip_lookup_url` | `hxxps://api[.]ipify[.]org/` | 否 | 动态 |
| `encryption_algo` | `AES-256-GCM (BCrypt, 32-byte key, 12-byte nonce, 16-byte tag per file)` | 是 | 静态 |
| `file_extension` | `.locked` | 是 | 动态 |
| `ransom_note_filename` | `RESTORE_FILES.txt` | 是 | 动态 |
| `target_dirs` | `Desktop;Documents;Downloads;Pictures;Videos;Music` | 是 | 动态 |
| `exfil_archive` | `loot_<victim_id>.zip (PowerShell Compress-Archive)` | 是 | 动态 |
| `victim_id` | `10 字节随机数(20 位十六进制)，用于文件名/标识` | 否 | 动态 |
| `hwid_source` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要仅凭使用了 AES/BCrypt 与 .locked 后缀就断言可提供解密方案：密钥为每次运行随机生成，仅经 Telegram 外发，样本内未发现任何可恢复密钥的本地材料。
- 不要把 VT 的 stealer 标签当作唯一定性：样本同时执行本地文件加密并投放勒索说明，属于窃密与加密勒索的复合行为。
- 不要声称存在持久化（Run 键/服务/计划任务）或备份破坏（vssadmin/wbadmin/影子副本删除）：导入表、字符串与动态遥测均未观察到相应能力。
- 不要仅凭导入 IsDebuggerPresent 和一处 cpuid 就断言存在反调试/反虚拟机：二者位于 CRT 初始化路径，未发现 VM 检测字符串或有效校验分支。
- 不要声称发现赎金钱包地址或具体支付方式：勒索说明中不含钱包地址、金额或支付指引。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态环境中 api[.]ipify[.]org 由本地模拟网络应答，因此外传正文里的 IP 字段是模拟页面内容而非真实公网 IP；只能证明存在该查询行为。
2. 动态观测到 Desktop/Documents/Downloads/Pictures 产生勒索说明与 .locked 文件，Videos/Music 目录在测试环境中为空，未取得该两目录的加密实例。
3. 密钥仅经 Telegram 外发、未在本地落盘，且每次运行随机生成；无攻击者侧密钥时无法解密被加密文件。
4. 遥测保存的 监控组件 命令行字段有长度截断，PowerShell Compress-Archive 的完整目标路径未能逐字读取，但上传的 zip 内容本身已佐证打包行为。
5. 未观察到文件加密与外传的严格先后顺序：两者在数秒内相邻完成，zip 内同时出现明文与已加密文件，故不宣称固定执行顺序。

## 证据索引

<details>
<summary>展开 24 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 357888 |
| `ev-000002` | scan.imphash | imphash=eeb986cd0ff24630aafa5ccb56369c8a |
| `ev-000003` | scan.rich | MSVC Rich header 10 条记录，richhash=5414cd1a94a9b105bc1777089ef2ab37 |
| `ev-000004` | scan.entropy | 各段熵 0–6.43，.text=6.432，无高熵加密段 |
| `ev-000010` | 字符串提取 | 字符串扫描：ASCII 1042 条 / UTF-16 218 条，含 base64 字母表等 |
| `ev-000014` | 密码学常量识别 | 标准 base64 字母表 @0x3bb20 |
| `ev-000015` | decompile.ghidra | FUN_140001000 初始化混淆 Token 常量 |
| `ev-000016` | decompile.ghidra | FUN_1400010f0 初始化混淆 chat_id 常量 |
| `ev-000017` | decompile.ghidra | FUN_140008de0 实现逐字节 -1 + base64 解码 |
| `ev-000018` | decompile.ghidra | FUN_140009220 通过 WinHTTP 查询 api[.]ipify[.]org |
| `ev-000019` | decompile.ghidra | FUN_140009be0 主流程：随机密钥/ID、MachineGuid、IP、Telegram 消息与文件加密调度 |
| `ev-000020` | decompile.ghidra | FUN_1400074c0 AES-256-GCM 加密实现 |
| `ev-000021` | decompile.ghidra | FUN_1400076d0 字节转十六进制（ID/密钥格式化） |
| `ev-000022` | decompile.ghidra | FUN_1400082b0 单文件加密与 .locked/RESTORE_FILES 路径构造 |
| `ev-000023` | decompile.ghidra | FUN_140014570 虚调用转发（非核心） |
| `ev-000024` | evidence.record | 脚本解码混淆常量得到 Bot Token 与 chat_id，并与动态捕获值一致 |
| `ref:35c54b9e37` | 动态分析平台 | 真实引爆完成：样本进程 pid 6624 存活，产出内存转储与网络/文件遥测；环境已回滚 |
| `ref:30cd423271` | sandbox.watch(live) | notes_manifest：Desktop/Documents/Downloads/Pictures 共 5 个勒索说明与 readme.txt.locked |
| `ref:c1c1afa599` | sandbox.watch(fakenet) | 捕获 GET api[.]ipify[.]org、POST /sendMessage（含 Key/HWID/IP）、POST /sendDocument（loot_<id>.zip） |
| `ref:25f931dd21` | sandbox.watch(sysmon) | 监控组件：样本进程创建、Dns query、.locked 与 RESTORE_FILES.txt 文件创建 |
| `ref:7574a78609` | sandbox.watch(telemetry) | 遥测含 Compress-Archive 命令行与 .locked/RESTORE_FILES 创建事件 |
| `c2_evidence:0e9b7cf7` | 连接证据提取 | 动态网络监控记录到 3 次到 api[.]ipify[.]org:443, api[.]telegram[.]org:443 的连接尝试；未捕获完整会话 |
| `telemetry:0e9b7cf7` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 118 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:0e9b7cf7:6624` | 进程事件监控 | 短命进程事件：0e9b7cf7b38ec7d33278e3b5c883636871b53ce987ebcc298acdc26a0fd44268.exe（pid 6624；MD5=2F46DB8D75D3A610A45ADA6153D098F1,SHA256=0E9B7CF7B38EC7D33278E3B5C883636871B53CE987EBCC298ACDC26A0FD44268,IMPHASH=EEB986CD0FF24630AAFA5CCB56369C8A） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
