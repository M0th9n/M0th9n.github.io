---
title: "恶意样本分析：PlikanLocker（PE · exe · 5bac59b3）"
published: 2026-11-11
draft: false
description: "恶意（置信度中）：PlikanLocker · ransomware · 难度 medium · 静态反编译（动态执行未取得运行时行为）"
tags: ["PlikanLocker", "ransomware", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **PlikanLocker**（存疑） · 置信度 **中**
> 
> 别名：BXBD Locker、BIOS Lock、EuxHacks2024 builder
> 
> 通过还原 .NET 元数据并反汇编全部 IL 方法，确认该程序会遍历所有本地固定驱动器，用 AES-256-CBC 加密 212 类文档/数据文件并改名为 .locked，随后删除明文原件；同时写入多重自启动、创建服务与计划任务、删除卷影副本与恢复环境、结束 74 类安全/取证进程、封锁键盘鼠标并显示伪造的 BIOS/蓝屏/Windows 更新全屏界面。功能与勒索锁定器一致，判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **PlikanLocker** · 别名 BXBD Locker、BIOS Lock、EuxHacks2024 builder · _存疑_ |
| 置信度 | **中** |
| 行为类 | ransomware |
| 难度 | medium |
| 首次出现 | 2026-11-10 12:15:38 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/5bac59b36cfcc8415207d273611584239473f43e612d6a61a9f43ca320bf5477/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪造系统更新界面</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1491.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">全盘文件加密</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486, T1485</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪装系统进程繁殖</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">写入多重自启动</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001, T1546.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">注册服务与计划任务</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003, T1053.005</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `5bac59b36cfcc8415207d273611584239473f43e612d6a61a9f43ca320bf5477` |
| MD5 | _未记录_ |
| 大小 | 114,688 字节（112.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪造系统更新界面

`T1491.001` · 置信度 **高** · 静态

启动后先显示伪造的 Windows Update 进度窗口，加密阶段切换为 BIOS 自检/蓝屏全屏界面，隐藏任务栏与桌面图标，并向用户展示俄语勒索说明，要求到 Telegram 联系。

> **证据**：Program.Main -> updateForm.Show -> ShowLockerUI/BIOSLoadingForm/BSODForm；隐藏 Shell_TrayWnd/Progman
> 
> **来源**：`ev-000009` · `ev-000008`

### 2. 全盘文件加密

`T1486, T1485` · 置信度 **高** · 静态

枚举所有本地固定/可移动驱动器（跳过 \\ 开头的网络路径），递归收集 212 类扩展名文件，按 CPU 数量并发加密为 AES-256-CBC 密文；每个文件写完后把原文件属性改为普通并 File.Delete 删除明文，只留 .locked 密文。

> **证据**：FileEncryptor.EncryptAllFiles / CollectFiles / EncryptFileFast；Aes::Create + Mode=CBC + Padding=PKCS7；末尾 File.SetAttributes(0x80) + File.Delete
> 
> **来源**：`ev-000009`

### 3. 伪装系统进程繁殖

`T1036.005` · 置信度 **高** · 静态

把自身复制为 hosts.exe/svchost.exe/winlogon.exe/services.exe/spoolsv.exe/lsass.exe/csrss.exe 等名称，随机投放到 System32\drivers\etc、Temp、Prefetch、Common Files、IE、Windows Mail 等目录并设为隐藏+系统属性。

> **证据**：AdvancedPersistence.CopyToSystemFolders；7 个目标目录 × 7 个伪装文件名，new Random 选择
> 
> **来源**：`ev-000009` · `ev-000007`

### 4. 写入多重自启动

`T1547.001, T1546.003` · 置信度 **高** · 静态

写入 HKCU/HKLM 的 Run 与 RunOnce，追加 Winlogon Userinit，修改 SafeBoot 的 AlternateShell/Minimal/Network，使常规与安全模式都启动本程序。

> **证据**：Form1.Install：Registry.SetValue 多处；HKLM\...\Winlogon\Userinit 拼接；SafeBoot\AlternateShell
> 
> **来源**：`ev-000009`

### 5. 注册服务与计划任务

`T1543.003, T1053.005` · 置信度 **高** · 静态

删除并重建名为 SystemUpdate/WindowsUpdateService/SystemUpdateService/SecurityUpdateService 的自启动服务（binPath 指向自身），创建 WindowsUpdate 登录计划任务（SYSTEM 权限），并通过 WMIC 注册 __EventFilter 与 CommandLineEventConsumer 实现 WMI 持久化。

> **证据**：Form1.Install：sc delete/create/config、schtasks /create /tn WindowsUpdate /sc onlogon /ru SYSTEM、wmic __EventFilter/CommandLineEventConsumer
> 
> **来源**：`ev-000009` · `ev-000007`

### 6. 删除卷影与恢复环境

`T1490` · 置信度 **高** · 静态

调用 vssadmin delete shadows /all /quiet、wmic shadowcopy delete、reagentc /disable，并用 bcdedit 关闭高级启动菜单，另写入 DisableSR 禁用系统还原。

> **证据**：Form1.Install IL_0747 起：vssadmin/shadowcopy/reagentc/bcdedit 命令串；CreateRestorePoint 反而先建“Windows Update”还原点
> 
> **来源**：`ev-000009`

### 7. 结束安全软件进程

`T1562.001` · 置信度 **高** · 静态

窗体定时器每 500 毫秒枚举并结束 74 个进程名，覆盖 Defender(msmpeng/mssense/windefend)、Malwarebytes、主流杀软、磁盘取证与数据恢复工具（testdisk/photorec/recuva 等），跳过自身 PID。

> **证据**：<Form1_Load>b__36_2：74 项字符串数组 + Process.GetProcessesByName + Kill
> 
> **来源**：`ev-000009` · `ev-000007`

### 8. 封锁系统管理工具

`T1112` · 置信度 **高** · 静态

写入策略注册表禁用任务管理器、命令提示符、注册表编辑器、控制面板、任务计划修改与系统还原，并屏蔽 USB 存储驱动启动。

> **证据**：Form1.Install：DisableTaskMgr/DisableCMD/DisableRegistryTools/NoControlPanel/DisableSR 写入；AntiBypass.BlockUSBDevices 把 USBSTOR\Start 设为 4
> 
> **来源**：`ev-000009`

### 9. 挂钩键盘限制交互

`T1562.001` · 置信度 **高** · 静态

安装 WH_KEYBOARD_LL 全局钩子，拦截绝大多数按键（含 F5/F7 单键、Alt+Tab、Win 键、Ctrl+Alt+Del 相关组合），并用 ClipCursor/ShowCursor 锁定鼠标；仅保留 F5+F7 组合弹出解锁窗口。

> **证据**：Form1.SetHook + HookCallback（SetWindowsHookEx(13,...)、Marshal.ReadInt32 判键码、返回 1 吞掉按键）；Form1_Shown ClipCursor/ShowCursor(0)
> 
> **来源**：`ev-000009`

### 10. 轮询Telegram指令

`T1071.001, T1102` · 置信度 **高** · 静态

后台线程每 5 秒请求 Telegram getUpdates，解析 "text" 字段执行 /info（回报主机信息）、/status、/unlock；加密完成后把主机信息与桌面截屏通过 sendMessage/sendPhoto 上传。

> **证据**：NetworkManager.SendTelegramMessage/CheckForCommands/ProcessCommand/SendTelegramPhoto；api[.]telegram[.]org + WebClient.UploadValues/DownloadString
> 
> **来源**：`ev-000009` · `ev-000007`

### 11. 硬编码口令可解锁

`T1552.001` · 置信度 **高** · 静态

解锁窗口接受固定口令 1234（KeyForm）或 unlock（UnlockForm），验证通过后仅关闭全屏界面并重启 explorer.exe，并不解密任何文件。

> **证据**：KeyForm.CheckKey 比较 "1234"；UnlockForm.CheckUnlock 比较 "unlock"；DecryptFile/DecryptData 无调用点
> 
> **来源**：`ev-000009`

### 12. 检测调试与虚拟机

`T1497.001, T1622` · 置信度 **高** · 静态

后台线程每秒调用 IsDebuggerPresent/CheckRemoteDebuggerPresent，发现调试器即 Environment.Exit；另通过 WMI Manufacturer/Model、Disk\Enum 注册表与 vmtoolsd/vboxservice 等进程名识别 虚拟化平台/VirtualBox/Xen/QEMU。

> **证据**：AntiBypass.<Initialize>b__4_0（调试检测循环）、IsVirtualMachine（结果被 pop 丢弃）
> 
> **来源**：`ev-000009` · `ev-000008`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot1/sendMessage` | 443 | c2 | 静态 | ⏳ 未观测 |
| telegram | `hxxps://api[.]telegram[.]org/bot1/getUpdates?offset=` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `BXBD_Locker_SingleInstance_Mutex`

**落地路径**

- `%LOCALAPPDATA%\Microsoft\Windows\Update\WindowsUpdate.exe`
- `%WINDIR%\System32\drivers\etc\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `%WINDIR%\Temp\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `%WINDIR%\Prefetch\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `%PROGRAMFILES%\Common Files\Microsoft Shared\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `%PROGRAMFILES%\Common Files\System\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `*.locked`

**注册表**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\AlternateShell`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\AlternateShell`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr`
- `HKCU\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableRegistryTools`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoControlPanel`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0\Task Creation`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0\Task Deletion`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore\DisableSR`
- `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start`

**服务**

- `SystemUpdate`
- `WindowsUpdateService`
- `SystemUpdateService`
- `SecurityUpdateService`

**计划任务**

- `WindowsUpdate`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org` | 是 | 静态 |
| `c2_uri` | `/bot<token>/sendMessage, /bot<token>/getUpdates?offset=<id>&timeout=5` | 是 | 静态 |
| `bot_token` | `1 (硬编码占位值,非有效令牌)` | 是 | 静态 |
| `chat_id` | `1 (硬编码占位值)` | 是 | 静态 |
| `encryption_algo` | `AES-256-CBC / PKCS7` | 是 | 静态 |
| `key_derivation` | `key=SHA512(UTF8(SHA512(UTF8(SHA512(UTF8(machine_fingerprint))+"EuxHacksSalt2024"))+"FinalKey2024"))[0:32]` | 是 | 静态 |
| `key_fingerprint_inputs` | `MachineName+UserName+OSVersion+ProcessorCount+各盘 TotalSize/VolumeLabel+Win32_Processor ProcessorId/Name` | 是 | 静态 |
| `encrypted_file_format` | `magic "LOCK" + 16 字节随机 IV + AES-CBC 密文,扩展名 .locked` | 是 | 静态 |
| `target_extensions_count` | `212` | 是 | 静态 |
| `install_path` | `%LOCALAPPDATA%\Microsoft\Windows\Update\WindowsUpdate.exe` | 是 | 静态 |
| `mutex` | `BXBD_Locker_SingleInstance_Mutex` | 是 | 静态 |
| `unlock_code` | `1234 (KeyForm) / unlock (UnlockForm, 大小写不敏感)` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要声称样本已改写 MBR：WriteToMBR 仅 CreateFile("\\.\PhysicalDrive0")、分配 512 字节缓冲后立即 CloseHandle，未调用 WriteFile，且全文件无调用点。
- 不要声称存在可用的 Telegram C2 会话：botToken 与 chatId 都被硬编码为字符串 "1"，不是有效令牌，动态分析也未观测到任何 api[.]telegram[.]org 请求。
- 不要当作 Qilin/Agenda 家族样本：内部命名、.NET 实现与 Telegram 机器人逻辑均指向自研勒索锁定器（BXBD/PlikanLocker），公开引擎的 qilin 标签缺乏样本内证据。
- 不要声称“解锁即恢复数据”：DecryptFile/DecryptData 虽实现 AES 解密，但全文件没有任何调用点，解锁只关闭界面。
- 不要声称检测到虚拟机就退出：IsVirtualMachine 的返回值被直接丢弃（pop），没有分支处置。
- 不要报 stealer 或 wiper：未见浏览器凭据/钱包文件收集或数据外传，唯有桌面截屏与主机信息经 Telegram 上传。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 动态沙箱投放后未观测到样本进程、注册表变更或服务创建，无法用真实运行佐证任何行为；PE 头畸形是最可能的原因。
2. 纯用户态仿真同样未产生 API 调用，说明样本不是可被通用仿真器加载的原生 PE。
3. Telegram C2 使用占位令牌 "1"，既无有效会话也无法验证请求/响应格式；C2 相关结论均为静态。
4. 加密密钥绑定 MachineName/UserName/OSVersion/ProcessorId/磁盘卷标等主机指纹，且不落盘保存，无法在分析环境复现解密。
5. 文件加密范围、排除目录与并发度来自 IL 推演，未在真实运行中统计。
6. 样本被破坏的 PE 头也可能是隔离/传输环节造成，不能据此反推其原始投放形态。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 基线哈希 |
| `ev-000002` | scan.imphash | imphash=42bd7b2eb905ea58f31607b0e955efe3（导入表已不可信，仅作标识） |
| `ev-000003` | scan.entropy | .text 熵 5.129，非加密壳 |
| `ev-000006` | PE 结构解析 | 机器类型 I386 与 Optional Magic 0x20b 位宽不一致；导入目录 RVA 落在 .text 内 |
| `ev-000007` | 字符串提取 | strings/UTF16 命中 screenshot_{0}、PlikanLocker、AES/Telegram/持久化相关标识 |
| `ev-000008` | 字符串提取 | 整体字符串统计（ASCII 776 / UTF16 426） |
| `ev-000009` | evidence.record | 手工解析 .NET 元数据 + dncil 反汇编 234 个 IL 方法得到的加密/持久化/远控/解锁证据 |
| `80d4dead54` | 动态分析平台 | 真实沙箱投放与轮询：0 个新进程、0 个转储、0 个勒索文本，回滚完成 |
| `b7011dfbd0` | dyn.run | 仿真未产生任何 API/文件/网络事件 |
| `telemetry:5bac59b3` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 100 条；已过滤工具/系统噪声 27 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
