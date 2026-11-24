---
title: "恶意样本分析：Remcos RAT（other · vbe · bd2201ac）"
published: 2026-11-22
draft: false
description: "恶意（置信度高）：Remcos RAT · rat/backdoor/stealer · 难度 medium · 纯静态分析"
tags: ["Remcos", "rat", "backdoor", "stealer"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Remcos RAT** · 置信度 **高**
> 
> 别名：Remcos、Remcos Pro、Remote Control
> 
> 该 .vbe 实为明文 VBScript 下载器：它在 C:\Temp 写入随机命名的 .ps1，并以 powershell.exe -nop -ep bypass -file 隐藏窗口执行；内层 PowerShell 依次使用 Base64、GZip、AES-256-CBC 与 XOR 解出 ConfuserEx 混淆的 .NET 加载器 DEVVV.dll，再把一个 537,600 字节的原生 PE 交给 DEVVV.WHORE::LAUNCHER 宿主到 aspnet_compiler.exe。原生载荷字符串明确包含 Remcos v7.3.1 Pro、BreakingSecurity.net、Remcos Agent initialized、Watchdog module activated 等，并在仿真内存中解出完整 Remcos 配置（C2 203.202.232[.]212:4047、互斥体 Rmc-ELYARJ、落地 remcos.exe）。结论由逐层解码、PE 结构/导入表、字符串与隔离仿真内存共同支撑。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Remcos RAT** · 别名 Remcos、Remcos Pro、Remote Control |
| 置信度 | **高** |
| 行为类 | rat · backdoor · stealer |
| 难度 | medium |
| 首次出现 | 2026-11-20 08:51:30 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/bd2201aca49ea9a68238326ae87b32597daa3ae7c761a981db1978a71c365309/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">写入并隐藏执行脚本</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">多层解码内存载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">反射加载.NET加载器</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">伪装系统编译器宿主</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">解密内置C2配置</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `bd2201aca49ea9a68238326ae87b32597daa3ae7c761a981db1978a71c365309` |
| MD5 | _未记录_ |
| 大小 | 3,366,116 字节（3.2 MB） |
| 类型 | other · `vbe` |

## 行为分析

共 **11** 条行为，每条都挂了证据，且全部静态可得。

### 1. 写入并隐藏执行脚本

`T1059.001` · 置信度 **高** · 静态

VBScript 将内嵌的 Base64 文本还原后写到 C:\Temp\<8 位大写随机字母>.ps1，并用 powershell.exe -nop -ep bypass -file 以隐藏窗口方式启动，执行结束后删除该脚本。

> **证据**：g_encodedPayload 解码 + Const PS_LAUNCH_CMD = "powershell.exe -nop -ep bypass -file """; WScript.Shell.Run g_launchCommand, 0, True; StepRemoveArtifacts 删除临时 ps1
> 
> **来源**：`ev-000007` · `ref:3ac0cc2b84`

### 2. 多层解码内存载荷

`T1027` · 置信度 **高** · 静态

第一层 PowerShell 使用 Base64->GZip->AES-256-CBC/PKCS7（内嵌 key/IV，并用 SHA-256 校验打包密文）解出第二层脚本；第二层再用重复密钥 XOR（ZZaDazKA6@@^^）解出 .NET 加载器。

> **证据**：PS Secure Loader - Layered Engine (v2) 注释；Test-HashMatches/Expand-GZipBytes/Invoke-AesDecrypt；ConvertFrom-MaskedBlob 的 repeating-key XOR 循环
> 
> **来源**：`ev-000007`

### 3. 反射加载.NET加载器

`T1620` · 置信度 **高** · 静态

第二层脚本通过 [Reflection.Assembly]::Load 在内存中加载 DEVVV.dll，并反射调用 DEVVV.WHORE 类型的 LAUNCHER 静态方法，不把加载器落盘。

> **证据**：Invoke-InMemoryAssembly 中 [Reflection.Assembly]::Load；GetType('DEVVV.WHORE') / GetMethod('LAUNCHER')；字符串 DEVVV.dll、WHORE、LAUNCHER
> 
> **来源**：`ev-000001` · `ev-000007` · `ref:d8b1a3ec28`

### 4. 伪装系统编译器宿主

`T1036` · 置信度 **中** · 静态

LAUNCHER 接收宿主路径 C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe 与原生 PE 字节数组，加载器内部包含 CreateProcess/进程与线程句柄/shellcode/LoadLibraryA 等字段，意图把 Remcos 载荷放入合法 .NET 编译器进程。

> **证据**：stage2 脚本 $hostExe='C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe'；加载器字符串 processInformation/startupInfo/applicationName/commandLine/processHandle/threadHandle/shellcode/LoadLibraryA/GetProcAddress
> 
> **来源**：`ev-000001` · `ev-000007` · `ref:d8b1a3ec28`

### 5. 解密内置C2配置

`T1027` · 置信度 **高** · 静态

原生 PE 从资源 SETTINGS（RVA 0x8a5cc，长度 0x4b5=1205）读取并解密配置，得到 C2 203.202.232[.]212:4047、互斥体 Rmc-ELYARJ、落地名 remcos.exe、目录名 doc、日志 logs.dat 等。

> **证据**：仿真 PC 0x41fa9b 调用 FindResourceA(hModule,"SETTINGS",0xa)，随后 LoadResource/LockResource/SizeofResource=0x4b5；仿真结束后堆 0x9470 处为明文配置 203.202.232[.]212:4047:1
> 
> **来源**：`ev-000008` · `ref:374ee2ae49`

### 6. 连接C2并保持会话

`T1571` · 置信度 **高** · 静态

载荷导入 WS2_32（socket/connect/send/recv 等）与 TLS 1.3 相关实现，并按配置连接 203.202.232[.]212:4047 建立远控通道。

> **证据**：WS2_32.dll 导入 ord 19/115/3/23/12/111/16/4 及 getaddrinfo；字符串 'Connecting | '、'Connected | '、'Connection Error: Unable to create socket'；配置首字段 203.202.232[.]212:4047
> 
> **来源**：`ref:4137b052ce` · `ev-000008`

### 7. 键盘记录与剪贴板窃取

`T1056.001` · 置信度 **高** · 静态

通过 SetWindowsHookExA/GetKeyboardState/ToUnicodeEx 实现键盘记录，并通过 OpenClipboard/GetClipboardData/SetClipboardData 读取和替换剪贴板内容。

> **证据**：USER32 导入 SetWindowsHookExA(@0x462264 IAT)、GetKeyboardState、ToUnicodeEx、OpenClipboard、GetClipboardData、SetClipboardData；字符串 'Online Keylogger Started'、'Offline Keylogger Started'、'[Text copied to clipboard]'
> 
> **来源**：`ref:4137b052ce` · `ref:3377cb5c7e`

### 8. 截屏与麦克风录音

`T1113` · 置信度 **高** · 静态

使用 BitBlt/StretchBlt/GDI+ 抓取屏幕，并用 waveInOpen/waveInStart 录制麦克风，分别存入 Screenshots 与 MicRecords 目录，供远控端回传。

> **证据**：GDI32 BitBlt/StretchBlt/CreateCompatibleBitmap；gdiplus GdipLoadImageFromStream/GdipSaveImageToStream；WINMM waveInOpen/waveInStart/waveInAddBuffer；配置字段 Screenshots、MicRecords
> 
> **来源**：`ref:4137b052ce` · `ref:3377cb5c7e` · `ev-000008`

### 9. 远程命令与文件下发

`T1105` · 置信度 **高** · 静态

具备执行 cmd.exe/powershell.exe、创建管道/进程以及通过 URLDownloadToFileW/InternetOpenUrlW 下载文件的能力，字符串中包含下载成功/失败提示。

> **证据**：KERNEL32 CreateProcessW/CreateProcessA/CreatePipe/PeekNamedPipe；urlmon URLDownloadToFileW/URLOpenBlockingStreamW；WININET InternetOpenUrlW/InternetReadFile；字符串 'Downloading file: '、'Downloaded file: '
> 
> **来源**：`ref:4137b052ce` · `ref:3377cb5c7e`

### 10. 看门狗重启保活

`T1547.001` · 置信度 **中** · 静态

内置 Watchdog 模块，检测进程存活并在异常退出后重启；载荷字符串包含 sc.exe、rmclient.exe、fsutil.exe、svchost.exe 以及注册表启动项/服务相关操作。

> **证据**：字符串 'Watchdog module activated'、'Remcos restarted by watchdog!'、'Watchdog launch failed!'、'SetSvcStartup'、'GetStartups'、HKLM/HKCU/HKCR/HKU/HKCC；导入 RegCreateKeyExW/RegSetValueExW
> 
> **来源**：`ref:3377cb5c7e` · `ref:4137b052ce`

### 11. 反调试与环境探测

`T1622` · 置信度 **中** · 静态

载荷导入 IsDebuggerPresent，并枚举进程、系统版本、显示器/会话信息；加载器字符串包含 Kill/FailFast 等，具备对抗分析与环境判断能力。

> **证据**：KERNEL32 IsDebuggerPresent(@IAT 0x462200)、CreateToolhelp32Snapshot/Process32FirstW/Process32NextW、GetVersionExW、EnumDisplaySettingsW；加载器字符串 Kill、FailFast、Debugger
> 
> **来源**：`ref:4137b052ce` · `ref:d8b1a3ec28`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `203.202.232[.]212` | 4047 | c2 | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `Rmc-ELYARJ`

**落地路径**

- `%APPDATA%\doc\remcos.exe`
- `%APPDATA%\doc\logs.dat`
- `%APPDATA%\doc\Screenshots`
- `%APPDATA%\doc\MicRecords`
- `C:\Temp\<8 uppercase letters>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `203.202.232[.]212` | 是 | 静态 |
| `c2_port` | `4047` | 是 | 静态 |
| `mutex` | `Rmc-ELYARJ` | 是 | 静态 |
| `install_path` | `%APPDATA%\doc\remcos.exe` | 是 | 静态 |
| `log_file` | `logs.dat` | 否 | 静态 |
| `screenshot_dir` | `Screenshots` | 否 | 静态 |
| `audio_capture_dir` | `MicRecords` | 否 | 静态 |
| `campaign_id` | `C2F9765B8459AF94E02C347A711FE487` | 否 | 静态 |
| `encryption_algo` | `Base64 + GZip + AES-256-CBC/PKCS7（外层）; XOR（加载器）` | 否 | 静态 |
| `watchdog` | `enabled` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得称其为勒索软件或擦除器：未发现文件加密、卷影删除或磁盘擦除的证据，载荷是远控木马。
- 不得声称已取得真实 C2 会话或已确认 203.202.232[.]212:4047 在线：C2 配置来自静态/仿真解密，未进行真实外联。
- 不得把 DEVVV.dll 当成最终恶意载荷：它只是 ConfuserEx 混淆的 .NET 加载器，最终载荷是内存中的 Remcos 原生 PE。
- 不得把样本描述为已在本机真实引爆：本次仅在隔离仿真环境中加载资源与内存快照，未在真实 Windows 宿主执行。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是（stage2 `fd8966550751d9616115529d2188295adcefe4eff57df5a158c27861ea984d2e`） |

**局限与待验证**

1. 本次分析为纯静态与用户态仿真，未在真实 Windows 主机执行样本，也未进行真实网络外联；C2 是否在线、真实会话与回传内容均未验证。
2. C2、互斥体、安装路径与构建标识来自仿真进程内存中的解密结果（自述证据，置信度上限 0.7），需在具备网络隔离与流量捕获的真实沙箱中复核。
3. .NET 加载器被 ConfuserEx 混淆（ConfusedByAttribute、不可见字符命名、控制流代理），未能完整还原其注入实现；宿主与注入方式依据其 P/Invoke/字段字符串及调用参数推断。
4. 持久化与注册表/服务/计划任务行为仅由字符串与导入 API 推断，未通过遥测或动态差分确认。
5. 原生 PE 的 SETTINGS 资源解密算法未完全逆向；明文配置是在仿真运行后从进程内存读取，未独立复算加密算法。
6. ip-api[.]com 查询串出现在载荷中，仅用于地理/网络信息探测，不能当作 C2。

## 证据索引

<details>
<summary>展开 5 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | .NET 加载器字符串：DEVVV.dll/WHORE/LAUNCHER/shellcode/processHandle/CreateProcess 相关字段 |
| `ev-000005` | 字符串提取 | 原生 PE 字符串：Remcos v7.3.1 Pro、BreakingSecurity.net、Watchdog、Keylogger、Screenshots、MicRecords 等 |
| `ev-000006` | decompile.ghidra | FUN_0041fa35 反编译，辅助确认资源/字符串处理代码 |
| `ev-000007` | evidence.record | 静态逐层解码投递链：VBE -> PS1 -> AES/XOR -> .NET DLL + 原生 PE |
| `ev-000008` | evidence.record | 隔离仿真内存快照解出 Remcos SETTINGS 明文（C2/互斥体/落地路径/构建标识） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
